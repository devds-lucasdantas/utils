#!/usr/bin/env python3
"""Auditoria estatica + teleprompter LOCAL para projetos Python AgentOps.

Nao instala pacotes, nao envia arquivos, nao grava video e nao copia codigo no
relatorio. O relatorio inclui metadados que podem ser corporativos: revise a
politica interna antes de compartilha-lo.

Uso (a partir da raiz do repositorio):
    python agentops_inspector.py audit
    python agentops_inspector.py teleprompt --scope core --speed 3
    python agentops_inspector.py teleprompt --scope all --speed 5

Teclas: Espaco pausa/retoma; setas esquerda/direita trocam arquivo;
+/- alteram velocidade; Esc fecha.
"""
from __future__ import annotations

import argparse
import ast
from collections import defaultdict
from datetime import datetime
import math
from pathlib import Path
import re
import subprocess
import sys
import time

PKG = "eng_agent_modernizador_legado"
EXCLUDED_DIRS = {
    ".git", ".venv", "venv", "__pycache__", "node_modules", ".pytest_cache",
    ".ruff_cache", ".mypy_cache", ".tox", "dist", "build", ".agentops-review",
}
SENSITIVE_NAMES = {".env", "pip.conf", "tls.key", "id_rsa", "id_ed25519"}
SECRET_FILENAME_RE = re.compile(
    r"(^\.env(?:\..*)?$|(?:^|/)(?:certs?|secrets?)/|\.(?:pem|p12|pfx|key|jks|keystore)$)",
    re.I,
)
# Heuristica conservadora: resultados suspeitos sao apenas sinalizados, nunca expostos.
SECRET_CONTENT_RE = re.compile(
    r"-----BEGIN (?:[A-Z ]* )?PRIVATE KEY-----|"
    r"(?i:(?:api[_-]?key|client[_-]?secret|password|passwd|access[_-]?token|"
    r"refresh[_-]?token)\s*[:=]\s*['\"][^'\"\r\n]{8,}['\"])",
)


def relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def sensitive_path(path: Path, root: Path) -> bool:
    name = relative(path, root)
    return path.name.lower() in SENSITIVE_NAMES or bool(SECRET_FILENAME_RE.search(name))


def list_sources(root: Path, scope: str = "all") -> list[Path]:
    folders = [root / PKG]
    if scope == "all":
        folders.append(root / "tests")
    found = []
    for folder in folders:
        if not folder.is_dir():
            continue
        for p in folder.rglob("*.py"):
            if not any(part in EXCLUDED_DIRS for part in p.relative_to(root).parts):
                if not sensitive_path(p, root):
                    found.append(p)
    priorities = [
        f"{PKG}/__main__.py", f"{PKG}/app.py", f"{PKG}/config.py",
        f"{PKG}/graph.py", f"{PKG}/llm/base.py", f"{PKG}/llm/factory.py",
        f"{PKG}/llm/gateway_outbound.py", f"{PKG}/rag/rag_tool.py",
        f"{PKG}/utils/guardrails_middleware.py", f"{PKG}/utils/tracing.py",
    ]
    position = {name: idx for idx, name in enumerate(priorities)}
    return sorted(set(found), key=lambda p: (position.get(relative(p, root), 999), relative(p, root)))


def read_source(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig", errors="replace")


def module_for(path: Path, root: Path) -> str:
    parts = list(path.relative_to(root).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def imports_for(tree: ast.AST, module: str, is_init: bool) -> tuple[set[str], set[str]]:
    used = set()
    external = set()
    pkg_parts = module.split(".") if is_init else module.split(".")[:-1]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                used.add(alias.name)
                external.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                up = node.level - 1
                anchor = pkg_parts[:len(pkg_parts) - up] if up <= len(pkg_parts) else []
                base = ".".join(anchor + (node.module.split(".") if node.module else []))
            else:
                base = node.module or ""
                if base:
                    external.add(base.split(".")[0])
            if base:
                used.add(base)
                for alias in node.names:
                    if alias.name != "*":
                        used.add(base + "." + alias.name)
    return used, external


def git_tracked(root: Path) -> set[str] | None:
    try:
        proc = subprocess.run(
            ["git", "ls-files", "-z", "--cached"], cwd=root,
            capture_output=True, check=True, timeout=8,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    return {p.decode("utf-8", "replace").replace("\\", "/")
            for p in proc.stdout.split(b"\0") if p}


def review(root: Path) -> tuple[str, dict]:
    files = list_sources(root, "all")
    if not (root / PKG).is_dir():
        raise RuntimeError(f"Pacote esperado nao encontrado: {root / PKG}")
    tracked = git_tracked(root)
    modules = {module_for(p, root): p for p in files}
    used_by = defaultdict(list)
    metadata = {}
    for path in files:
        name = relative(path, root)
        code = read_source(path)
        module = module_for(path, root)
        flags = []
        risk = bool(SECRET_CONTENT_RE.search(code))
        try:
            tree = ast.parse(code, filename=name)
            imports, external = imports_for(tree, module, path.name == "__init__.py")
            classes = [n.name for n in tree.body if isinstance(n, ast.ClassDef)]
            functions = [n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            local = set()
            for imp in imports:
                if imp in modules and imp != module:
                    local.add(imp)
                elif imp.startswith(PKG + ".") and imp in modules:
                    local.add(imp)
            for imp in local:
                used_by[imp].append(name)
            entry = any(
                isinstance(n, ast.If) and isinstance(n.test, ast.Compare)
                and isinstance(n.test.left, ast.Name) and n.test.left.id == "__name__"
                for n in tree.body
            )
            if entry:
                flags.append("bloco __name__ detectado")
            if any(isinstance(n, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == "app" for target in n.targets
            ) for n in tree.body):
                flags.append("variavel app detectada")
            metadata[name] = {
                "lines": len(code.splitlines()), "module": module,
                "classes": classes, "functions": functions, "imports": sorted(local),
                "external": sorted(external - {PKG, "tests"}),
                "risk": risk, "flags": flags,
            }
        except SyntaxError as exc:
            metadata[name] = {
                "lines": len(code.splitlines()), "module": module, "classes": [],
                "functions": [], "imports": [], "external": [],
                "risk": risk, "flags": [f"AST ERRO: {type(exc).__name__} na linha {exc.lineno}"],
            }
    tracked_sensitive = (
        sorted(p for p in tracked if (
            Path(p).name.lower() in SENSITIVE_NAMES or SECRET_FILENAME_RE.search(p)
        )) if tracked is not None else None
    )
    lines = [
        "# Auditoria estrutural local AgentOps",
        "",
        f"Gerado em: {datetime.now().isoformat(timespec='seconds')}",
        "",
        "**Limite:** analise AST/estatica. Nao prova que um modulo e dispensavel. "
        "Entrypoints, imports dinamicos, Docker/Jenkins e contratos da esteira exigem verificacao.",
        "",
        "**Confidencialidade:** nao inclui o conteudo dos arquivos; NOMES de modulos, "
        "funcoes e imports podem ser informacao interna. Compartilhe somente se autorizado.",
        "",
        f"Python analisados: **{len(files)}**.", "",
        "## Arquivos sensiveis rastreados pelo Git (apenas caminhos)", "",
    ]
    if tracked_sensitive is None:
        lines.append("Nao foi possivel verificar o indice Git.")
    elif not tracked_sensitive:
        lines.append("Nenhum caminho com padroes sensiveis detectado no indice Git.")
    else:
        lines.extend(f"- {p}" for p in tracked_sensitive)
        lines.append("\n**ATENCAO:** verificar se houve commit de segredos e seguir politica interna de rotacao.")
    lines += ["", "## Inventario", "", "| Arquivo | Linhas | Importado por (AST) | Sinais |", "|---|---:|---:|---|"]
    for name, info in metadata.items():
        refs = len(used_by.get(info["module"], []))
        signals = "; ".join(info["flags"] + (["POSSIVEL segredo literal (revisao local)"] if info["risk"] else []))
        lines.append(f"| `{name}` | {info['lines']} | {refs} | {signals.replace('|', '/')} |")
    lines += ["", "## Modulos e dependencias", ""]
    for name, info in metadata.items():
        lines += [
            f"### `{name}`", "",
            f"- Modulo: `{info['module']}`",
            f"- Classes: {', '.join('`'+s+'`' for s in info['classes']) or '(nenhuma declarada no topo)'}",
            f"- Funcoes: {', '.join('`'+s+'`' for s in info['functions']) or '(nenhuma declarada no topo)'}",
            f"- Dependencias locais (AST): {', '.join('`'+s+'`' for s in info['imports']) or '(nenhuma identificada)'}",
            f"- Imports externos (raiz): {', '.join('`'+s+'`' for s in info['external']) or '(nenhum identificado)'}",
            f"- Referenciado por: {', '.join('`'+s+'`' for s in sorted(used_by.get(info['module'], []))) or '(nenhuma referencia AST identificada)'}",
            "",
        ]
    lines += [
        "## Verificacoes manuais obrigatorias", "",
        "- Conferir ENTRYPOINT/CMD do Dockerfile, Jenkinsfile, setup.py, README e contratos da plataforma.",
        "- Conferir configuracoes YAML/JSON apenas LOCALMENTE; nao incluir valores ou credenciais em capturas.",
        "- Revisar imports dinamicos, plug-ins, rotas, dependencies de framework e chamadas via strings.",
        "- Confirmar testes e equivalencia de comportamento antes de remover ou renomear modulos.",
        "- Nunca considerar ausencia de referencias AST como prova de modulo morto.", "",
    ]
    return "\n".join(lines), metadata


def cmd_audit(root: Path, out: Path) -> int:
    report, metadata = review(root)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report, encoding="utf-8")
    print(f"Relatorio local: {out}")
    print(f"Arquivos .py analisados: {len(metadata)}")
    count = sum(int(x["risk"]) for x in metadata.values())
    if count:
        print(f"ATENCAO: {count} arquivo(s) com possiveis segredos literais. "
              "Nao filme esses arquivos sem revisao local.")
    print("Nenhum arquivo de codigo, certificado, chave ou .env foi copiado para o relatorio.")
    return 0


def cmd_teleprompt(root: Path, scope: str, speed: float, hold: float, delay: float, fullscreen: bool) -> int:
    try:
        import tkinter as tk
        from tkinter import ttk
    except ImportError:
        print("Tkinter indisponivel. Use uma instalacao Python com suporte Tcl/Tk.", file=sys.stderr)
        return 2
    files = list_sources(root, scope)
    safe = []
    blocked = []
    for path in files:
        if SECRET_CONTENT_RE.search(read_source(path)):
            blocked.append(relative(path, root))
        else:
            safe.append(path)
    if blocked:
        print("Arquivos OMITIDOS por padrao de possivel segredo literal:")
        for name in blocked:
            print(" -", name)
    if not safe:
        print("Nenhum arquivo .py elegivel no escopo selecionado.", file=sys.stderr)
        return 2
    win = tk.Tk()
    win.title("AgentOps | Leitura automatica local")
    win.geometry("1450x920")
    if fullscreen:
        win.attributes("-fullscreen", True)
    elif sys.platform.startswith("win"):
        try:
            win.state("zoomed")
        except tk.TclError:
            pass
    win.configure(bg="#0b1220")
    header = tk.Frame(win, bg="#111827", padx=18, pady=10)
    header.pack(side="top", fill="x")
    title = tk.Label(header, bg="#111827", fg="#f9fafb", font=("Consolas", 15, "bold"), anchor="w")
    title.pack(side="top", fill="x")
    status = tk.Label(header, bg="#111827", fg="#93c5fd", font=("Consolas", 10), anchor="w")
    status.pack(side="top", fill="x", pady=(5, 0))
    wrapper = tk.Frame(win, bg="#0b1220", padx=12, pady=12)
    wrapper.pack(fill="both", expand=True)
    scroller = tk.Scrollbar(wrapper)
    scroller.pack(side="right", fill="y")
    view = tk.Text(
        wrapper, bg="#0b1220", fg="#d1d5db", insertbackground="#d1d5db",
        font=("Consolas", 16), padx=22, pady=20, wrap="none",
        yscrollcommand=scroller.set, bd=0, relief="flat", takefocus=True,
    )
    view.pack(fill="both", expand=True)
    scroller.config(command=view.yview)
    state = {"i": 0, "playing": True, "speed": speed, "carry": 0.0,
             "last": time.monotonic(), "bottom": None,
             "ready_at": time.monotonic() + delay}

    def label_update() -> None:
        remain = max(0.0, state["ready_at"] - time.monotonic())
        prep = f" | inicio em {math.ceil(remain)}s" if remain else ""
        mode = "RODANDO" if state["playing"] else "PAUSADO"
        status.config(text=(f"{mode}{prep} | {state['speed']:.1f} linhas/s | "
                            "[ESPACO] pausa [←/→] arquivo [+/-] velocidade [ESC] sair | "
                            f"{len(blocked)} arquivos omitidos por risco"))

    def load(index: int) -> None:
        if index >= len(safe):
            state["playing"] = False
            title.config(text="FIM DO TELEPROMPTER")
            status.config(text="Concluido. [←] volta ao arquivo anterior | [ESC] sair")
            return
        if index < 0:
            index = 0
        state["i"] = index
        state["carry"] = 0.0
        state["bottom"] = None
        path = safe[index]
        content = read_source(path)
        title.config(text=f"{index+1:02}/{len(safe):02}  {relative(path, root)}  "
                          f"({len(content.splitlines())} linhas)")
        view.config(state="normal")
        view.delete("1.0", "end")
        # Nenhum conteudo e enviado pela aplicacao; apenas exibido nesta janela local.
        view.insert("1.0", content)
        view.yview_moveto(0)
        view.config(state="disabled")
        label_update()

    def pause(_event=None) -> None:
        state["playing"] = not state["playing"]
        state["last"] = time.monotonic()
        label_update()

    def next_file(_event=None) -> None:
        load(state["i"] + 1)

    def prev_file(_event=None) -> None:
        load(state["i"] - 1)

    def change_speed(delta: float):
        def handler(_event=None) -> None:
            state["speed"] = max(0.5, min(30.0, state["speed"] + delta))
            label_update()
        return handler

    def tick() -> None:
        now = time.monotonic()
        elapsed = min(0.5, now - state["last"])
        state["last"] = now
        if state["playing"] and now >= state["ready_at"]:
            state["carry"] += elapsed * state["speed"]
            whole = int(state["carry"])
            if whole:
                view.yview_scroll(whole, "units")
                state["carry"] -= whole
            if view.yview()[1] >= 0.999:
                if state["bottom"] is None:
                    state["bottom"] = now
                elif now - state["bottom"] >= hold:
                    load(state["i"] + 1)
            else:
                state["bottom"] = None
        label_update()
        win.after(100, tick)

    win.bind("<space>", pause)
    win.bind("<Right>", next_file)
    win.bind("<Left>", prev_file)
    for k in ("<plus>", "<equal>", "<KP_Add>"):
        win.bind(k, change_speed(0.5))
    for k in ("<minus>", "<KP_Subtract>"):
        win.bind(k, change_speed(-0.5))
    win.bind("<Escape>", lambda _event: win.destroy())
    load(0)
    tick()
    win.mainloop()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, default=Path.cwd(),
                        help="Raiz do repositorio (padrao: pasta atual)")
    sub = parser.add_subparsers(dest="command", required=True)
    pa = sub.add_parser("audit", help="Relatorio AST sem codigo-fonte")
    pa.add_argument("--out", type=Path, default=Path(".agentops-review/agentops-audit.md"))
    pt = sub.add_parser("teleprompt", help="Leitor local com rolagem automatica")
    pt.add_argument("--scope", choices=("core", "all"), default="core",
                    help="core: pacote; all: pacote + testes")
    pt.add_argument("--speed", type=float, default=3.0, help="Linhas por segundo (0.5 a 30)")
    pt.add_argument("--hold", type=float, default=3.0, help="Pausa no fim de cada arquivo em segundos")
    pt.add_argument("--delay", type=float, default=8.0, help="Tempo inicial para preparar gravacao")
    pt.add_argument("--fullscreen", action="store_true", help="Janela de tela cheia")
    args = parser.parse_args()
    root = args.root.resolve()
    if not root.is_dir():
        parser.error(f"Pasta nao existe: {root}")
    if args.command == "audit":
        out = args.out if args.out.is_absolute() else root / args.out
        return cmd_audit(root, out)
    if not (0.5 <= args.speed <= 30) or args.hold < 0 or args.delay < 0:
        parser.error("speed deve ser 0.5..30; hold e delay devem ser >= 0")
    return cmd_teleprompt(root, args.scope, args.speed, args.hold, args.delay, args.fullscreen)


if __name__ == "__main__":
    raise SystemExit(main())
