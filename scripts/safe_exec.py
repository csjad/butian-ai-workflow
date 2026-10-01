#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""safe_exec.py — 受控外部安全工具执行包装器（支持 nmap + Burp 上游代理）

在 agent 调用 subfinder / httpx / nuclei / nmap 等外部工具前：
1. 校验目标在授权范围内（调用 scope_validator.py）；
2. 校验工具在白名单内；
3. 以非 shell 方式执行（禁止命令注入）；
4. 记录审计日志。
绝不执行任意命令；工具名与参数均受控。
支持 Burp 上游代理（config/tools.yaml 的 proxy 字段，默认关闭，需环境变量开启）。

用法：
    python scripts/safe_exec.py \
        --tool nmap --target example-a.com \
        --scope config/scope.yaml -- -Pn --top-ports 100 --max-rate 50 -T2
"""
from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import subprocess
import sys

try:
    import yaml
except ImportError:
    yaml = None

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUDIT_DB = os.path.join(ROOT, "audit_log.db")
SCOPE_VALIDATOR = os.path.join(ROOT, "scripts", "scope_validator.py")
TOOLS_REGISTRY = os.path.join(ROOT, "config", "tools.yaml")

# 全局认可的安全工具集合（仅这些可被调用）
KNOWN_SAFE_TOOLS = {
    "subfinder", "httpx", "naabu", "katana", "nuclei", "dalfox",
    "gf", "gau", "waybackurls", "assetfinder", "amass", "dnsx",
    "sublist3r", "aquatone", "arjun", "paramspider",
    "nmap",   # 新增：端口扫描补充（需限速 + 授权闸门）
}

# 支持 HTTP 上游代理的工具（Burp 抓包）
PROXY_CAPABLE = {"httpx", "nuclei", "katana", "subfinder", "gau", "waybackurls"}


def audit(event: str, tool: str, target: str, detail: str) -> None:
    try:
        conn = sqlite3.connect(AUDIT_DB)
        conn.execute(
            """CREATE TABLE IF NOT EXISTS tool_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT DEFAULT (datetime('now')),
                event TEXT, tool TEXT, target TEXT, detail TEXT)"""
        )
        conn.execute("INSERT INTO tool_runs (event, tool, target, detail) VALUES (?,?,?,?)",
                     (event, tool, target, detail[:500]))
        conn.commit()
        conn.close()
    except Exception:
        pass


def load_registry() -> dict:
    """读取 config/tools.yaml，返回 {proxy, extra_paths:{tool:[dir]}}"""
    reg = {"proxy": "", "extra_paths": {}}
    if yaml is None or not os.path.isfile(TOOLS_REGISTRY):
        return reg
    try:
        with open(TOOLS_REGISTRY, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        reg["proxy"] = data.get("proxy", "") or ""
        for name, cfg in (data.get("tools") or {}).items():
            if isinstance(cfg, dict) and cfg.get("enabled", True):
                reg["extra_paths"][name] = cfg.get("extra_paths", []) or []
    except Exception:
        pass
    return reg


def check_scope(target: str, scope: str) -> bool:
    if not os.path.isfile(SCOPE_VALIDATOR):
        return False
    r = subprocess.run([sys.executable, SCOPE_VALIDATOR, "--target", target,
                        "--scope", scope], capture_output=True, text=True)
    return r.returncode == 0


def find_tool(tool: str, extra_paths: list[str] | None = None) -> str | None:
    """按优先级定位外部工具可执行文件：
    1) 环境变量 BUTIAN_TOOLS_BIN
    2) Go 的 GOBIN
    3) config/tools.yaml 中该工具的 extra_paths（如 nmap 的 Nmap 安装目录）
    4) 系统 PATH
    """
    search_dirs: list[str] = []
    env_dir = os.environ.get("BUTIAN_TOOLS_BIN")
    if env_dir:
        search_dirs.append(env_dir)
    go = shutil.which("go")
    if go:
        try:
            gobin = subprocess.run([go, "env", "GOBIN"], capture_output=True,
                                   text=True, timeout=15).stdout.strip()
            if not gobin:
                gopath = subprocess.run([go, "env", "GOPATH"], capture_output=True,
                                        text=True, timeout=15).stdout.strip()
                if gopath:
                    gobin = os.path.join(gopath, "bin")
            if gobin:
                search_dirs.append(gobin)
        except Exception:
            pass
    if extra_paths:
        search_dirs.extend(extra_paths)
    for d in search_dirs:
        for ext in ("", ".exe"):
            cand = os.path.join(d, tool + ext)
            if os.path.isfile(cand):
                return cand
    for ext in ("", ".exe"):
        c = shutil.which(tool + ext)
        if c:
            return c
    return None


def main() -> None:
    ap = argparse.ArgumentParser(description="受控外部安全工具包装器")
    ap.add_argument("--tool", required=True, help="工具名，必须在白名单内")
    ap.add_argument("--target", required=True, help="目标（须通过 scope 校验）")
    ap.add_argument("--scope", required=True)
    ap.add_argument("tool_args", nargs="*", help="传递给工具的参数（非 shell）")
    ap.add_argument("--stdin-file", default=None,
                    help="把文件内容作为 stdin 传给工具（用于 gau/waybackurls 多域批量）")
    args = ap.parse_args()

    reg = load_registry()

    tool = args.tool.strip()
    if tool not in KNOWN_SAFE_TOOLS:
        audit("DENY", tool, args.target, "tool not in known safe set")
        sys.stderr.write(f"[safe_exec] 工具 {tool} 不在白名单，拒绝执行\n")
        sys.exit(1)

    if not check_scope(args.target, args.scope):
        audit("DENY", tool, args.target, "scope check failed")
        sys.stderr.write("[safe_exec] 目标未通过授权校验，拒绝执行\n")
        sys.exit(1)

    extra = reg["extra_paths"].get(tool)
    exe = find_tool(tool, extra)
    if not exe:
        audit("ERROR", tool, args.target, "executable not found")
        sys.stderr.write(f"[safe_exec] 未找到 {tool}，请确认已安装并在 PATH / tools.yaml extra_paths 中\n")
        sys.exit(1)

    cmd = [exe] + list(args.tool_args)

    # Burp 上游代理：默认关闭；仅当 BUTIAN_PROXY 显式设置或 BUTIAN_PROXY_AUTO=1 时启用
    proxy = os.environ.get("BUTIAN_PROXY") or ""
    if not proxy and os.environ.get("BUTIAN_PROXY_AUTO") == "1":
        proxy = reg.get("proxy", "")
    if proxy and tool in PROXY_CAPABLE and "-proxy" not in cmd and "--proxy" not in cmd:
        cmd += ["-proxy", proxy]
        os.environ["HTTP_PROXY"] = proxy
        os.environ["HTTPS_PROXY"] = proxy
        audit("PROXY", tool, args.target, f"routed via {proxy}")

    audit("RUN", tool, args.target, " ".join(cmd)[:400])
    stdin_handle = None
    if args.stdin_file and os.path.isfile(args.stdin_file):
        try:
            stdin_handle = open(args.stdin_file, "r", encoding="utf-8")
        except Exception:
            stdin_handle = None
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=1800, stdin=stdin_handle)
        if stdin_handle is not None:
            try:
                stdin_handle.close()
            except Exception:
                pass
        sys.stdout.write(r.stdout or "")
        if r.stderr:
            sys.stderr.write(r.stderr)
        sys.exit(r.returncode)
    except subprocess.TimeoutExpired:
        audit("ERROR", tool, args.target, "timeout")
        sys.stderr.write("[safe_exec] 执行超时\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
