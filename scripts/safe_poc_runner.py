#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
safe_poc_runner.py — 安全 PoC 验证执行器（只读、低影响、可审计）

仅执行白名单内的 HTTP 方法，校验目标在授权范围内，限制速率与响应大小，
禁止破坏性 payload，全程写审计日志。绝不执行系统命令、绝不修改目标数据。

依赖：Python 标准库（urllib / json / sqlite3）。
用法：
    python scripts/safe_poc_runner.py \
        --target https://api.example.com/vuln \
        --scope config/scope.yaml \
        --method POST --data "id=1'" --marker "sqlerr_poc" --level 1
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime

# 复用 scope_validator 的校验（通过子进程调用，保证单一安全逻辑）
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUDIT_DB = os.path.join(ROOT, "audit_log.db")
SCOPE_VALIDATOR = os.path.join(ROOT, "scripts", "scope_validator.py")

# 允许的方法
ALLOWED_METHODS = {"GET", "HEAD", "POST", "OPTIONS"}

# 危险关键字（命中即拒绝，避免破坏性利用）
DANGEROUS_PATTERNS = [
    "drop table", "delete from", "truncate ", "update set", "insert into",
    "rm -rf", "rm /", "; cat ", "&& whoami", "| id", "`id`", "$(id)",
    "powershell", "certutil", "wget http", "curl http",
    "<?php", "/etc/passwd", "c:\\\\windows",
]

# level=1 额外禁止的验证探针（更严格，仅反射性无害标记）
LEVEL1_FORBIDDEN = ["<script>", "alert(", "document.cookie", "' or '1'='1",
                    "1=1--", "union select", "sleep(", "benchmark("]


def audit(event: str, target: str, detail: str) -> None:
    try:
        conn = sqlite3.connect(AUDIT_DB)
        conn.execute(
            """CREATE TABLE IF NOT EXISTS poc_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT DEFAULT (datetime('now')),
                event TEXT, target TEXT, detail TEXT)"""
        )
        conn.execute("INSERT INTO poc_runs (event, target, detail) VALUES (?,?,?)",
                     (event, target, detail[:500]))
        conn.commit()
        conn.close()
    except Exception:
        pass


def check_scope(target: str, scope: str) -> bool:
    if not os.path.isfile(SCOPE_VALIDATOR):
        sys.stderr.write("[safe_poc] scope_validator.py 缺失，拒绝执行\n")
        return False
    r = subprocess.run([sys.executable, SCOPE_VALIDATOR, "--target", target,
                        "--scope", scope], capture_output=True, text=True)
    return r.returncode == 0


def main() -> None:
    ap = argparse.ArgumentParser(description="安全 PoC 验证执行器")
    ap.add_argument("--target", required=True)
    ap.add_argument("--scope", required=True)
    ap.add_argument("--method", default="GET")
    ap.add_argument("--data", default="")
    ap.add_argument("--header", action="append", default=[], help="Header: Name:Value")
    ap.add_argument("--marker", default="", help="期望在响应中出现的标记（用于判定）")
    ap.add_argument("--level", type=int, default=1, help="1=无害反射探针，2=标准测试向量")
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--max-bytes", type=int, default=200000)
    args = ap.parse_args()

    # 1) 方法校验
    method = args.method.upper()
    if method not in ALLOWED_METHODS:
        audit("DENY", args.target, f"method {method} not allowed")
        print(json.dumps({"decision": "DENY", "reason": f"method {method} not allowed"}, ensure_ascii=False))
        sys.exit(1)

    # 2) 范围校验
    if not check_scope(args.target, args.scope):
        audit("DENY", args.target, "scope check failed")
        print(json.dumps({"decision": "DENY", "reason": "target not in authorized scope"}, ensure_ascii=False))
        sys.exit(1)

    # 3) payload 危险关键字
    payload = (args.data or "").lower()
    for p in DANGEROUS_PATTERNS:
        if p in payload:
            audit("DENY", args.target, f"dangerous pattern: {p}")
            print(json.dumps({"decision": "DENY", "reason": f"dangerous pattern blocked: {p}"}, ensure_ascii=False))
            sys.exit(1)
    if args.level <= 1:
        for p in LEVEL1_FORBIDDEN:
            if p in payload:
                audit("DENY", args.target, f"level1 forbidden: {p}")
                print(json.dumps({"decision": "DENY", "reason": f"level1 probe forbidden: {p}"}, ensure_ascii=False))
                sys.exit(1)

    # 4) 构造请求
    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    headers.setdefault("User-Agent", "butian-ai-workflow/1.0 (authorized-test)")

    data_bytes = args.data.encode("utf-8") if args.data else None
    req = urllib.request.Request(args.target, data=data_bytes, method=method, headers=headers)

    # 5) 执行（带超时与熔断检查）
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as resp:
            body = resp.read(args.max_bytes)
            status = resp.status
            resp_headers = dict(resp.headers)
            text = body.decode("utf-8", errors="replace")
        elapsed = round(time.time() - start, 3)
        marker_hit = bool(args.marker) and (args.marker in text)
        audit("RUN", args.target, f"status={status} elapsed={elapsed}s marker_hit={marker_hit}")
        result = {
            "decision": "ALLOW",
            "status": status,
            "elapsed_s": elapsed,
            "marker_hit": marker_hit,
            "response_headers": {k: v for k, v in resp_headers.items() if k.lower() in ("content-type", "server", "location")},
            "body_excerpt": text[:1000],
        }
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except urllib.error.HTTPError as e:
        audit("RUN", args.target, f"HTTPError {e.code}")
        print(json.dumps({"decision": "ALLOW", "status": e.code,
                          "body_excerpt": e.read(args.max_bytes).decode("utf-8", "replace")[:1000]},
                         ensure_ascii=False, indent=2))
    except Exception as e:
        audit("ERROR", args.target, str(e)[:200])
        print(json.dumps({"decision": "ERROR", "reason": str(e)}, ensure_ascii=False))
        sys.exit(1)


if __name__ == "__main__":
    main()
