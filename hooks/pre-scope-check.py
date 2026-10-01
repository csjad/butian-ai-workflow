#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pre-scope-check.py — 执行前授权校验钩子

在任何扫描/验证批次启动前调用，对目标列表逐个运行 scope_validator。
任一目标被拒绝则整体非零退出，阻止批次执行。

用法：
    python hooks/pre-scope-check.py --scope config/scope.yaml \
        --targets example.com api.example.com
或：
    cat targets.txt | python hooks/pre-scope-check.py --scope config/scope.yaml
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCOPE_VALIDATOR = os.path.join(ROOT, "scripts", "scope_validator.py")


def main() -> None:
    ap = argparse.ArgumentParser(description="执行前授权校验钩子")
    ap.add_argument("--scope", required=True)
    ap.add_argument("--targets", nargs="*", default=[])
    args = ap.parse_args()

    targets = list(args.targets)
    if not targets and not sys.stdin.isatty():
        targets = [t.strip() for t in sys.stdin.read().splitlines() if t.strip()]

    if not targets:
        sys.stderr.write("无目标输入\n")
        sys.exit(2)

    results = []
    denied = 0
    for t in targets:
        r = subprocess.run([sys.executable, SCOPE_VALIDATOR, "--target", t,
                            "--scope", args.scope, "--json"],
                           capture_output=True, text=True)
        try:
            out = json.loads(r.stdout)
        except Exception:
            out = {"decision": "DENY" if r.returncode else "ALLOW", "reason": r.stderr.strip()}
        results.append({"target": t, **out})
        if out.get("decision") != "ALLOW":
            denied += 1

    print(json.dumps({"checked": len(targets), "denied": denied, "results": results},
                     ensure_ascii=False, indent=2))
    sys.exit(1 if denied else 0)


if __name__ == "__main__":
    main()
