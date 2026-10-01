#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
audit_logger.py — 全量审计日志（统一入口）

记录每一次阶段启动、目标校验、工具执行、PoC 运行，供合规追溯与自证清白。
所有安全相关脚本也可直接写各自的子表，本脚本提供聚合视图。

依赖：Python 标准库（sqlite3）。
用法：
    python scripts/audit_logger.py --phase recon --target example.com --action start
    python scripts/audit_logger.py --query 50
    python scripts/audit_logger.py --export audit_export.json
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUDIT_DB = os.path.join(ROOT, "audit_log.db")


def conn():
    c = sqlite3.connect(AUDIT_DB)
    c.execute(
        """CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT DEFAULT (datetime('now')),
            phase TEXT, target TEXT, action TEXT, detail TEXT)"""
    )
    return c


def log(phase: str, target: str, action: str, detail: str = "") -> None:
    c = conn()
    c.execute("INSERT INTO audit_events (phase, target, action, detail) VALUES (?,?,?,?)",
              (phase, target, action, detail[:500]))
    c.commit()
    c.close()


def query(limit: int) -> list:
    c = conn()
    rows = c.execute(
        "SELECT ts, phase, target, action, detail FROM audit_events ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    c.close()
    return [
        {"ts": r[0], "phase": r[1], "target": r[2], "action": r[3], "detail": r[4]}
        for r in rows
    ]


def export(path: str) -> None:
    events = query(10_000_000)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(events, f, ensure_ascii=False, indent=2)
    print(f"[audit] 已导出 {len(events)} 条记录到 {path}")


def main() -> None:
    ap = argparse.ArgumentParser(description="审计日志")
    ap.add_argument("--phase", help="阶段名（compliance/recon/scan/verify/impact/report）")
    ap.add_argument("--target")
    ap.add_argument("--action")
    ap.add_argument("--detail", default="")
    ap.add_argument("--query", type=int, metavar="N", help="查看最近 N 条")
    ap.add_argument("--export", help="导出审计到 JSON 文件")
    args = ap.parse_args()

    if args.export:
        export(args.export)
        return
    if args.query is not None:
        for e in query(args.query):
            print(f"{e['ts']} | {e['phase']} | {e['target']} | {e['action']} | {e['detail']}")
        return
    if args.phase and args.target and args.action:
        log(args.phase, args.target, args.action, args.detail)
        print(f"[audit] logged: {args.phase}/{args.target}/{args.action}")
    else:
        sys.stderr.write("需提供 --phase/--target/--action 或 --query/--export\n")
        sys.exit(2)


if __name__ == "__main__":
    main()
