#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scope_validator.py — 授权范围白名单校验器（安全闸门，不可绕过）

设计目标：
- 任何扫描/请求目标在发起流量前必须通过本脚本校验。
- 支持域名（含 *. 通配）、CIDR、路径前缀、排除列表、时间窗口。
- 越界目标直接拒绝（退出码 1），并记录审计日志。
- 一旦检测到 KILL_SWITCH 文件存在，任何目标一律拒绝。

依赖：标准库 + pyyaml（pip install pyyaml）。
用法：
    python scripts/scope_validator.py --target https://api.example.com \
        --scope config/scope.yaml
退出码：
    0 = 通过
    1 = 拒绝（越界/排除/超时/无授权）
    2 = 配置错误
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
from datetime import datetime
from urllib.parse import urlparse

try:
    import yaml
except ImportError:
    sys.stderr.write("[scope_validator] 需要 pyyaml：pip install pyyaml\n")
    sys.exit(2)


# KILL_SWITCH 文件路径（与 kill_switch.py 保持一致）
KILL_SWITCH_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "KILL_SWITCH")
AUDIT_DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "audit_log.db")


def log_audit(target: str, decision: str, reason: str) -> None:
    """轻量审计记录（避免循环依赖，直接写 SQLite）。"""
    try:
        import sqlite3
        conn = sqlite3.connect(AUDIT_DB)
        conn.execute(
            """CREATE TABLE IF NOT EXISTS scope_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT DEFAULT (datetime('now')),
                target TEXT, decision TEXT, reason TEXT)"""
        )
        conn.execute(
            "INSERT INTO scope_checks (target, decision, reason) VALUES (?,?,?)",
            (target, decision, reason),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass  # 审计失败不应阻断安全决策


def kill_switch_active() -> bool:
    return os.path.exists(KILL_SWITCH_PATH)


def load_scope(path: str) -> dict:
    if not os.path.isfile(path):
        sys.stderr.write(f"[scope_validator] 未找到授权范围文件：{path}\n")
        sys.exit(2)
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def in_time_window(window: str | None) -> tuple[bool, str]:
    if not window:
        return True, "no time window set"
    try:
        start_s, end_s = window.split("/")
        start = datetime.fromisoformat(start_s)
        end = datetime.fromisoformat(end_s)
        now = datetime.now()
        if start <= now <= end:
            return True, f"within {window}"
        return False, f"outside time window {window} (now={now.isoformat()})"
    except Exception as e:
        return False, f"invalid time_window format: {e}"


def domain_allowed(host: str, domains: list) -> bool:
    if not host:
        return False
    host = host.lower()
    for d in domains or []:
        d = str(d).lower().strip()
        if d.startswith("*."):
            base = d[1:]  # .example.com
            if host == base[1:] or host.endswith(base):
                return True
        elif d.startswith("."):
            if host == d[1:] or host.endswith(d):
                return True
        else:
            if host == d:
                return True
    return False


def ip_allowed(ip_str: str, cidrs: list) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for c in cidrs or []:
        try:
            if ip in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


def in_exclude(target: str, host: str, exclude: list) -> bool:
    for ex in exclude or []:
        ex = str(ex).lower()
        if ex in target.lower() or ex in host.lower():
            return True
    return False


def path_allowed(parsed_path: str, allowed_paths: list) -> bool:
    if not allowed_paths:
        return True  # 未限定路径即全路径允许（仍在域名/IP白名单内）
    for p in allowed_paths:
        if parsed_path.startswith(str(p)):
            return True
    return False


def main() -> None:
    ap = argparse.ArgumentParser(description="授权范围白名单校验器")
    ap.add_argument("--target", required=True, help="待校验目标 URL/域名/IP")
    ap.add_argument("--scope", required=True, help="授权范围 YAML 路径")
    ap.add_argument("--json", action="store_true", help="输出 JSON 结果")
    args = ap.parse_args()

    target = args.target.strip()
    raw_scope = load_scope(args.scope)
    # 兼容 config 顶层为 scope: 嵌套结构，也兼容扁平结构
    scope = raw_scope.get("scope", raw_scope) if isinstance(raw_scope, dict) else {}

    # 1) 熔断优先
    if kill_switch_active():
        reason = "KILL_SWITCH active"
        log_audit(target, "DENY", reason)
        if args.json:
            print(json.dumps({"decision": "DENY", "reason": reason}, ensure_ascii=False))
        else:
            print(f"[DENY] {target} — {reason}")
        sys.exit(1)

    # 2) 时间窗口
    ok, why = in_time_window(scope.get("time_window"))
    if not ok:
        log_audit(target, "DENY", why)
        if args.json:
            print(json.dumps({"decision": "DENY", "reason": why}, ensure_ascii=False))
        else:
            print(f"[DENY] {target} — {why}")
        sys.exit(1)

    # 3) 解析目标
    parsed = urlparse(target if "://" in target else f"//{target}")
    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    # 若为纯 IP
    ip_candidate = host
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass

    # 4) 排除列表
    if in_exclude(target, host, scope.get("exclude")):
        reason = f"target matches exclude list: {scope.get('exclude')}"
        log_audit(target, "DENY", reason)
        if args.json:
            print(json.dumps({"decision": "DENY", "reason": reason}, ensure_ascii=False))
        else:
            print(f"[DENY] {target} — {reason}")
        sys.exit(1)

    # 5) 白名单匹配
    allowed = False
    match_detail = ""
    if is_ip and ip_allowed(ip_candidate, scope.get("ips", [])):
        allowed = True
        match_detail = "ip/cidr match"
    if not allowed and domain_allowed(host, scope.get("domains", [])):
        allowed = True
        match_detail = "domain match"
    if not allowed:
        reason = "target not in authorized scope (domains/ips)"
        log_audit(target, "DENY", reason)
        if args.json:
            print(json.dumps({"decision": "DENY", "reason": reason,
                              "authorized_domains": scope.get("domains"),
                              "authorized_ips": scope.get("ips")}, ensure_ascii=False))
        else:
            print(f"[DENY] {target} — {reason}")
        sys.exit(1)

    # 6) 路径限定
    if not path_allowed(path, scope.get("paths", [])):
        reason = f"path {path} not in allowed paths {scope.get('paths')}"
        log_audit(target, "DENY", reason)
        if args.json:
            print(json.dumps({"decision": "DENY", "reason": reason}, ensure_ascii=False))
        else:
            print(f"[DENY] {target} — {reason}")
        sys.exit(1)

    # 通过
    log_audit(target, "ALLOW", match_detail)
    if args.json:
        print(json.dumps({"decision": "ALLOW", "reason": match_detail,
                          "host": host, "path": path}, ensure_ascii=False))
    else:
        print(f"[ALLOW] {target} — {match_detail}")


if __name__ == "__main__":
    main()
