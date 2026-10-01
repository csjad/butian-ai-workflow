#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pre-dangerous-tool.py — 高危工具/动作二次确认钩子

对 sqlmap、wpscan、认证绕过/爆破类等高风险动作，要求人工显式确认。
默认（无 --confirm）返回非零退出，阻止自动化执行，落实"人工在环"。

用法：
    python hooks/pre-dangerous-tool.py --tool sqlmap --target https://example.com
    # 人工确认后：
    python hooks/pre-dangerous-tool.py --tool sqlmap --target https://example.com --confirm
"""
from __future__ import annotations

import argparse
import sys

# 需人工二次确认的高危工具/动作
HIGH_RISK_TOOLS = {
    "sqlmap": "可修改/删除数据库数据，须明确授权且限定只读参数",
    "wpscan": "WordPress 暴力/枚举，可能触发账户锁定",
    "hydra": "凭证爆破，可能触发锁定/法律风险",
    "john": "口令破解",
    "metasploit": "利用框架，可能执行实际攻击载荷",
    "nuclei-fuzz": "模糊测试模板，高频请求",
    "auth-bypass": "认证绕过测试，可能触及越权",
}


def main() -> None:
    ap = argparse.ArgumentParser(description="高危工具二次确认钩子")
    ap.add_argument("--tool", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--confirm", action="store_true", help="人工已确认")
    args = ap.parse_args()

    risk = HIGH_RISK_TOOLS.get(args.tool.lower())
    if not risk:
        print(f"[pre-dangerous] {args.tool} 不在高危清单，放行")
        sys.exit(0)

    if not args.confirm:
        sys.stderr.write(
            f"\n⚠️ 高危动作待确认\n"
            f"  工具：{args.tool}\n"
            f"  目标：{args.target}\n"
            f"  风险：{risk}\n"
            f"  如需继续，必须人工显式确认（--confirm），并确认已在授权范围内。\n"
        )
        sys.exit(1)

    print(f"[pre-dangerous] 人工已确认：{args.tool} @ {args.target}")
    sys.exit(0)


if __name__ == "__main__":
    main()
