#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
report_renderer.py — 漏洞报告渲染器（草稿，不提交）

读取 findings/verified/<domain>.json，渲染为 Markdown / HTML 草稿报告。
支持平台模板差异（butian / box / cnvd）。报告仅供人工审阅与复现，绝不自动提交。

依赖：Python 标准库。
用法：
    python scripts/report_renderer.py \
        --input findings/verified/example.com.json \
        --platform butian --format markdown --output reports/example.com.md
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

PLATFORM_TITLES = {
    "butian": "补天漏洞响应平台 - 漏洞报告草稿",
    "box": "漏洞盒子 - 漏洞报告草稿",
    "cnvd": "CNNVD/CNVD - 漏洞报告草稿",
}


def load_findings(path: str) -> list:
    if not os.path.isfile(path):
        sys.stderr.write(f"[report] 未找到 {path}\n")
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        return data.get("findings", [data])
    return data


def render_markdown(findings: list, platform: str, domain: str) -> str:
    title = PLATFORM_TITLES.get(platform, "漏洞报告草稿")
    lines = [f"# {title}", "", f"- 目标域名：{domain}", f"- 生成时间：{datetime.now().isoformat(timespec='seconds')}", "- 状态：**草稿，待人工复现与确认，未提交**", ""]
    findings = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "info"), 9))
    if not findings:
        lines.append("未发现可确认漏洞（已通过验证阶段）。")
        return "\n".join(lines)
    for i, f in enumerate(findings, 1):
        lines.append(f"## 漏洞 {i}：{f.get('vuln_type', '未知')} ({f.get('severity', '').upper()})")
        lines.append("")
        lines.append(f"- **CWE**：{f.get('cwe', 'N/A')}")
        lines.append(f"- **置信度**：{f.get('confidence', 'N/A')}")
        lines.append(f"- **目标**：{f.get('target', 'N/A')}")
        lines.append(f"- **证据**：{f.get('evidence', 'N/A')}")
        lines.append(f"- **复现步骤**：{f.get('reproducible_steps', 'N/A')}")
        lines.append(f"- **修复建议**：{f.get('fix_suggestion', 'N/A')}")
        lines.append(f"- **AI 建议动作**：{f.get('suggested_action', 'N/A')}")
        lines.append("")
    lines.append("---")
    lines.append("> 本草稿由 AI 辅助生成，须经人工复现与确认后方可提交。所有测试均在授权范围内进行。")
    return "\n".join(lines)


def render_html(findings: list, platform: str, domain: str) -> str:
    md = render_markdown(findings, platform, domain)
    # 极简 HTML 包装（不引入外部依赖）
    body = md.replace("\n", "<br>\n")
    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>漏洞报告草稿 - {domain}</title>
<style>body{{font-family:system-ui,'Microsoft YaHei',sans-serif;max-width:900px;margin:2em auto;padding:0 1em;color:#222}}h1,h2{{color:#0a4}}pre{{background:#f5f5f5;padding:1em;border-radius:6px;overflow:auto}}blockquote{{color:#666;border-left:3px solid #ccc;padding-left:1em}}</style>
</head><body>
{body}
</body></html>"""


def main() -> None:
    ap = argparse.ArgumentParser(description="漏洞报告渲染器（草稿）")
    ap.add_argument("--input", required=True)
    ap.add_argument("--platform", default="butian", choices=list(PLATFORM_TITLES))
    ap.add_argument("--format", default="markdown", choices=["markdown", "html"])
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    domain = os.path.basename(args.input).replace(".json", "")
    findings = load_findings(args.input)

    if args.format == "html":
        out = render_html(findings, args.platform, domain)
    else:
        out = render_markdown(findings, args.platform, domain)

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(out)
    print(f"[report] 已生成 {args.format} 报告：{args.output}（{len(findings)} 条发现）")


if __name__ == "__main__":
    main()
