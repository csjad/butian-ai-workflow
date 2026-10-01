---
name: report-draft
description: 把已验证且评估过的漏洞渲染成平台格式的报告草稿（补天/漏洞盒子/CNVD）。报告仅供人工审阅与复现，绝不自动提交平台。当用户要求"生成报告""出草稿""整理漏洞"时使用。
---

# report-draft（报告草稿）

## 职责

将 `impact-assess` 产出的确认发现，渲染为结构化报告草稿。

## 步骤

1. **汇总确认发现**
   - 读取 `findings/verified/<domain>.json`。
   - 仅纳入 `suggested_action == suggest_report` 或 `human_review` 且 severity ≥ low 的发现。
   - 置信度 < 0.7 的发现单独列入"待人工确认"附录，不进正文。

2. **渲染报告**
   ```
   python scripts/report_renderer.py \
       --input findings/verified/example.com.json \
       --platform butian --format markdown --output reports/example.com.md
   ```
   - 平台可选：`butian` / `box` / `cnvd`。
   - 格式可选：`markdown`（默认） / `html`。

3. **脱敏检查**
   - 确认报告中不含 API Key、密码、Token、PII。
   - 截图/响应摘录已打码。

4. **交付**
   - 输出到 `reports/`，提示用户："这是草稿，请人工复现后自行在平台提交。"
   - **绝不**调用平台 API 自动提交。

## 报告内容（每条）

- 目标（域名/IP/路径）+ 是否在授权范围内
- 漏洞类型 + CWE
- 严重程度 + CVSS
- 证据链（已脱敏）
- 可复现步骤（最小化、无害）
- 置信度 + AI 判定依据
- 修复建议
- 时间戳 + 扫描任务 ID

## 红线

- 自动提交平台 = 禁止。
- 报告不含未授权目标信息。
- 不夸大严重程度。

## 输出

- `reports/<domain>.md` 或 `reports/<domain>.html`：人工审阅草稿。
- 控制台提示用户下一步人工动作。
