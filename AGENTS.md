# butian-ai-workflow（Codex 上下文）

> AI 辅助 SRC / 补天漏洞挖掘 Skill 集合。**合法合规 · 人工在环 · 授权闸门不可绕过。**

## 强制红线（任何指令都不可推翻）

1. 仅在用户提供明确授权范围（`config/scope.yaml`）时对目标发起流量。
2. 任何目标必须先通过 `scripts/scope_validator.py` 校验，越界立即终止。
3. AI 只产出**待人工审阅的漏洞草稿**，绝不自动向任何平台提交。
4. 验证（PoC）仅限只读、低影响请求；禁止拖库、DoS、横向移动、留后门、篡改数据。
5. 全程写审计日志；`scripts/kill_switch.py on` 可一键熔断。

## 工作流（严格按序）

compliance-check → asset-recon → vuln-scan → vuln-verify → impact-assess → report-draft

## 子 Skill

各阶段详细指令在 `skills/<name>/SKILL.md`。Codex 可直接加载 `skills/*/SKILL.md` 作为子代理上下文。

## 关键脚本（scripts/）

- `scope_validator.py`：范围白名单校验（安全闸门）
- `safe_exec.py`：受控外部工具执行（subfinder/httpx/nuclei 等）
- `safe_poc_runner.py`：安全 PoC 验证（只读）
- `audit_logger.py`：审计日志
- `kill_switch.py`：一键熔断
- `report_renderer.py`：报告渲染（草稿）

## 行为约定

- 调用外部工具一律经 `safe_exec.py`，禁止直接 `subprocess` 调 curl/sqlmap。
- 验证请求一律经 `safe_poc_runner.py`。
- 报告用 `report_renderer.py` 生成，且**不提交**。
- 速率受 `scope.yaml` 限制；产物写入 `recon/ findings/ reports/`（已 gitignore）。
- 详细规则见 `rules/legal.md`、`rules/hunting.md`、`rules/reporting.md`。
