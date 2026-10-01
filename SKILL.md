---
name: butian-ai-workflow
description: 合法合规的 AI 辅助 SRC/补天漏洞挖掘工作流。仅用于已获书面授权的目标。编排 合规校验→资产测绘→漏洞扫描→安全PoC验证→影响评估→报告草稿 六个阶段，坚持人工在环、授权闸门不可绕过、全量审计、一键熔断。当用户要求"挖洞""SRC""补天""授权扫描""漏洞挖掘"且该目标已提供授权范围时使用。绝不在无授权情况下对公网目标发起扫描；绝不直接向平台提交报告；绝不执行破坏性利用。
---

# butian-ai-workflow（AI 辅助 SRC 漏洞挖掘 · 合规版）

> 本 Skill 是一套**人工在环、合规优先**的 AI 辅助漏洞挖掘工作流。
> **红线（任何情况下不可违反）：**
> 1. 仅在用户提供**书面/明确授权范围**时对目标发起任何流量。
> 2. 任何扫描/请求目标必须先通过 `scripts/scope_validator.py` 校验，越界立即终止并记审计日志。
> 3. AI 只产出**待人工审阅的漏洞草稿**，绝不自动向任何 SRC/补天平台提交。
> 4. 验证（PoC）仅限**只读、低影响**请求；禁止拖库、DoS、横向移动、留后门、篡改数据。
> 5. 全程写审计日志；用户可随时用 `scripts/kill_switch.py on` 一键熔断。

## 何时使用

- 用户已给出目标（域名/IP/路径）**和**授权范围（白名单、时间窗口、允许的工具）。
- 用户要求产出"漏洞草稿""扫描报告""资产清单""待确认发现"。
- **不使用**：用户未提供授权、要求自动提交报告、要求攻击未授权目标、要求破坏性利用。

## 工作流（严格按序）

```
1. compliance-check  → 读取 scope YAML，生成白名单，校验目标合法性
2. asset-recon       → 子域/端口/服务/指纹/JS端点/历史URL
3. vuln-scan         → Nuclei 模板扫描 + AI 语义分析（非破坏性）
4. vuln-verify       → 安全 PoC 验证 + AI 真假判定 + 置信度
5. impact-assess     → CVSS / 严重程度 / 业务影响
6. report-draft      → 生成人工审阅草稿（不提交）
```

每个阶段开始前：
- 运行 `python scripts/scope_validator.py --target <目标>` 校验；
- 运行 `python scripts/audit_logger.py --phase <阶段> --target <目标> --action start` 记日志；
- 检查 `KILL_SWITCH` 文件是否存在（`python scripts/kill_switch.py status`）。

## 子 Skill 索引（详细指令见各 SKILL.md）

| 子 Skill | 路径 | 职责 |
|----------|------|------|
| compliance-check | `skills/compliance-check/SKILL.md` | 授权校验、白名单生成 |
| asset-recon | `skills/asset-recon/SKILL.md` | 资产测绘 |
| vuln-scan | `skills/vuln-scan/SKILL.md` | 模板扫描 + AI 语义 |
| vuln-verify | `skills/vuln-verify/SKILL.md` | 安全 PoC + AI 判定 |
| impact-assess | `skills/impact-assess/SKILL.md` | 影响评估 |
| report-draft | `skills/report-draft/SKILL.md` | 报告草稿 |

## 关键脚本（scripts/）

- `scope_validator.py`：范围白名单校验（**不可绕过**）。
- `safe_poc_runner.py`：白名单命令模式执行只读 PoC。
- `audit_logger.py`：SQLite 审计日志。
- `kill_switch.py`：一键熔断。
- `report_renderer.py`：Markdown/HTML 报告渲染。
- `install_tools.ps1` / `install_tools.sh`：外部工具安装（**用户手动运行**）。

## 环境依赖

- Python 3.12+（建议用隔离 venv）
- 外部工具（按需）：subfinder、httpx、naabu、katana、nuclei、dalfox、gf、gau、waybackurls
- LLM（OpenAI 兼容）：DeepSeek API 或 小米 MiMo API，配置见 `config/models.yaml`

## 方法论外挂（跨 Skill，按需调用）

本 Skill 只管**闸门与流程**（能不能测、以什么安全方式测、怎么记审计、怎么出草稿）。
若需要"**某类漏洞具体怎么测、怎么判定真假**"的方法层知识，调用同级 Skill **`src-hunter-kb`**
（`~/.workbuddy/skills/src-hunter-kb/`）：

- 48 个漏洞类型专题：越权 IDOR / 注入 / SSRF / XSS / CSRF / 请求走私 / 竞态 / 文件上传 / OAuth-JWT / 逻辑漏洞 / WAF 绕过等
- 8 条分层研究规则（`00-core` → `07-tool-routing`）+ `knowledge-base/打穿短表.md`（手法总索引）
- 参考：`../src-hunter-kb/SKILL.md`、交叉索引见项目工作区 `交叉索引-src-hunter-kb-vs-butian.md`

> **冲突时以本 Skill 的合规红线与 `rules/legal.md` 为准。** 外挂库只提供方法，不赋予任何执行权限。

## 重要提醒

- 所有流量必须落在授权白名单内。
- 任何阶段发现越界，立即停止并报告用户。
- 报告仅作为草稿供人工复现与提交，AI 结论须由用户验证。
- 详见 `README.md`、`rules/legal.md`。
