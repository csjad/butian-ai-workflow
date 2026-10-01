# butian-ai-workflow

> **合法合规的 AI 辅助 SRC / 补天漏洞挖掘 Skill 集合（人工在环 · 合规版）**

本仓库是一套面向 **WorkBuddy（优先）、Claude Code、Codex、Hermes、Zcode** 的安全研究 Skill 集合。
它把"授权校验 → 资产测绘 → 漏洞扫描 → 安全 PoC 验证 → 影响评估 → 报告草稿"封装成可拼装的安全 Agent 工作流。

**这不是一个自动攻击工具。** 它坚持：
- ✅ 仅在用户提供明确授权范围时对目标发起流量；
- ✅ 授权闸门（`scope_validator.py`）**不可绕过**；
- ✅ AI 只产出**待人工审阅的漏洞草稿**，绝不自动提交平台；
- ✅ 验证（PoC）仅限只读、低影响请求；
- ✅ 全量审计日志 + 一键熔断（`kill_switch.py`）。

---

## ⚠️ 法律与合规声明

1. 本工具**仅供授权的安全研究与漏洞响应（SRC/补天）使用**。
2. **严禁**对任何未获书面授权的系统发起扫描、探测或利用。
3. 使用本工具即表示你已获得对目标资产的合法测试授权，并遵守目标 SRC 平台的规则与当地法律。
4. 自动提交报告、破坏性利用、拖库、DoS、横向移动等行为**明确禁止**，代码层面已做限制。
5. AI 输出可能有误报/漏报，**所有发现须人工复现与确认后方可提交**。

---

## 目录结构

```
butian-ai-workflow/
├── README.md                         # 本文件
├── CLAUDE.md                         # Claude Code 全局上下文
├── AGENTS.md                         # Codex 全局上下文
├── .workbuddy/skills/butian-ai-workflow/SKILL.md   # WorkBuddy 主 Skill
├── skills/                           # 原子 Skill
│   ├── compliance-check/SKILL.md
│   ├── asset-recon/SKILL.md
│   ├── vuln-scan/SKILL.md
│   ├── vuln-verify/SKILL.md
│   ├── impact-assess/SKILL.md
│   └── report-draft/SKILL.md
├── agents/                           # 子 Agent 定义
│   ├── recon-agent.md
│   ├── scanner-agent.md
│   ├── verifier-agent.md
│   └── report-writer-agent.md
├── rules/                            # 行为约束
│   ├── legal.md
│   ├── hunting.md
│   └── reporting.md
├── hooks/                            # 钩子脚本
│   ├── pre-scope-check.py
│   ├── pre-dangerous-tool.py
│   └── audit-logger.py
├── scripts/                          # 可执行脚本
│   ├── scope_validator.py
│   ├── safe_poc_runner.py
│   ├── audit_logger.py
│   ├── kill_switch.py
│   ├── report_renderer.py
│   ├── install_tools.ps1             # Windows 安装
│   └── install_tools.sh              # Linux/macOS 安装
├── config/
│   ├── config.example.yaml
│   └── models.yaml
├── assets/
│   └── banner.jpg
└── .gitignore
```

---

## 多平台安装

### WorkBuddy（优先）

将本仓库克隆/解压到本地，WorkBuddy 会自动识别 `.workbuddy/skills/butian-ai-workflow/SKILL.md`。
在会话中直接说：

> 对 `example.com` 做授权扫描，授权范围见 `config/scope.yaml`

### Claude Code

仓库根目录的 `CLAUDE.md` 与各 `skills/*/SKILL.md` 会被 Claude Code 读取。

### Codex

根目录 `AGENTS.md` 与 `.codex/` 配置会被 Codex 读取（见下方"Codex 适配"）。

### Hermes / Zcode

这两个客户端均兼容通用 Skill 格式。请将本仓库根目录作为 Skill 目录加载：
- 让 Hermes/Zcode 读取 `CLAUDE.md` 作为系统上下文；
- 让它们读取 `skills/*/SKILL.md` 作为可调用子技能；
- 若本机有特定 Skill 加载路径（如 `%APPDATA%\ZCode\skills`），可将 `skills/` 与 `.workbuddy/skills/butian-ai-workflow/` 的 `SKILL.md` 软链/复制到对应目录。

> 具体路径以你本机 Hermes/Zcode 实际配置为准；本仓库不假设其私有目录结构。

---

## 快速开始（MVP 闭环）

```powershell
# 1. 安装外部工具（手动运行，不自动执行）
powershell -ExecutionPolicy Bypass -File scripts/install_tools.ps1

# 2. 准备授权范围配置（从示例模板复制后填写）
cp config/scope.example.yaml config/scope.yaml
# 编辑 config/scope.yaml：填入你获授权的域名/IP/路径/时间窗口
# ⚠️ 务必改掉 time_window，示例值（2026-01-01~2026-01-07）已过期，
#    不改的话闸门会 fail-closed 拒绝一切目标。

# 3. 校验范围（安全闸门）
python scripts/scope_validator.py --target www.example-a.com --scope config/scope.yaml
# 期望：[ALLOW] ... domain match（退出码 0）
python scripts/scope_validator.py --target www.example-outside.com --scope config/scope.yaml
# 期望：[DENY] ... not in authorized scope（退出码 1）

# 4. 发起合规扫描（在 WorkBuddy 会话中触发主 Skill）
#    或直接运行各阶段脚本，详见 skills/*/SKILL.md
```

---

## 配置 LLM（DeepSeek / 小米 MiMo）

编辑 `config/models.yaml`：

```yaml
providers:
  deepseek:
    base_url: "https://api.deepseek.com/v1"   # 或你的中转地址
    api_key: "${DEEPSEEK_API_KEY}"             # 环境变量注入，勿硬编码
    models: ["deepseek-chat", "deepseek-reasoner"]
  mimo:
    # 按量 key（sk- 开头）用此地址；TokenPlan（tp- 开头）用 token-plan-cn 地址
    base_url: "https://api.xiaomimimo.com/v1"
    api_key: "${MIMO_API_KEY}"
    models: ["mimo-v2.5", "mimo-v2.5-pro"]   # v2-flash/pro/omni 已于 2026-06-30 废弃
```

> API Key 一律走环境变量，**禁止写入仓库**。

---

## 关于本仓库的占位符约定

本仓库是从实际使用中的私有版本脱敏后发布的，因此你会在文档与脚本中看到以下占位符，
请按自己的环境替换：

| 占位符 | 含义 | 替换为 |
|---|---|---|
| `example-a.com` / `example-b.com.cn` … | 示例目标域名 | 你自己的**已授权**域名 |
| `example-outside.com` | 越权对照样本（用于验证闸门） | 保持原样即可 |
| `203.0.113.10` | 示例 IP（RFC 5737 文档地址段） | 你自己的授权 IP |
| `$TOOLS_ROOT` | 安全工具安装根目录 | 如 `/opt/pentest`、`C:/tools` |
| `$GOROOT` / `$GOPATH` / `$GOMODCACHE` / `$GOCACHE` | Go 工具链目录 | `go env` 查询实际值 |
| `$NUCLEI_TEMPLATES` | nuclei 模板目录 | 实际模板路径 |
| `$WORK_DIR` | 扫描产物输出目录 | 任意本地目录 |
| `$BUTIAN_ROOT` | 本项目根目录 | 实际克隆路径 |
| `<venv>` / `python` | Python 解释器 | 你的虚拟环境解释器 |
| `C:/Users/<you>` | 用户目录 | 你的实际用户目录 |

> **为什么真实目标一律被移除**：公开"测过哪些厂商"的清单，既可能违反部分 SRC 平台
> 关于漏洞修复前不得披露目标的规定，也会把真实资产暴露给其他人。
> 本仓库只保留**方法论与工具链**，不含任何真实目标信息。
> 案例库（`knowledge-base/04-案例库-*.md`）为脱敏后的结构示例，可直接照此格式记录你自己的案例。

---

## 许可

本项目用于授权安全研究，采用与上游社区一致的 MIT 协议（详见 LICENSE）。
使用即代表你理解并遵守上述合规声明。
