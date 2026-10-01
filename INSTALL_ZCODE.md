# butian-ai-workflow — ZCode 安装说明

> 合法合规的 AI 辅助 SRC/补天漏洞挖掘工作流（人工在环 · 合规版）
> 兼容 WorkBuddy / Claude Code / Codex / ZCode（SKILL.md 标准格式，frontmatter: name + description）

---

## 1. 安装（三选一）

### 方式 A：一键（推荐，本机已装好）
```bash
# 把整个 butian-ai-workflow 目录放到 ZCode 技能目录即可：
cp -r butian-ai-workflow ~/.zcode/skills/
# Windows: 复制但保留原目录
#   robocopy butian-ai-workflow %USERPROFILE%\.zcode\skills\butian-ai-workflow /E
```
重启 ZCode 生效（技能名：`butian-ai-workflow`）。

### 方式 B：zip 解压
1. 解压 `butian-ai-workflow-zcode-v1.0.zip`
2. 把解压出的 `butian-ai-workflow` 文件夹放到 `%USERPROFILE%\.zcode\skills\` 下
3. 重启 ZCode

### 方式 C：其他兼容 Agent
- Claude Code：`~/.claude/skills/butian-ai-workflow/`
- Codex：`~/.codex/skills/butian-ai-workflow/`
- OpenCode：`~/.config/opencode/skills/butian-ai-workflow/`

---

## 2. 首次配置（4 步，必做）

- [ ] **① 配置授权范围** `config/scope.yaml`：把 `domains` 的 `example.com` 换成你的授权域名，`time_window` 换成授权有效期
- [ ] **② 闸门自检**：
  ```bash
  python scripts/scope_validator.py --target <你的域名>   # 应输出 ALLOW
  python scripts/scope_validator.py --target out-of-scope.example     # 应输出 DENY
  ```
- [ ] **③ 外部工具链**：运行 `scripts/install_tools.sh`（或 `.ps1`，Windows 需管理员）安装 subfinder/httpx/naabu/katana/nuclei/gau/waybackurls/nmap；或用 `BUTIAN_TOOLS_BIN` 环境变量指向已装工具目录（如 `$(go env GOPATH)/bin`）
- [ ] **④ LLM 配置** `config/models.yaml`：填 OpenAI 兼容 API（DeepSeek / 小米 MiMo / SiliconFlow 均可）；工具自动发现用 `scripts/safe_exec.py`（支持 `config/tools.yaml` extra_paths + Burp 代理）

---

## 3. 使用（在 ZCode 对话中）

对 ZCode 说：**"使用 butian-ai-workflow，目标 <你的授权域名>"**，Agent 会按六阶段工作流执行：
```
compliance-check → asset-recon → vuln-scan → vuln-verify → impact-assess → report-draft
```
每个阶段自动过 `scope_validator.py` 闸门 + 写审计日志 + 检查 KILL_SWITCH。

---

## 4. 合规红线（不可违反）
1. 仅扫描 `scope.yaml` 白名单内资产；越权目标被闸门拒绝并记日志
2. 验证仅限只读、低影响请求；禁止拖库 / DoS / 横向移动 / 留后门 / 篡改数据
3. AI 只产出**待人工审阅的草稿**，绝不自动向 SRC/补天提交
4. 随时可熔断：`python scripts/kill_switch.py on`

---

## 5. 目录结构速览
```
butian-ai-workflow/
├── SKILL.md                  # 入口（ZCode 自动识别）
├── scripts/                  # 闸门/审计/熔断/执行器/安装脚本
├── hooks/                    # 前置闸门钩子（scope 检查/审计/危险动作）
├── config/                   # scope.yaml / tools.yaml / models.yaml
├── skills/                   # 6 个子技能（compliance-check 等）
├── agents/                   # 4 个 Agent 角色定义
├── rules/                    # 狩猎/法律/上报规范
├── knowledge-base/           # 环境搭建/合规红线/提交手册/案例库
└── KILL_SWITCH.closed        # 熔断文件（存在=熔断）
```

## 6. 版本
v1.0 ｜ 2026-08-18 ｜ 来源：butian-ai-workflow（实测：example-a.com 提交成功 QTV4-2026-XXXXXXXX；example-b.edu.cn / example-d.com 完整合规流程）
