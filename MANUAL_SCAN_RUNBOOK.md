# 首次手动合规扫描 · 操作手册（butian-ai-workflow）

> 适用：本机工具链已就绪（7/8 核心工具），准备在补天平台**已授权**资产上手动跑通一次闭环。
> 原则：授权闸门不可绕过 · AI 只出草稿、绝不自动提交 · PoC 只读低影响 · 全量审计 + 一键熔断。

---

## 0. 当前工具链状态（已验证）

`$(go env GOPATH)/bin` 现含（共 9 个）：

| 工具 | 用途 | 状态 |
|---|---|---|
| subfinder | 子域枚举 | ✅ 预装 |
| httpx | HTTP 存活/探测（已修复 Python 同名冲突） | ✅ 本次确认 |
| naabu | 端口扫描 | ✅ 本次装(v2.6.1) |
| katana | 爬虫/端点发现 | ✅ 本次装(v1.4.0) |
| nuclei | 漏洞模板扫描 | ✅ 预装 |
| gau | URL 历史采集 | ✅ 本次装(v2.2.4) |
| waybackurls | URL 历史采集 | ✅ 预装 |
| ffuf / gobuster | 目录/参数爆破 | ✅ 预装（附加） |
| **dalfox** | XSS 参数 fuzz | ⚠️ 本机装不上（github 被墙），**可选补装**；nuclei 模板已覆盖 XSS 检测 |

`safe_exec.py` 已加固：工具解析优先 `BUTIAN_TOOLS_BIN`(=gopath/bin) → `go env GOBIN` → PATH，避免误调 Python `httpx`。

---

## 1. 填真实授权范围（必须，且只填你获授权的）

编辑 `config/scope.yaml`（先 `cp config/config.example.yaml config/scope.yaml` 若还没有）：

```yaml
scope:
  domains:
    - 你在补天获授权的域名.com          # 例如厂商给的 SRC 范围
    - "*.厂商域名.com"                  # 含子域
  ips: []                               # 或填授权的 IP/CIDR
  paths: []                             # 置空=该域名下全路径；可限定如 ["/api/*"]
  exclude:
    - "admin.厂商域名.com"              # 命即拒绝（生产/敏感入口）
  rate_limit: 20                        # 单次任务速率上限(rps)，保守些
  max_requests: 2000                    # 单次请求数上限
  time_window: "2026-08-18T09:00/2026-08-19T09:00"  # 授权有效时间窗(ISO8601)
  allowed_tools: [subfinder, httpx, naabu, katana, nuclei, gau, waybackurls]
  forbidden_behaviors:
    - no_exploit_with_data_modification
    - no_dos
    - no_lateral_movement
    - no_data_exfiltration
    - no_persistence
```

⚠️ **只填补天平台明确授权给你、且在时间窗内的资产。** 授权过期 = 视为未授权，闸门会拒绝。

---

## 2. 跑通前自检（每一步都该成功）

```powershell
# 2.1 校验 Python 依赖
python -c "import yaml; print('pyyaml ok')"

# 2.2 校验授权闸门（应 ALLOW）
python scripts/scope_validator.py --target 你的授权域名.com --scope config/scope.yaml

# 2.3 校验越权被拦（应 DENY，且不会发任何流量）
python scripts/safe_exec.py --tool naabu --target out-of-scope.example --scope config/scope.yaml
```

---

## 3. 手动跑一次（合规网关逐道开）

在本机用 `safe_exec.py` 包裹外部工具（它会在启动工具前强制校验 scope + 工具白名单 + 写审计）：

```powershell
# 资产测绘：子域
python scripts/safe_exec.py --tool subfinder --target 你的授权域名.com --scope config/scope.yaml -- -d 你的授权域名.com -silent

# 存活探测
python scripts/safe_exec.py --tool httpx --target 你的授权域名.com --scope config/scope.yaml -- -u 你的授权域名.com -silent -title -status-code

# 端口/爬虫（按需在 scope 的 allowed_tools 内）
python scripts/safe_exec.py --tool katana --target 你的授权域名.com --scope config/scope.yaml -- -u https://你的授权域名.com -silent

# 漏洞模板扫描（只读，不利用）
python scripts/safe_exec.py --tool nuclei --target 你的授权域名.com --scope config/scope.yaml -- -u https://你的授权域名.com -rl 20 -silent
```

> 每次调用都会写 `audit_log.db`。任何目标不在 `scope.yaml` 内 → 直接拒绝，不发流量。

---

## 4. 发现处理（人工在环）

1. nuclei/工具输出 = **待人工复现的线索**，不是结论。
2. 对每条发现，用 `scripts/safe_poc_runner.py` 做**只读、低影响**验证（不拖库、不改数据、不DoS）。
3. 确认后，由**你本人**在补天平台提交报告。AI/本 Skill **绝不自动提交**。
4. 一键熔断：`python scripts/kill_switch.py`（激活后所有目标全部 DENY）。

---

## 5. 可选：补装 dalfox

本机 github 直连被墙，dalfox 装不上。在**有 github 访问**的机器上：

```bash
GOTOOLCHAIN=local GOSUMDB=off GOPROXY=https://goproxy.cn,direct \
  go install github.com/projectdiscovery/dalfox/v2/cmd/dalfox@v2.9.2
```

装好后把 `dalfox.exe` 放进 `$(go env GOPATH)/bin` 并把 `dalfox` 加回 `scope.yaml` 的 `allowed_tools`。

---

## 红线重申

- 未获书面授权 ≠ 不扫。
- 不自动提交、不破坏性利用、不横向移动、不拖库、不DoS。
- 所有动作可审计、可熔断。
