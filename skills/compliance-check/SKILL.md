---
name: compliance-check
description: 授权范围校验与白名单生成。在发起任何流量前调用，读取 scope.yaml，校验目标是否在授权白名单内、是否在时间窗口内、是否命中排除列表。越界立即终止。当用户提供授权范围或准备开始扫描前使用。
---

# compliance-check（合规前置）

## 职责

在任何侦察/扫描/验证动作之前，确保目标**已获授权**且**在白名单内**。

## 输入

- 用户提供的授权范围文件 `config/scope.yaml`（首次使用需从 `config.example.yaml` 复制并填写）。
- 待校验目标（域名 / IP / URL）。

## 操作步骤

1. **确认授权文件存在**：若 `config/scope.yaml` 不存在，提示用户先创建并填写授权范围，**不得**使用默认/空范围继续。
2. **校验目标**：对每一个将要访问的目标运行
   ```
   python scripts/scope_validator.py --target <目标> --scope config/scope.yaml
   ```
   - 退出码 `0` = 允许；`1` = 拒绝；`2` = 配置错误。
   - 任何 `DENY` 必须立即停止后续流程并向用户报告，**不得**绕过。
3. **检查熔断**：运行 `python scripts/kill_switch.py status`，若已激活则停止全部操作。
4. **生成白名单摘要**：把 scope 中的 domains/ips/paths/exclude/time_window/allowed_tools 汇总成一句话给用户确认。

## 授权范围 YAML 结构（config/scope.yaml）

```yaml
scope:
  domains:
    - example.com
    - "*.example.com"
  ips: []                 # 可选 CIDR，如 ["10.0.0.0/24"]
  paths: ["/api/*"]       # 可选路径前缀限制
  exclude: ["prod-db.internal", "admin.example.com"]
  rate_limit: 50          # rps 上限
  max_requests: 10000     # 单次任务请求数上限
  time_window: "2026-08-17T14:00/2026-08-18T14:00"
  allowed_tools:
    - subfinder
    - httpx
    - nuclei
    - dalfox
  forbidden_behaviors:
    - no_exploit_with_data_modification
    - no_dos
    - no_lateral_movement
```

## 红线

- 无授权文件 → 不扫描。
- 校验拒绝 → 不扫描。
- 时间窗口外 → 不扫描。
- 禁止把 `forbidden_behaviors` 中列出的行为当作"可选项"。
- 绝不修改 scope 文件以"扩大"范围；如用户要求扩大，需重新明确授权。

## 输出

- 通过：`ALLOW <目标> — <匹配原因>`
- 拒绝：`DENY <目标> — <原因>`，并终止流程。
