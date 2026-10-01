---
name: asset-recon
description: 授权范围内的资产测绘。子域名枚举、端口扫描、服务指纹、JS 端点与历史 URL 收集。所有目标必须通过 scope_validator 校验。使用 subfinder/httpx/naabu/katana/gau/waybackurls 等工具，经由 safe_exec 包装执行。当用户要求"信息收集""资产测绘""找子域""端口扫描""指纹识别"时使用。
---

# asset-recon（资产测绘）

## 职责

在授权范围内绘制攻击面：子域、活口、端口、服务/技术栈、JS 中隐藏端点、历史 URL。

## 前置

- 已通过 `compliance-check` 阶段，scope 文件就绪。
- 目标域名在 `scope.domains` 白名单内。

## 步骤

对每个授权根域执行：

1. **子域枚举**（被动 + 主动）
   ```
   python scripts/safe_exec.py --tool subfinder --target example.com \
       --scope config/scope.yaml -- -d example.com -silent
   ```
   可叠加 `assetfinder`、`amass`（需 API key 时走环境变量）。

2. **活口探测 + 指纹**
   ```
   python scripts/safe_exec.py --tool httpx --target example.com \
       --scope config/scope.yaml -- -l subs.txt -tech-detect -title -status-code -json
   ```

3. **端口扫描**（速率受限）
   ```
   python scripts/safe_exec.py --tool naabu --target example.com \
       --scope config/scope.yaml -- -host example.com -top-ports 1000 -rate 1000
   ```

4. **爬虫 + 历史 URL**
   ```
   python scripts/safe_exec.py --tool katana --target https://example.com \
       --scope config/scope.yaml -- -u https://example.com -silent
   python scripts/safe_exec.py --tool gau --target example.com \
       --scope config/scope.yaml -- example.com
   ```

5. **JS 敏感信息**（AI 语义辅助，见 vuln-scan 的 JS 分析）
   - 收集 JS 文件列表，用 AI 做语义分析，识别 AccessKey、内网地址、隐藏 API。

## 输出

- 写入 `recon/<domain>/`：
  - `subdomains.json`（子域 + 活口 + 标题 + 技术栈）
  - `ports.json`
  - `urls.json`（爬虫 + 历史 URL）
- 汇总成一张资产表供后续 vuln-scan 消费。

## 红线

- 所有 `--target` 必须在 scope 白名单内；`safe_exec` 会二次校验，越界直接拒绝。
- 速率不得超过 scope 限制；不得对单点高频探测。
- 不收集授权范围外的第三方资产。
- 产物含潜在敏感信息，写入 `recon/` 且 **不入库/不提交**。
