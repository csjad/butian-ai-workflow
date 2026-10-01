---
name: vuln-scan
description: 授权范围内的漏洞初筛。基于指纹匹配 Nuclei 模板、Dalfox XSS 探测，并对 JS/接口文档做 AI 语义分析以发现 AccessKey、隐藏 API、越权线索。所有流量经由 safe_exec/safe_poc_runner 受控执行。当用户要求"扫漏洞""跑模板""找 XSS""JS 审计"时使用。
---

# vuln-scan（漏洞初筛）

## 职责

对资产测绘结果做非破坏性初步筛查，产出**待验证**的发现列表。本阶段**不做最终判定**，仅标记可疑点交 `vuln-verify`。

## 步骤

1. **模板扫描（Nuclei，低风险/信息类优先）**
   ```
   python scripts/safe_exec.py --tool nuclei --target https://example.com \
       --scope config/scope.yaml -- -u https://example.com -rl 50 -silent \
       -tags cve,exposure,misconfig,default-login -severity low,medium,high,critical
   ```
   - 默认排除 `fuzz`/`brute-force` 类高强度模板（见 `rules/hunting.md`）。
   - 速率 `-rl` 取 scope 中 `rate_limit` 与 50 的较小值。

2. **XSS 被动探测（Dalfox，仅反射，不存储）**
   ```
   python scripts/safe_exec.py --tool dalfox --target https://example.com \
       --scope config/scope.yaml -- pipe --silence --no-banner < urls.txt
   ```

3. **JS / 接口语义分析（AI）**
   - 读取 `recon/<domain>/urls.json` 中的 JS 文件。
   - 用 LLM（DeepSeek / MiMo，见 `config/models.yaml`）做语义分析：
     - 识别硬编码 AccessKey / Secret / Token；
     - 识别内网地址、测试环境入口；
     - 识别隐藏 API 端点、参数、潜在越权点。
   - 输出结构化 `js_findings.json`（类型 + 位置 + 风险说明 + 置信度）。

## 输出

- 写入 `findings/raw/<domain>.json`：
  - `nuclei`: 模板命中列表（template / severity / matched_at）
  - `dalfox`: 可疑 XSS 参数
  - `js_findings`: AI 语义发现
- 每条原始发现标注 `needs_verify: true`，交给 `vuln-verify`。

## 红线

- 不执行任何会修改/删除数据的 payload。
- Nuclei 模板排除高强度爆破类；Dalfox 仅反射探测。
- 速率受控；产物不提交。
- 本阶段结论**不等于漏洞**，必须进 `vuln-verify`。
