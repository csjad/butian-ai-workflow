---
name: vuln-verify
description: 对 vuln-scan 产出的可疑发现做安全 PoC 验证与 AI 真假判定。仅用 safe_poc_runner 发送只读、低影响请求，AI 输出严格 JSON（置信度/证据/复现步骤/严重程度/建议动作）。禁止破坏性利用。当用户要求"验证漏洞""确认是否为真漏洞""跑 PoC""去误报"时使用。
---

# vuln-verify（安全验证与判定）

## 职责

把 `vuln-scan` 的待验证发现，逐个用**只读、低影响** PoC 验证，并由 AI 给出真假判定与置信度。输出**待人工审阅**的确认发现。

## 步骤

对 `findings/raw/<domain>.json` 中每条 `needs_verify` 发现：

1. **构造无害 PoC**
   - 使用带唯一标记（marker）的探针，例如 `xss_poc_<rand>`、`sqlerr_poc_<rand>`。
   - level=1：仅反射性无害标记；level=2：标准测试向量，但仍禁止破坏性关键字（脚本已拦截）。

2. **执行（受控）**
   ```
   python scripts/safe_poc_runner.py \
       --target <url> --scope config/scope.yaml \
       --method <GET|POST> --data "<无害探针>" --marker "<marker>" --level 1
   ```
   - 目标自动经 `scope_validator` 二次校验。
   - 响应截断至 200KB，仅返回状态码/关键头/摘录。

3. **AI 判定（严格 JSON Schema）**
   调用 LLM（DeepSeek / MiMo）对证据做判定，输出：
   ```json
   {
     "is_vulnerable": true|false,
     "confidence": 0.0-1.0,
     "vuln_type": "XSS|SQLi|SSRF|IDOR|...",
     "cwe": "CWE-79",
     "severity": "critical|high|medium|low|info",
     "evidence": "请求/响应关键摘录（已脱敏）",
     "reproducible_steps": "最小化无害复现步骤",
     "suggested_action": "suggest_report|human_review|false_positive"
   }
   ```
   - 置信度 < 0.7 → `suggested_action: human_review`，不进正式报告正文。
   - 通过 7-Question Gate（见 `rules/reporting.md`）任一不过 → 转 `human_review`。

4. **写回**
   - 确认发现写入 `findings/verified/<domain>.json`。
   - 误报/低置信写入 `findings/review/<domain>.json`。

## 红线

- 绝不执行 RCE / 写数据 / 删数据 / 拖库 / DoS 类 payload。
- 验证请求必须经 `safe_poc_runner`，禁止直接 subprocess 调 curl/sqlmap 等。
- AI 结论仅供参考，**不自动提交**。
- 任何影响可用性/隐私的迹象立即停手并报告。

## 输出

- `findings/verified/<domain>.json`：可进 `impact-assess` 的确认发现。
- `findings/review/<domain>.json`：待人工确认。
