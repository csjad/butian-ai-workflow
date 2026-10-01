#!/usr/bin/env bash
# 受控扫描流水线 —— example-b.edu.cn（示例大学，补天公益SRC）
# 极克制策略：被动枚举 → 单请求存活 → top-100 低速端口 → www 浅层爬取
# 每一步都经 safe_exec 授权闸门；非 shell 拼接参数。
set -u
SKILL="$BUTIAN_ROOT"
OUT="$SKILL/output/example-b_2026-08-18"
SCOPE="$SKILL/config/scope.yaml"
PY="python"
LOG="$OUT/scan.log"
mkdir -p "$OUT"
ts(){ date "+%Y-%m-%d %H:%M:%S"; }
echo "[$(ts)] === 开始受控扫描 example-b.edu.cn (极克制) ===" | tee -a "$LOG"

# 0) 闸门自检（目标 + 一个越权对照）
"$PY" "$SKILL/scripts/scope_validator.py" --target example-b.edu.cn --scope "$SCOPE" | tee -a "$LOG"
"$PY" "$SKILL/scripts/scope_validator.py" --target out-of-scope.example --scope "$SCOPE" | tee -a "$LOG"

# 1) 被动子域枚举（subfinder，限速 5，被动源不主动探测）
echo "[$(ts)] [1/4] subfinder 被动枚举 ..." | tee -a "$LOG"
"$PY" "$SKILL/scripts/safe_exec.py" --tool subfinder --target example-b.edu.cn --scope "$SCOPE" -- \
  -d example-b.edu.cn -rl 5 -timeout 30 -silent -o "$OUT/subfinder.txt" >> "$LOG" 2>&1
echo "    subfinder 结果行数: $(wc -l < "$OUT/subfinder.txt" 2>/dev/null || echo 0)" | tee -a "$LOG"

# 2) 存活探测（httpx，单请求，限速 5/s）
echo "[$(ts)] [2/4] httpx 存活探测 ..." | tee -a "$LOG"
{ cat "$OUT/subfinder.txt" 2>/dev/null; echo "example-b.edu.cn"; echo "www.example-b.edu.cn"; } > "$OUT/_all_hosts.txt"
"$PY" "$SKILL/scripts/safe_exec.py" --tool httpx --target example-b.edu.cn --scope "$SCOPE" -- \
  -l "$OUT/_all_hosts.txt" -silent -rate-limit 5 -timeout 10 -o "$OUT/httpx_alive.txt" >> "$LOG" 2>&1
echo "    httpx 存活主机数: $(wc -l < "$OUT/httpx_alive.txt" 2>/dev/null || echo 0)" | tee -a "$LOG"

# 3) 低速端口扫描（naabu，top-100，rate 50，T2，-Pn）
echo "[$(ts)] [3/4] naabu top-100 低速端口 ..." | tee -a "$LOG"
"$PY" "$SKILL/scripts/safe_exec.py" --tool naabu --target example-b.edu.cn --scope "$SCOPE" -- \
  -list "$OUT/httpx_alive.txt" -top-ports 100 -rate 50 -Pn -timeout 30 -o "$OUT/naabu_ports.txt" >> "$LOG" 2>&1
echo "    naabu 端口结果字节: $(wc -c < "$OUT/naabu_ports.txt" 2>/dev/null || echo 0)" | tee -a "$LOG"

# 4) 浅层爬取（katana，仅 www，深度 2）
echo "[$(ts)] [4/4] katana 浅层爬取 (www only) ..." | tee -a "$LOG"
"$PY" "$SKILL/scripts/safe_exec.py" --tool katana --target www.example-b.edu.cn --scope "$SCOPE" -- \
  -u https://www.example-b.edu.cn -d 2 -jc -silent -timeout 10 -o "$OUT/katana_urls.txt" >> "$LOG" 2>&1
echo "    katana URL 数: $(wc -l < "$OUT/katana_urls.txt" 2>/dev/null || echo 0)" | tee -a "$LOG"

echo "[$(ts)] === 扫描完成（nuclei 跳过：教育网极克制 + 未确认模板存在）===" | tee -a "$LOG"
