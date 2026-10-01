#!/usr/bin/env bash
# 通用受控扫描流水线（复用版）
# 用法：bash scripts/run_target_scan.sh <domain> <output_dir_name>
# 示例：bash scripts/run_target_scan.sh example-d.com example-d_2026-08-18
set -u
DOMAIN="${1:-}"
OUT_NAME="${2:-}"
if [ -z "$DOMAIN" ] || [ -z "$OUT_NAME" ]; then
    echo "Usage: $0 <domain> <output_dir_name>" >&2
    exit 2
fi
SKILL="$BUTIAN_ROOT"
OUT="$SKILL/output/$OUT_NAME"
SCOPE="$SKILL/config/scope.yaml"
PY="python"
LOG="$OUT/scan.log"
mkdir -p "$OUT"
ts(){ date "+%Y-%m-%d %H:%M:%S"; }
echo "[$(ts)] === 开始受控扫描 $DOMAIN (极克制) ===" | tee -a "$LOG"

# 0) 闸门自检
echo "[$(ts)] [0/4] 授权闸门自检 ..." | tee -a "$LOG"
"$PY" "$SKILL/scripts/scope_validator.py" --target "$DOMAIN" --scope "$SCOPE" | tee -a "$LOG"
"$PY" "$SKILL/scripts/scope_validator.py" --target out-of-scope.example --scope "$SCOPE" | tee -a "$LOG"
"$PY" "$SKILL/scripts/scope_validator.py" --target "www.$DOMAIN" --scope "$SCOPE" | tee -a "$LOG"

# 1) 被动子域枚举（限速 5）
echo "[$(ts)] [1/4] subfinder 被动枚举 ..." | tee -a "$LOG"
"$PY" "$SKILL/scripts/safe_exec.py" --tool subfinder --target "$DOMAIN" --scope "$SCOPE" -- \
  -d "$DOMAIN" -rl 5 -timeout 30 -silent -o "$OUT/subfinder.txt" >> "$LOG" 2>&1
echo "    subfinder 结果行数: $(wc -l < "$OUT/subfinder.txt" 2>/dev/null || echo 0)" | tee -a "$LOG"

# 2) 存活探测（单请求，限速 5/s）
echo "[$(ts)] [2/4] httpx 存活探测 ..." | tee -a "$LOG"
{ cat "$OUT/subfinder.txt" 2>/dev/null; echo "$DOMAIN"; echo "www.$DOMAIN"; } > "$OUT/_all_hosts.txt"
"$PY" "$SKILL/scripts/safe_exec.py" --tool httpx --target "$DOMAIN" --scope "$SCOPE" -- \
  -l "$OUT/_all_hosts.txt" -silent -rate-limit 5 -timeout 10 -o "$OUT/httpx_alive.txt" >> "$LOG" 2>&1
echo "    httpx 存活主机数: $(wc -l < "$OUT/httpx_alive.txt" 2>/dev/null || echo 0)" | tee -a "$LOG"

# 3) 低速端口扫描（naabu，top-100，rate 50，-Pn；注意 naabu 不支持 -T）
echo "[$(ts)] [3/4] naabu top-100 低速端口 ..." | tee -a "$LOG"
"$PY" "$SKILL/scripts/safe_exec.py" --tool naabu --target "$DOMAIN" --scope "$SCOPE" -- \
  -list "$OUT/httpx_alive.txt" -top-ports 100 -rate 50 -Pn -timeout 30 -o "$OUT/naabu_ports.txt" >> "$LOG" 2>&1
echo "    naabu 端口结果行数: $(wc -l < "$OUT/naabu_ports.txt" 2>/dev/null || echo 0)" | tee -a "$LOG"

# 4) 浅层爬取（仅 www，深度 2）
echo "[$(ts)] [4/4] katana 浅层爬取 (www only) ..." | tee -a "$LOG"
"$PY" "$SKILL/scripts/safe_exec.py" --tool katana --target "www.$DOMAIN" --scope "$SCOPE" -- \
  -u "https://www.$DOMAIN" -d 2 -jc -silent -timeout 10 -o "$OUT/katana_urls.txt" >> "$LOG" 2>&1
echo "    katana URL 数: $(wc -l < "$OUT/katana_urls.txt" 2>/dev/null || echo 0)" | tee -a "$LOG"

echo "[$(ts)] === 扫描完成（nuclei 跳过：极克制 + 未确认模板存在）===" | tee -a "$LOG"
