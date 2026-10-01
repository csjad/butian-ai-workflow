#!/usr/bin/env bash
# 安装外部安全工具（Go 工具链）。仅安装，不发起任何扫描。
# 需 Go 1.21+ 且在 PATH。工具安装到 $HOME/go/bin。
set -euo pipefail

if ! command -v go >/dev/null 2>&1; then
  echo "[error] 未检测到 Go，请先安装 Go 1.21+ (https://go.dev/dl/)" >&2
  exit 1
fi
echo "[ok] $(go version)"

TOOLS=(
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "github.com/projectdiscovery/katana/cmd/katana@latest"
  "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
  "github.com/projectdiscovery/dalfox/v2/cmd/dalfox@latest"
  "github.com/lc/gau/v2/cmd/gau@latest"
  "github.com/tomnomnom/waybackurls@latest"
)

export PATH="$HOME/go/bin:$PATH"

for t in "${TOOLS[@]}"; do
  name=$(basename "$t" | sed 's/@latest//')
  echo "==> 安装 $name"
  if go install "$t"; then
    echo "[ok] $name"
  else
    echo "[fail] $name 安装失败" >&2
  fi
done

# 更新 nuclei 模板
if command -v nuclei >/dev/null 2>&1; then
  echo "==> 更新 nuclei 模板"
  nuclei -update-templates || echo "[warn] 模板更新失败（可稍后手动 nuclei -update-templates）"
fi

echo "安装完成。请确认 \$HOME/go/bin 在 PATH 中。"
