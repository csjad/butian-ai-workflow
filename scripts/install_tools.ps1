#Requires -Version 5.1
<#
.SYNOPSIS
    Windows 安装脚本：安装 AI 辅助漏洞挖掘所需的外部安全工具（Go 工具链）。
.DESCRIPTION
    用 `go install` 安装 ProjectDiscovery 等开源安全工具到 $env:USERPROFILE\go\bin。
    本脚本仅安装工具，不自动发起任何扫描。运行前请确保已安装 Go 1.21+ 并加入 PATH。
    如担心 C/E 盘空间，工具默认装到用户目录，不会占用项目目录。
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

function Test-Go {
    try {
        $g = Get-Command go -ErrorAction SilentlyContinue
        if (-not $g) {
            Write-Error "未检测到 Go。请先安装 Go 1.21+ (https://go.dev/dl/) 并加入 PATH。"
            exit 1
        }
        $ver = & go version
        Write-Host "[ok] $ver"
    } catch {
        Write-Error "Go 检测失败：$_"
        exit 1
    }
}

$TOOLS = @(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "github.com/projectdiscovery/katana/cmd/katana@latest",
    "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
    "github.com/projectdiscovery/dalfox/v2/cmd/dalfox@latest",
    "github.com/lc/gau/v2/cmd/gau@latest",
    "github.com/tomnomnom/waybackurls@latest"
)

Test-Go

$binDir = Join-Path $env:USERPROFILE "go\bin"
if (-not (Test-Path $binDir)) { New-Item -ItemType Directory -Path $binDir | Out-Null }
$env:PATH = "$binDir;$env:PATH"

foreach ($t in $TOOLS) {
    $name = ($t -split "/")[-1] -replace "@latest", ""
    Write-Host "`n==> 安装 $name ($t)"
    try {
        & go install $t
        Write-Host "[ok] $name 安装完成"
    } catch {
        Write-Warning "[fail] $name 安装失败：$_"
    }
}

Write-Host "`n所有工具尝试安装完毕。验证："
foreach ($n in @("subfinder","httpx","naabu","katana","nuclei","dalfox","gau","waybackurls")) {
    $p = Get-Command $n -ErrorAction SilentlyContinue
    if ($p) { Write-Host "  [ok] $n -> $($p.Source)" }
    else   { Write-Host "  [missing] $n" }
}
Write-Host "`n请确认 $binDir 已在 PATH 中。"
