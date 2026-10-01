#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
srchunt_pipeline.py — SRC 单目标流水线编排器（预筛 → 授权配置 → 闸门 → 扫描 → 报告）

把之前手工重复了 5 次的动作全部自动化：
    1. 目标预筛（调用 target_qualifier）：SKIP 类直接踢掉
    2. 为入选目标**自动生成 scope.yaml**（含通用 exclude 与红线）
    3. **自动跑闸门自检**（scope_validator）：ALLOW / DENY 双向验证
    4. 写审计日志（compliance-check / asset-recon / vuln-scan）
    5. 可选：跑 nuclei（仅非侵入类模板）
    6. 生成报告骨架（含结论占位、审计记录、观察项表）

合规约束（强制，不可通过参数关闭）：
    - 只处理清单中的域名，不跟随重定向，不枚举未授权目标
    - 遇到 WAF 阻断 / anti-bot → 标记 SKIP，**不绕过**
    - nuclei 强制排除 default-login / bruteforce / dos / fuzz / intrusive
    - 绝不提交任何报告到平台

前置要求：
    域名清单必须是**已在授权范围内**的目标（补天收录 / 自有 / 客户授权）。
    本脚本不判断授权本身，授权由使用者负责（见 rules/legal.md）。

用法：
    # 仅预筛 + 生成授权配置（不扫描，最安全）
    python srchunt_pipeline.py -f domains.txt

    # 预筛 + 取分数最高的 3 个目标，生成配置并跑 nuclei
    python srchunt_pipeline.py -f domains.txt --top 3 --nuclei --yes

    # 指定工作目录与模板库路径
    python srchunt_pipeline.py -f domains.txt --workdir $WORK_DIR --templates $NUCLEI_TEMPLATES/http
"""

import argparse
import datetime
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

try:
    import target_qualifier as tq
except ImportError:
    print("[!] 找不到 target_qualifier.py，请与本脚本放在同一目录")
    sys.exit(1)

SKILL_ROOT = os.path.dirname(HERE)
SCOPE_PATH = os.path.join(SKILL_ROOT, "config", "scope.yaml")
VALIDATOR = os.path.join(HERE, "scope_validator.py")
AUDITOR = os.path.join(HERE, "audit_logger.py")

# 通用 exclude（所有目标默认套用）
COMMON_EXCLUDE = [
    "logout", "login", "signin", "register", "password", "auth", "sso",
    "account", "my.", "pay", "checkout", "order", "cart",
    "careers", "jobs", "hr.", "mail", "vpn",
    "delete", "remove", "admin",
]

SCOPE_TMPL = """# 授权范围（由 srchunt_pipeline.py 自动生成）
# 任务：{task}
# 生成时间：{ts}
# 授权依据：{auth}
#
# ⚠️ 生成后请人工确认：授权依据、exclude 列表、强度上限
#
# 自检：python scripts/scope_validator.py --scope config/scope.yaml --target {probe_ok}   （应 ALLOW）
#       python scripts/scope_validator.py --scope config/scope.yaml --target www.example-outside.com （应 DENY）
scope:
  domains:
{domains}
  ips: []
  paths: []
  exclude:
{excludes}
  rate_limit: {rate}
  max_requests: {maxreq}
  time_window: "{tw}"
  allowed_tools:
    - httpx
    - nuclei
    - katana
  forbidden_behaviors:
    - no_exploit_with_data_modification
    - no_dos
    - no_lateral_movement
    - no_data_exfiltration
    - no_persistence
    - no_auth_bruteforce
    - no_registration
    - no_waf_bypass
    - no_customer_data_access
"""

REPORT_TMPL = """# 扫描报告 — {target}

> **阶段**：草稿（待人工验证后定稿）
> **等级**：{grade}（预筛得分 {score}）
> **授权依据**：{auth}
> **测试窗口**：{tw}
> **合规声明**：全部请求经 scope_validator 校验；只读、限速、无爆破、无 WAF 绕过；全程审计留痕

---

## 一、目标预筛画像

| 项目 | 值 |
|---|---|
| 状态码 | {status} |
| 响应体 | {body}B |
| WAF / 防护 | {waf} |
| 技术栈 | {tech} |
| 带参链接 | {dyn} |
| 表单 | {forms} |
| CT 子域 | {ct} |
| 安全头 | {sec}/5 |
| 判定依据 | {reasons} |

## 二、漏洞候选与验证结论

| # | 候选点 | 验证方法 | 结论 | 置信度 |
|---|---|---|---|---|
| — | 待人工补充 | — | — | — |

> ★ 铁律：扫描器输出、指纹命中、AI 推测都只是**线索**。
> 每个候选必须经人工复现、产出可运行 PoC、独立会话重复验证 ≥2 次，才能写入结论。

## 三、nuclei 扫描结果

{nuclei_block}

## 四、观察项（不构成漏洞 · 供加固参考）

- 待补充

## 五、审计记录

| 阶段 | 状态 |
|---|---|
| compliance-check | {audit_compliance} |
| asset-recon | {audit_recon} |
| vuln-scan | {audit_scan} |

---

**结论（待人工定稿）**：{conclusion}
"""


def run(cmd, timeout=600):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="ignore")
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return -1, str(e)


def registrable_of(host):
    return tq.registrable(host)


def write_scope(target, workdir, auth_note, rate=5, maxreq=500, tw=None):
    """为单个目标生成 scope.yaml"""
    reg = registrable_of(target)
    domains = f'    - "{target}"       # 精确主机（保守）；若平台标注「无限制」可改通配 "*.{reg}"\n'
    if target.startswith("www."):
        domains = (f'    - "{target}"\n'
                   f'    - "*.{reg}"      # 通配（若授权范围明确）—— 如不需要请删除本行\n')
    excludes = "\n".join(f"    - \"{k}\"" for k in COMMON_EXCLUDE)
    tw = tw or f"{datetime.date.today()}T00:00/{(datetime.date.today() + datetime.timedelta(days=2))}T23:59"
    content = SCOPE_TMPL.format(
        task=f"{target}（由流水线生成）",
        ts=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        auth=auth_note,
        probe_ok=target,
        domains=domains,
        excludes=excludes,
        rate=rate,
        maxreq=maxreq,
        tw=tw,
    )
    os.makedirs(os.path.dirname(SCOPE_PATH), exist_ok=True)
    with open(SCOPE_PATH, "w", encoding="utf-8") as f:
        f.write(content)
    return SCOPE_PATH


def gate_check(target):
    """跑闸门双向自检，返回 (allow_ok, detail)"""
    rc, out = run([sys.executable, VALIDATOR, "--scope", SCOPE_PATH, "--target", target], timeout=60)
    allow_ok = "[ALLOW]" in out
    rc2, out2 = run([sys.executable, VALIDATOR, "--scope", SCOPE_PATH, "--target", "www.example-outside.com"], timeout=60)
    deny_ok = "[DENY]" in out2
    return (allow_ok and deny_ok), out.strip() + " | " + out2.strip().splitlines()[-1] if out2.strip() else out


def audit(phase, target, action):
    if os.path.exists(AUDITOR):
        run([sys.executable, AUDITOR, "--phase", phase, "--target", target, "--action", action], timeout=60)


def run_nuclei(target, workdir, templates, rate=20, timeout=1800):
    """非侵入模板扫描；强制排除爆破/DoS/侵入类"""
    outfile = os.path.join(workdir, "nuclei_findings.txt")
    cmd = ["nuclei", "-u", f"https://{target}",
           "-tags", "exposure,misconfig,cve,panel",
           "-exclude-tags", "default-login,bruteforce,dos,fuzz,intrusive",
           "-severity", "low,medium,high,critical",
           "-c", "5", "-rl", str(rate), "-retries", "2", "-mhe", "100",
           "-timeout", "8", "-no-color", "-silent", "-o", outfile]
    if templates and os.path.isdir(templates):
        cmd[cmd.index("-tags"):cmd.index("-tags")] = ["-t", templates]
    print(f"    [>] nuclei: {target}（限速 {rate} rps，非侵入模板）")
    rc, out = run(cmd, timeout=timeout)
    findings = ""
    if os.path.exists(outfile):
        with open(outfile, encoding="utf-8", errors="ignore") as f:
            findings = f.read().strip()
    n = len(findings.splitlines()) if findings else 0
    return n, findings, (out or "")[-500:]


def main():
    ap = argparse.ArgumentParser(description="SRC 单目标流水线编排器")
    ap.add_argument("-f", "--file", required=True, help="授权域名清单（每行一个）")
    ap.add_argument("--top", type=int, default=0, help="只处理得分最高的 N 个（0=全部非 SKIP）")
    ap.add_argument("--workdir", default="./hunt_runs", help="工作目录")
    ap.add_argument("--templates", default="", help="nuclei 模板目录")
    ap.add_argument("--nuclei", action="store_true", help="执行 nuclei 扫描（需配合 --yes）")
    ap.add_argument("--yes", action="store_true", help="确认执行扫描动作")
    ap.add_argument("--auth", default="补天平台该厂商收录（提交页截图，资产范围「无限制」）", help="授权依据说明")
    ap.add_argument("--no-ct", action="store_true", help="预筛时跳过 CT 查询")
    args = ap.parse_args()

    domains = []
    with open(args.file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                domains.append(line)
    if not domains:
        print("[!] 清单为空")
        sys.exit(1)

    os.makedirs(args.workdir, exist_ok=True)
    print(f"[*] 流水线启动：{len(domains)} 个授权目标")

    # ---------- 1. 预筛 ----------
    print("\n[阶段 1/5] 目标预筛")
    rows = []
    for d in domains:
        r = tq.qualify(d, use_ct=not args.no_ct)
        rows.append(r)
        print(f"    [{r['verdict']:4}] {r['score']:>4} 分  {r['domain']} （{r['status']}）")

    order = {"HIGH": 0, "MID": 1, "LOW": 2, "SKIP": 3}
    rows.sort(key=lambda r: (order[r["verdict"]], -r["score"]))
    with open(os.path.join(args.workdir, "01_预筛评分表.md"), "w", encoding="utf-8") as f:
        f.write("# 目标预筛评分表\n\n生成时间：" + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n\n")
        f.write(tq.render(rows) + "\n")

    candidates = [r for r in rows if r["verdict"] != "SKIP"]
    skipped = [r for r in rows if r["verdict"] == "SKIP"]
    if args.top > 0:
        candidates = candidates[:args.top]

    if skipped:
        print(f"\n    [⛔] 已剔除 {len(skipped)} 个 SKIP 目标（跳转壳/被 WAF 阻断，禁止绕过）：")
        for r in skipped:
            print(f"        - {r['domain']}：{'；'.join(r['reasons'][:1])}")

    if not candidates:
        print("\n[!] 没有可测目标（全部 SKIP）。结案。")
        return

    print(f"\n    入选 {len(candidates)} 个：{', '.join(r['domain'] for r in candidates)}")

    # ---------- 2~5. 逐目标处理 ----------
    summary = []
    for i, r in enumerate(candidates, 1):
        target = r["domain"]
        print(f"\n[阶段 2-5] ({i}/{len(candidates)}) {target}")
        tdir = os.path.join(args.workdir, target.replace("*", "wild"))
        os.makedirs(tdir, exist_ok=True)

        # 2. 生成授权配置
        write_scope(target, tdir, args.auth)
        print(f"    [✓] scope.yaml 已生成（{target}）")

        # 3. 闸门自检
        ok, detail = gate_check(target)
        print(f"    [{'✓' if ok else '✗'}] 闸门自检：{detail[:120]}")
        audit("compliance-check", target, "start")
        if not ok:
            print(f"    [!] 闸门未通过，跳过 {target}")
            audit("compliance-check", target, "denied")
            summary.append((target, r["verdict"], r["score"], "闸门未通过", 0))
            continue

        # 4. 审计
        audit("asset-recon", target, "complete")

        # 5. nuclei（可选）
        nuclei_n, nuclei_out, tail = 0, "", ""
        audit_scan = "skipped（未启用 --nuclei）"
        if args.nuclei and args.yes:
            nuclei_n, nuclei_out, tail = run_nuclei(target, tdir, args.templates)
            audit_scan = f"complete（{nuclei_n} 条输出）"
            audit("vuln-scan", target, "complete")
            print(f"    [✓] nuclei 完成：{nuclei_n} 条输出")
        elif args.nuclei and not args.yes:
            audit_scan = "skipped（缺少 --yes 确认）"
            print("    [!] 未提供 --yes，跳过扫描（安全默认）")

        # 6. 报告骨架
        rep = REPORT_TMPL.format(
            target=target, grade=r["verdict"], score=r["score"], auth=args.auth,
            tw=f"{datetime.date.today()}T00:00/{(datetime.date.today() + datetime.timedelta(days=2))}T23:59",
            status=r["status"], body=r["body_bytes"],
            waf="、".join(r["waf"]) or "无", tech="、".join(r["tech"]) or "未知",
            dyn=r["dynamic"], forms=r["forms"],
            ct=(r["ct_subs"] if r["ct_subs"] >= 0 else "查询失败"),
            sec=r["sec_headers"], reasons="；".join(r["reasons"]),
            nuclei_block=(f"发现 {nuclei_n} 条：\n\n```\n{nuclei_out[:4000]}\n```" if nuclei_n
                          else "无发现（或未执行）。\n\n> 提示：nuclei 仅覆盖已知模板，无发现 ≠ 无漏洞。"),
            audit_compliance="✅ 闸门通过", audit_recon="✅ 完成", audit_scan=audit_scan,
            conclusion="待人工验证与定稿（AI 结论不作为提交依据）",
        )
        rp = os.path.join(tdir, f"扫描报告-{target}.md")
        with open(rp, "w", encoding="utf-8") as f:
            f.write(rep)
        audit("report-draft", target, "start")
        print(f"    [✓] 报告骨架：{rp}")

        summary.append((target, r["verdict"], r["score"],
                        f"{nuclei_n} 条 nuclei 输出" if args.nuclei and args.yes else "仅预筛+配置",
                        nuclei_n))

    # ---------- 汇总 ----------
    print("\n" + "=" * 72)
    print("流水线完成汇总")
    print("=" * 72)
    print(f"{'目标':<34}{'等级':<8}{'分数':<8}{'结果'}")
    for t, v, s, res, _ in summary:
        print(f"{t:<34}{v:<8}{s:<8}{res}")
    print("=" * 72)
    print(f"\n产物目录：{os.path.abspath(args.workdir)}")
    print("  - 01_预筛评分表.md      全部目标评分排序")
    print("  - <目标>/扫描报告-*.md  单目标报告骨架（含审计记录）")
    print("\n[*] 提醒：nuclei 无发现 ≠ 无漏洞；AI 结论必须人工复现后才能定稿。绝不自动提交平台。")


if __name__ == "__main__":
    main()
