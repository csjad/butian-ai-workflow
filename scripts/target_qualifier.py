#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
target_qualifier.py — SRC/补天 目标预筛打分器（60 秒定性）

用途：
    在投入 nuclei / Strix / 手工深测之前，先对一批候选域名做**单次请求级**预检，
    按「动态面 / 防护强度 / 技术栈年龄 / 资产广度」打分排序，把明显没有产出的
    目标（跳转壳、纯静态、被 WAF 阻断）直接筛掉，避免无效投入。

合规约束（强制）：
    1. 仅对**已进入授权白名单**的域名运行（先用 scope_validator.py 校验）。
    2. 每个域名只发 1~2 个请求（不跟随出域跳转、不枚举路径）。
    3. 若判定为 anti-bot / WAF 挑战 → 输出 verdict=BLOCKED，**禁止绕过**，直接跳过该目标。
    4. 本脚本不执行任何漏洞检测、不做爆破、不触达业务数据。

用法：
    python target_qualifier.py -f domains.txt                # 批量（每行一个域名）
    python target_qualifier.py -d www.a.com -d www.b.com     # 直接传域名
    python target_qualifier.py -f domains.txt --out score.md # 输出到文件
    python target_qualifier.py -f domains.txt --no-ct        # 跳过 CT 子域查询（更快）

输出：按分数降序的表格 + verdict（HIGH / MID / LOW / SKIP）
"""

import argparse
import json
import re
import ssl
import sys
import time
import urllib.request
import urllib.error
from collections import OrderedDict

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
TIMEOUT = 12
MAX_BODY = 300_000

# 多级后缀（用于判定"注册域是否相同"）
MULTI_SUFFIX = {"com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn", "co.jp", "com.hk", "com.tw"}

# ---------- WAF / 反自动化特征 ----------
WAF_SIGNS = [
    ("加速乐 Jiasule", lambda h, b: "x-via-jsl" in h or "__jsluid_s" in h or "jsl" in b[:2000].lower()),
    ("Cloudflare",     lambda h, b: "cf-ray" in h or "cloudflare" in h.get("server", "").lower()),
    ("腾讯云 WAF",      lambda h, b: "x-waf-uuid" in h or "qcloudwzgj" in b[:3000]),
    ("阿里云 WAF",      lambda h, b: "ali-swift" in h or "aliyun" in h.get("server", "").lower()),
    ("ModSecurity",    lambda h, b: "mod_security" in h.get("server", "").lower()),
    ("安全狗",          lambda h, b: "safedog" in h or "safedog" in b[:2000].lower()),
    ("创宇盾/知道创宇",  lambda h, b: "yundun" in b[:3000] or "365cyd" in b[:3000]),
    ("拦截页(通用)",    lambda h, b: any(k in b[:3000] for k in ["访问被拒绝", "请求被拦截", "您的访问请求", "Access Denied", "Forbidden", "防火墙"])),
]

# ---------- 技术栈 / CMS 指纹 ----------
TECH_SIGNS = OrderedDict([
    ("ASP.NET",     lambda h, b: "x-aspnet" in h or "x-aspnetmvc-version" in h or "__viewstate" in b[:8000].lower()),
    ("PHP",         lambda h, b: bool(re.search(r"\.php(\?|\"|'|$)", b[:20000], re.I)) or "php" in h.get("x-powered-by", "").lower()),
    ("Java/JSP",    lambda h, b: bool(re.search(r"\.jsp(\?|\"|'|$)", b[:20000], re.I)) or "jsessionid" in b[:8000].lower()),
    ("Struts2",     lambda h, b: re.search(r"\.action(\?|$)", b[:20000], re.I)),
    ("WordPress",   lambda h, b: "wp-content" in b[:20000] or "wp-includes" in b[:20000]),
    ("织梦DedeCMS",  lambda h, b: bool(re.search(r"/plus/|dedeajax|dedecms|DedeCMS", b[:20000]))),
    ("帝国CMS",      lambda h, b: "/e/admin" in b[:20000] or "empirecms" in b[:20000].lower()),
    ("点晴/博达系",   lambda h, b: "/system/resource/" in b[:20000]),
    ("TRS WCM",     lambda h, b: re.search(r"info/\d+/\d+\.htm", b[:20000])),
    ("ThinkPHP",    lambda h, b: "thinkphp" in b[:20000].lower() or "system error" in b[:3000].lower()),
    ("jQuery(旧)",   lambda h, b: bool(re.search(r"jquery[/-](1\.[0-9]|2\.[0-1])", b[:40000], re.I))),
])

SEC_HEADERS = ["strict-transport-security", "content-security-policy", "x-frame-options",
               "x-content-type-options", "referrer-policy"]


def registrable(host: str) -> str:
    """取注册域（处理 .com.cn 等多级后缀）"""
    host = host.split(":")[0].strip().lower().rstrip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-3:]) in MULTI_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """★ 合规关键：绝不跟随重定向（尤其是跳转到授权域之外的 3xx）"""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(url: str):
    """单次 GET，**不跟随重定向**（越域跳转只记录 Location，绝不请求目标域）"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    })
    try:
        with opener.open(req, timeout=TIMEOUT) as r:
            body = r.read(MAX_BODY).decode("utf-8", errors="ignore")
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            return r.status, hdrs, body, None
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(MAX_BODY).decode("utf-8", errors="ignore")
        except Exception:
            pass
        hdrs = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
        return e.code, hdrs, body, None
    except Exception as e:
        return 0, {}, "", str(e)


def ct_count(domain: str) -> int:
    """crt.sh 被动子域计数（第三方源，不发往目标）"""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read().decode("utf-8", errors="ignore"))
        subs = set()
        for e in data:
            for n in re.split(r"\n", e.get("name_value", "")):
                n = n.strip().lstrip("*.")
                if n.endswith(domain):
                    subs.add(n)
        return len(subs)
    except Exception:
        return -1  # -1 = 未知


def qualify(domain: str, use_ct: bool = True) -> dict:
    d = domain.strip().lower()
    if not d.startswith(("http://", "https://")):
        d = "https://" + d
    host = re.sub(r"^https?://", "", d).split("/")[0]

    t0 = time.time()
    status, hdrs, body, err = fetch(d)
    elapsed = round(time.time() - t0, 1)

    res = {
        "domain": host,
        "status": status,
        "body_bytes": len(body),
        "sec": elapsed,
        "redirect_out": "",
        "waf": [],
        "tech": [],
        "dynamic": 0,
        "forms": 0,
        "sec_headers": 0,
        "ct_subs": -1,
        "score": 0,
        "reasons": [],
        "verdict": "LOW",
    }

    if status == 0:
        res["verdict"] = "SKIP"
        res["reasons"].append(f"不可达({err[:40]})")
        return res

    # ---- 1. 跳转出域检测 ----
    loc = hdrs.get("location", "")
    if status in (301, 302, 303, 307, 308) and loc:
        try:
            tgt_host = re.sub(r"^https?://", "", loc).split("/")[0]
            if registrable(tgt_host) != registrable(host):
                res["redirect_out"] = tgt_host
                res["score"] -= 100
                res["reasons"].append(f"★跳转出域→{tgt_host}（不在授权范围，不得跟测）")
        except Exception:
            pass
        if len(body) == 0:
            res["score"] -= 40
            res["reasons"].append("302 响应体 0 字节（纯跳转壳，无攻击面）")

    # ---- 2. WAF / 反自动化 ----
    for name, fn in WAF_SIGNS:
        try:
            if fn(hdrs, body):
                res["waf"].append(name)
        except Exception:
            pass
    if res["waf"]:
        if status == 403 or "拦截页" in "".join(res["waf"]) or "加速乐" in "".join(res["waf"]):
            res["score"] -= 50
            res["reasons"].append(f"★防护阻断/anti-bot：{'、'.join(res['waf'])}（禁止绕过→跳过）")
        else:
            res["score"] -= 15
            res["reasons"].append(f"有防护：{'、'.join(res['waf'])}（可测但需降速）")
    else:
        res["score"] += 20
        res["reasons"].append("无明显 WAF/防自动化")

    # ---- 3. 技术栈 ----
    for name, fn in TECH_SIGNS.items():
        try:
            if fn(hdrs, body):
                res["tech"].append(name)
        except Exception:
            pass
    if res["tech"]:
        res["score"] += 15
        if any(k in res["tech"] for k in ["ASP.NET", "Java/JSP", "Struts2", "PHP", "织梦DedeCMS", "帝国CMS", "ThinkPHP", "jQuery(旧)"]):
            res["score"] += 10
            res["reasons"].append(f"老旧/动态技术栈：{'、'.join(res['tech'])}")
        else:
            res["reasons"].append(f"技术栈：{'、'.join(res['tech'])}")

    # ---- 4. 动态面 ----
    if body:
        dyn = re.findall(r'href=["\']([^"\']*\?(?:id|ID|newsid|wbnewsid|cid|type|page|keyword|q|cat|article)[^"\']*)["\']', body, re.I)
        res["dynamic"] = len(set(dyn))
        res["forms"] = len(re.findall(r"<form", body, re.I))
        ext = len(re.findall(r"(?:\.jsp|\.aspx|\.php|\.action|\.do)(?:\?|$)", body, re.I))
        if res["dynamic"] > 0:
            res["score"] += 25
            res["reasons"].append(f"带参链接 {res['dynamic']} 个（有输入点）")
        if res["forms"] > 0:
            res["score"] += 15
            res["reasons"].append(f"表单 {res['forms']} 个（有提交点）")
        if ext > 0:
            res["score"] += 15
            res["reasons"].append(f"动态脚本端点 {ext} 处（jsp/aspx/php/action/do）")
        if res["dynamic"] == 0 and res["forms"] == 0 and ext == 0:
            res["score"] -= 30
            res["reasons"].append("★纯静态站（无输入点，注入/XSS 面≈0）")

    # ---- 5. 安全头（侧面反映运维水平）----
    res["sec_headers"] = sum(1 for h in SEC_HEADERS if h in hdrs)
    if res["sec_headers"] <= 1:
        res["score"] += 10
        res["reasons"].append(f"安全头仅 {res['sec_headers']}/5（配置薄弱，易出低端问题）")

    # ---- 6. 资产广度 ----
    if use_ct:
        n = ct_count(registrable(host))
        res["ct_subs"] = n
        if n > 200:
            # 泛域名证书 / crt.sh 数据噪声会导致虚高，不作为加分依据
            res["reasons"].append(f"CT 数据 {n} 条（>200，疑为泛域名证书噪声，不计分）")
        elif n >= 5:
            res["score"] += 15
            res["reasons"].append(f"CT 子域 {n} 个（资产面广）")
        elif n == 1:
            res["score"] -= 15
            res["reasons"].append("CT 仅根域 1 个名字（资产面窄）")

    # ---- 定级 ----
    s = res["score"]
    blocked = any("禁止绕过" in r for r in res["reasons"])
    out_of_domain = any("跳转出域" in r for r in res["reasons"])
    if blocked or out_of_domain:
        res["verdict"] = "SKIP"
    elif s >= 60:
        res["verdict"] = "HIGH"
    elif s >= 25:
        res["verdict"] = "MID"
    else:
        res["verdict"] = "LOW"
    return res


def render(rows, use_ct=True):
    order = {"HIGH": 0, "MID": 1, "LOW": 2, "SKIP": 3}
    rows.sort(key=lambda r: (order[r["verdict"]], -r["score"]))
    icon = {"HIGH": "🔥", "MID": "🟡", "LOW": "⚪", "SKIP": "⛔"}
    lines = []
    lines.append("| 等级 | 分数 | 域名 | 状态 | 响应体 | WAF/防护 | 技术栈 | 带参 | 表单 | CT子域 | 安全头 | 判定依据 |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for r in rows:
        lines.append("| {v} {verdict} | {score} | `{d}` | {st} | {bb}B | {waf} | {tech} | {dyn} | {fm} | {ct} | {sh}/5 | {rs} |".format(
            v=icon[r["verdict"]], verdict=r["verdict"], score=r["score"], d=r["domain"],
            st=r["status"] or "0", bb=r["body_bytes"],
            waf="、".join(r["waf"]) or "—", tech="、".join(r["tech"][:3]) or "—",
            dyn=r["dynamic"], fm=r["forms"], ct=(r["ct_subs"] if r["ct_subs"] >= 0 else "-"),
            sh=r["sec_headers"], rs="；".join(r["reasons"][:3]) or "—"))
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="SRC 目标预筛打分器")
    ap.add_argument("-f", "--file", help="域名清单文件（每行一个）")
    ap.add_argument("-d", "--domain", action="append", default=[], help="单个域名（可重复）")
    ap.add_argument("-o", "--out", help="输出 markdown 文件路径")
    ap.add_argument("--no-ct", action="store_true", help="跳过 CT 子域查询（更快）")
    args = ap.parse_args()

    domains = list(args.domain)
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        domains.append(line)
        except Exception as e:
            print(f"[!] 读取清单失败: {e}")
            sys.exit(1)

    if not domains:
        ap.print_help()
        sys.exit(1)

    print(f"[*] 目标预筛开始，共 {len(domains)} 个域名（每域 1 个请求，CT={'关' if args.no_ct else '开'}）")
    rows = []
    for d in domains:
        r = qualify(d, use_ct=not args.no_ct)
        rows.append(r)
        print(f"    [{r['verdict']:4}] {r['score']:>4} 分  {r['domain']}  ({r['status']})  {'、'.join(r['reasons'][:2])}")

    md = render(rows)
    print("\n=== 评分表（按等级/分数排序）===\n")
    print(md)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write("# 目标预筛评分表\n\n")
            f.write(f"生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}　域名数：{len(rows)}\n\n")
            f.write(md + "\n")
        print(f"\n[+] 已写入 {args.out}")
    print("\n[*] 提示：SKIP 类目标（跳转出域 / 被 WAF 阻断）禁止绕过，直接放弃。HIGH 类优先投入。")


if __name__ == "__main__":
    main()
