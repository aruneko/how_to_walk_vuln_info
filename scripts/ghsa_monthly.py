"""GitHub Advisory Database の月別公開数（GitHub がレビューしたもの）を集計し、グラフを描画するスクリプト。

使い方:
    git clone --depth 1 https://github.com/github/advisory-database
    python3 scripts/ghsa_monthly.py advisory-database

集計方法:
    advisories/github-reviewed/ 以下の OSV 形式のアドバイザリのうち、
    取り下げ（withdrawn）されていないものを published の年月で数える。
"""
import collections
import csv
import json
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib import font_manager  # noqa: E402

START, END = "2021-01", "2026-09"
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CSV_OUT = os.path.join(REPO, "data", "ghsa-reviewed-monthly.csv")
PNG_OUT = os.path.join(REPO, "assets", "ghsa-reviewed-monthly.png")


def count(db_dir):
    monthly = collections.Counter()
    for dirpath, _, files in os.walk(os.path.join(db_dir, "advisories", "github-reviewed")):
        for name in files:
            if not name.endswith(".json"):
                continue
            with open(os.path.join(dirpath, name), encoding="utf-8") as fh:
                adv = json.load(fh)
            if adv.get("withdrawn"):
                continue
            monthly[adv["published"][:7]] += 1
    return {m: monthly[m] for m in sorted(monthly) if START <= m <= END}


def plot(monthly):
    jp = sorted({f.name for f in font_manager.fontManager.ttflist if "CJK JP" in f.name},
                key=lambda n: (n != "Noto Sans CJK JP", "Sans" not in n))
    if jp:
        plt.rcParams["font.family"] = jp[0]
    surface, ink, muted, grid, bar = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df", "#2a78d6"

    months = list(monthly)
    values = list(monthly.values())
    fig, ax = plt.subplots(figsize=(12, 5.2), dpi=160)
    fig.patch.set_facecolor(surface)
    ax.set_facecolor(surface)
    ax.bar(range(len(months)), values, width=0.78, color=bar, zorder=3)

    ax.set_xticks([i for i, m in enumerate(months) if m.endswith("-01")])
    ax.set_xticklabels([m[:4] + "年" for m in months if m.endswith("-01")], color=muted)
    ax.set_xlim(-1, len(months))
    ax.tick_params(axis="y", colors=muted, length=0)
    ax.tick_params(axis="x", length=0)
    ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{int(v):,}"))
    ax.grid(axis="y", color=grid, linewidth=0.8, zorder=0)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(muted)
    top = max(values) * 1.1
    ax.set_ylim(0, top)

    i22 = months.index("2022-05")
    ax.text(i22 + 1.2, values[i22] * 0.97, f"2022年5月：{values[i22]:,}\n過去の CVE（2000〜2021年）を一括登録",
            ha="left", va="top", fontsize=8.5, color=muted, linespacing=1.4)

    peak = max(range(len(values)), key=lambda i: values[i] if months[i] >= "2026" else -1)
    for i in (peak, len(values) - 1):
        ax.text(i, values[i] + top * 0.01, f"{values[i]:,}", ha="center", va="bottom", fontsize=9, color=ink)

    ax.set_title("GitHub Advisory Database：レビュー済みアドバイザリの月別公開数（2021年1月〜2026年9月）",
                 loc="left", fontsize=13, color=ink, pad=14)
    fig.text(0.01, 0.01, "出典: github/advisory-database の github-reviewed を published の年月で集計（2026年10月20日時点）",
             fontsize=8, color=muted)
    fig.tight_layout(rect=(0, 0.03, 1, 1))
    os.makedirs(os.path.dirname(PNG_OUT), exist_ok=True)
    fig.savefig(PNG_OUT, facecolor=surface)


def main():
    monthly = count(sys.argv[1])
    os.makedirs(os.path.dirname(CSV_OUT), exist_ok=True)
    with open(CSV_OUT, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["month", "reviewed"])
        writer.writerows(monthly.items())
    plot(monthly)


if __name__ == "__main__":
    main()
