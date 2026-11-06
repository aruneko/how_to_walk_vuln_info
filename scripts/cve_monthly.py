"""CVE の月別発行数を集計し、グラフを描画するスクリプト。

使い方:
    git clone --depth 1 https://github.com/CVEProject/cvelistV5
    python3 scripts/cve_monthly.py cvelistV5

集計方法:
    cves/ 以下の CVE JSON 5 レコードのうち state が PUBLISHED のものを、
    cveMetadata.datePublished（CVE List への公開日）の年月で数える。
    REJECTED（取り下げ）のレコードは含めない。
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

START, END = "2021-01", "2026-10"
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CSV_OUT = os.path.join(REPO, "data", "cve-monthly.csv")
PNG_OUT = os.path.join(REPO, "assets", "cve-monthly.png")

# 図の中に書き込む出来事（年月, ラベル）
EVENTS = [
    ("2024-02", "2024年2月\nNVD のエンリッチメントが停滞\nLinux カーネルが CNA に"),
    ("2024-09", "2024年9月30日\nバックログ解消の\n期限を守れず"),
    ("2026-04", "2026年4月15日\nNVD が\n優先度方式へ転換"),
]


def count(cvelist_dir):
    monthly = collections.Counter()
    for dirpath, _, files in os.walk(os.path.join(cvelist_dir, "cves")):
        for name in files:
            if not (name.startswith("CVE-") and name.endswith(".json")):
                continue
            try:
                with open(os.path.join(dirpath, name), encoding="utf-8") as fh:
                    meta = json.load(fh).get("cveMetadata", {})
            except (OSError, json.JSONDecodeError):
                continue
            published = meta.get("datePublished")
            if meta.get("state") == "PUBLISHED" and published:
                monthly[published[:7]] += 1
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

    x = range(len(months))
    ax.bar(x, values, width=0.78, color=bar, zorder=3)

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

    top = max(values) * 1.08
    ax.set_ylim(0, top)
    for ym, label in EVENTS:
        i = months.index(ym)
        ax.axvline(i, color=muted, linewidth=1, linestyle=(0, (3, 3)), zorder=2)
        ax.text(i - 0.6, top * 0.97, label, ha="right", va="top", fontsize=8.5, color=muted, linespacing=1.4)

    # 先頭と末尾の値だけ直接ラベルを付ける
    for i in (0, len(values) - 1):
        ax.text(i, values[i] + top * 0.01, f"{values[i]:,}", ha="center", va="bottom", fontsize=9, color=ink)

    ax.set_title("CVE の月別発行数（2021年1月〜2026年10月）", loc="left", fontsize=14, color=ink, pad=14)
    fig.text(0.01, 0.01, "出典: CVEProject/cvelistV5 の PUBLISHED レコードを datePublished の年月で集計（2026年11月4日時点）",
             fontsize=8, color=muted)
    fig.tight_layout(rect=(0, 0.03, 1, 1))
    os.makedirs(os.path.dirname(PNG_OUT), exist_ok=True)
    fig.savefig(PNG_OUT, facecolor=surface)


def main():
    monthly = count(sys.argv[1])
    os.makedirs(os.path.dirname(CSV_OUT), exist_ok=True)
    with open(CSV_OUT, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["month", "published"])
        writer.writerows(monthly.items())
    plot(monthly)
    years = collections.Counter()
    for m, v in monthly.items():
        years[m[:4]] += v
    for y, v in sorted(years.items()):
        print(y, f"{v:,}")


if __name__ == "__main__":
    main()
