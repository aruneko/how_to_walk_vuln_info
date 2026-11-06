"""BOD 26-04 の修正期限の表（Table 1）を、2025〜2026年に公開された CVE に当てはめて集計するスクリプト。

第3章「3.5 BOD 26-04」の「実際のデータに当てはめると」の表を再現する。

使い方:
    git clone --depth 1 https://github.com/CVEProject/cvelistV5
    git clone --depth 1 https://github.com/cisagov/kev-data
    python3 scripts/bod2604_simulation.py cvelistV5 kev-data/known_exploited_vulnerabilities.json

集計方法:
    - 対象: cves/ 以下の CVE JSON 5 レコードのうち、state が PUBLISHED で、
      cveMetadata.datePublished（CVE List への公開日）が 2025年または 2026年のもの。
      CVE ID の年ではなく公開日で選ぶため、CVE-2024-xxxx などの古い ID も含まれる
    - KEV: KEV カタログ（known_exploited_vulnerabilities.json）に、その CVE ID があるかどうか
    - 自動化可能性・技術的影響: CISA の ADP（Vulnrichment）が CVE レコードに付けた SSVC の値
      （Automatable / Technical Impact）
    - SSVC の値がない CVE は、BOD 26-04 の Implementation Guidance に従い、
      自動化可能性「no」、技術的影響「total」として扱う
    - 公開状態は「すべて公開されている場合」と「すべて社内にある場合」の 2 通りで集計する

本文の数値は、cvelistV5 のコミット df2e021505cd522fe73489c898783c6def214ea2（2026年10月20日）と
KEV カタログのバージョン 2026.10.16 を使って集計したもの。
"""
import collections
import json
import os
import sys

# BOD 26-04 Table 1: (公開状態, KEV, 自動化可能, 技術的影響が total) -> 修正期限
TABLE1 = {
    (True, True, True, True): "3 日 ＋ フォレンジックトリアージ",
    (True, True, True, False): "3 日",
    (True, True, False, True): "3 日 ＋ フォレンジックトリアージ",
    (True, True, False, False): "14 日",
    (True, False, True, True): "3 日",
    (True, False, True, False): "14 日",
    (True, False, False, True): "14 日",
    (True, False, False, False): "60 日",
    (False, True, True, True): "3 日 ＋ フォレンジックトリアージ",
    (False, True, True, False): "14 日",
    (False, True, False, True): "14 日",
    (False, True, False, False): "14 日",
    (False, False, True, True): "60 日",
    (False, False, True, False): "60 日",
    (False, False, False, True): "次回の定期アップグレード時",
    (False, False, False, False): "次回の定期アップグレード時",
}
ROWS = ["3 日 ＋ フォレンジックトリアージ", "3 日", "14 日", "60 日", "次回の定期アップグレード時"]


def ssvc_options(record):
    """CVE レコードの ADP コンテナから SSVC の値を取り出す。なければ None"""
    for adp in record.get("containers", {}).get("adp", []) or []:
        for metric in adp.get("metrics", []) or []:
            other = metric.get("other", {})
            if other.get("type") == "ssvc":
                options = {}
                for kv in other.get("content", {}).get("options", []):
                    options.update(kv)
                return options
    return None


def main():
    cvelist_dir, kev_path = sys.argv[1], sys.argv[2]
    with open(kev_path, encoding="utf-8") as fh:
        kev = {v["cveID"] for v in json.load(fh)["vulnerabilities"]}

    result = {True: collections.Counter(), False: collections.Counter()}
    crosstab = collections.Counter()
    kev_by_id_year = collections.Counter()
    total = 0

    for dirpath, _, files in os.walk(os.path.join(cvelist_dir, "cves")):
        for name in files:
            if not (name.startswith("CVE-") and name.endswith(".json")):
                continue
            try:
                with open(os.path.join(dirpath, name), encoding="utf-8") as fh:
                    record = json.load(fh)
            except (OSError, json.JSONDecodeError):
                continue
            meta = record.get("cveMetadata", {})
            published = meta.get("datePublished") or ""
            if meta.get("state") != "PUBLISHED" or published[:4] not in ("2025", "2026"):
                continue

            total += 1
            cve_id = meta["cveId"]
            in_kev = cve_id in kev
            options = ssvc_options(record)
            if in_kev:
                kev_by_id_year[cve_id[4:8]] += 1

            if options is None or options.get("Automatable") is None:
                # Implementation Guidance: メタデータがない場合は no / total として扱う
                automatable, total_control = False, True
                crosstab[(in_kev, "SSVC なし")] += 1
            else:
                automatable = options["Automatable"] == "yes"
                total_control = options["Technical Impact"] == "total"
                crosstab[(in_kev, options.get("Exploitation"))] += 1

            for exposed in (True, False):
                result[exposed][TABLE1[(exposed, in_kev, automatable, total_control)]] += 1

    print(f"対象の CVE: {total:,} 件（うち KEV 掲載 {sum(kev_by_id_year.values()):,} 件）")
    print()
    print("| 修正期限 | 公開されている場合 | 社内にある場合 |")
    print("|---|---:|---:|")
    for row in ROWS:
        cells = [f"{result[e][row]:,}（{result[e][row] / total:.1%}）" if result[e][row] else "0" for e in (True, False)]
        print(f"| {row} | {cells[0]} | {cells[1]} |")
    print()
    print("KEV 掲載と SSVC の悪用状況（Exploitation）のクロス集計:")
    for (in_kev, exploitation), count in sorted(crosstab.items(), key=str):
        print(f"  KEV={'あり' if in_kev else 'なし'} / Exploitation={exploitation}: {count:,}")
    print()
    print("KEV 掲載の CVE の、CVE ID の年ごとの内訳:", dict(sorted(kev_by_id_year.items())))


if __name__ == "__main__":
    main()
