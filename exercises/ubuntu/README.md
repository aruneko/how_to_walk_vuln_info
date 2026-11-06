# Ubuntu 演習：研究室の Web サーバーの USN トリアージ

## シナリオ

研究室では、Ubuntu 24.04 LTS の Web サーバー **web01** を運用しています。nginx で研究室の Web サイトを公開していて、管理のために SSH も外部から使えるようにしています。

2026年10月20日、研究室の先生から次のように頼まれました。

> web01 は 9 月 1 日に `apt upgrade` したきりです。その後に出た Ubuntu のセキュリティ情報（USN）がいくつかあるようなので、
> **このサーバーに当たっていない修正はどれか**、**どれを急ぐべきか**を調べてください。

## 前提となる環境

- web01 は**インターネットに公開されています**（nginx と SSH）。BOD 26-04 でいう「公開状態」は「**はい**」です
- web01 の情報は [`server/web01.txt`](server/web01.txt) にあります（`lsb_release`、`uname -r`、`uptime`、`dpkg -l` の出力）

## 配布物

| ファイル | 内容 |
|---|---|
| [`server/web01.txt`](server/web01.txt) | web01 の情報 |
| [`server/old01.txt`](server/old01.txt) | 発展問題で使う、別のサーバー old01 の情報 |
| [`data/usn/`](data/usn/) | 調査対象の USN（OSV 形式、2026年10月21日時点） |
| [`data/kev/known_exploited_vulnerabilities.csv`](data/kev/known_exploited_vulnerabilities.csv) | CISA KEV カタログ（2026年10月16日版） |
| [`data/nvd/`](data/nvd/) | 一部の CVE の NVD の情報（2026年10月20日時点） |

### 調査対象の USN（Ubuntu 24.04 LTS 向け）

| USN | 公開日 | 対象（ソースパッケージ） |
|---|---|---|
| [USN-8278-1](data/usn/USN-8278-1.json) | 2026-05-19 | linux |
| [USN-8611-1](data/usn/USN-8611-1.json) | 2026-07-27 | glibc |
| [USN-8678-1](data/usn/USN-8678-1.json) | 2026-08-25 | openssl |
| [USN-8721-1](data/usn/USN-8721-1.json) | 2026-09-03 | openssh |
| [USN-8563-5](data/usn/USN-8563-5.json) | 2026-09-14 | nginx |
| [USN-8847-1](data/usn/USN-8847-1.json) | 2026-09-29 | openssl |
| [USN-8903-1](data/usn/USN-8903-1.json) | 2026-10-08 | linux |
| [USN-8917-1](data/usn/USN-8917-1.json) | 2026-10-13 | linux |

### USN の OSV データの読み方

USN の OSV データは、第5章の GHSA とほぼ同じ形をしています。

```json
{
  "id": "USN-8847-1",
  "summary": "openssl vulnerabilities",
  "upstream": [ "UBUNTU-CVE-2026-35189", "UBUNTU-CVE-2026-35191", "…" ],
  "affected": [
    {
      "package": { "ecosystem": "Ubuntu:24.04:LTS", "name": "openssl" },
      "ranges": [ { "type": "ECOSYSTEM", "events": [ { "introduced": "0" }, { "fixed": "3.0.13-0ubuntu3.16" } ] } ],
      "ecosystem_specific": {
        "binaries": [
          { "binary_name": "libssl3t64", "binary_version": "3.0.13-0ubuntu3.16" },
          { "binary_name": "openssl", "binary_version": "3.0.13-0ubuntu3.16" }
        ]
      }
    }
  ]
}
```

- `upstream`：この USN で修正された CVE（`UBUNTU-` を外すと CVE ID になる）
- `affected[].package.ecosystem`：Ubuntu のリリース。今回は **`Ubuntu:24.04:LTS`** のものだけを見る
- `affected[].package.name`：**ソースパッケージ**の名前
- `ranges[].events[].fixed`：修正されたバージョン
- `ecosystem_specific.binaries`：このソースパッケージから作られる**バイナリパッケージ**（`dpkg -l` に表示される名前）とそのバージョン

## 問題

### 問1：deb のバージョン比較

次の 2 つのバージョンのうち、新しいのはどちらですか。

1. `3.0.13-0ubuntu3.15` と `3.0.13-0ubuntu3.16`
2. `6.17.0-29.29~24.04.1` と `6.17.0-29.29`
3. `1:9.6p1-3ubuntu13.18` と `9.7p1-1`
4. `1.1.1f-1ubuntu2.24` と `1.1.1f-1ubuntu2.24+esm6`

### 問2：OpenSSL は影響を受けるか

1. `data/nvd/CVE-2026-54874.json` を見てください。NVD の CPE で判定すると、web01 の OpenSSL は CVE-2026-54874 の影響を受けますか
2. 同じ CVE-2026-54874 は、どの USN で修正されていますか。その USN にもとづくと、web01 は影響を受けますか。問2-1 の結果と違うのはなぜでしょうか
3. USN-8847-1 の対象は `openssl` というソースパッケージですが、web01 の `dpkg -l` には `openssl` のほかに `libssl3t64` があります。この 2 つの関係を説明してください。また、どちらを更新する必要がありますか

### 問3：当たっていない USN と、束の中の KEV

1. 8 件の USN それぞれについて、web01 に**適用済みか未適用か**を判定してください。ここでは **`dpkg -l` に表示されているパッケージのバージョン**だけで判断します

| USN | 対象 | 修正バージョン | web01 のバージョン | 適用済み／未適用 | 含まれる CVE の数 |
|---|---|---|---|---|---|
| USN-8278-1 | linux | | | | |
| USN-8611-1 | glibc | | | | |
| USN-8678-1 | openssl | | | | |
| USN-8721-1 | openssh | | | | |
| USN-8563-5 | nginx | | | | |
| USN-8847-1 | openssl | | | | |
| USN-8903-1 | linux | | | | |
| USN-8917-1 | linux | | | | |

2. 未適用の USN に含まれる CVE は、合わせて何件ですか。また、それを解消するために**更新が必要なソースパッケージ**はいくつですか
3. 未適用の USN の中に、**KEV に載っている CVE** は含まれていますか。含まれている場合、その CVE と、含んでいる USN を答えてください
4. 問3-3 で見つけた CVE について、`data/nvd/` の SSVC の情報を使い、BOD 26-04 の修正期限を求めてください

### 問4：本当に直っているか

問3-1 で、USN-8278-1（KEV に載っている CVE-2026-31431 を含む）は「適用済み」と判定できたはずです。

1. `server/web01.txt` の `uname -r` と `uptime` を見てください。web01 は、CVE-2026-31431 の影響を**本当に受けていない**と言えるでしょうか
2. web01 の管理者は、次に何をすべきでしょうか。BOD 26-04 の考え方もふまえて、やるべきことを順番に挙げてください

### 問5（発展）：サポートが切れたリリース

研究室には、もう 1 台 Ubuntu 20.04 LTS のサーバー **old01** があります（[`server/old01.txt`](server/old01.txt)）。

1. [`data/usn/USN-8847-2.json`](data/usn/USN-8847-2.json) を見て、old01 の OpenSSL が修正済みかどうかを判定してください
2. この修正を old01 に適用するには、何が必要でしょうか。`ecosystem` の値に注目してください

## ヒント

- deb のバージョンは `エポック:上流のバージョン-リビジョン` の形をしています。エポック（`:` の前の数字）が省略されているときは `0` です。比べるときは、**エポック → 上流のバージョン → リビジョン**の順に比べます
- `~` は「どんな文字よりも小さい（何もないよりも小さい）」、`+` は通常の記号として扱われ、何もないよりも大きくなります
- Ubuntu が使えれば、`dpkg --compare-versions 3.0.13-0ubuntu3.15 lt 3.0.13-0ubuntu3.16 && echo yes` で比較を確かめられます
- カーネルのバイナリパッケージは、`linux-image-6.8.0-138-generic` のように**名前にバージョンの一部が入っています**。`uname -r` の `6.8.0-110-generic` は、`linux-image-6.8.0-110-generic`（バージョン `6.8.0-110.110`）のカーネルで起動していることを表します
- `jq` が使える場合は、次のように USN の CVE を取り出して KEV と突き合わせられます

```sh
# USN に含まれる CVE の一覧を作る
jq -r '.upstream[] | sub("^UBUNTU-"; "")' data/usn/USN-8917-1.json > cves.txt
wc -l cves.txt

# KEV に載っているものを探す
grep -wF -f cves.txt data/kev/known_exploited_vulnerabilities.csv | cut -d, -f1
```
