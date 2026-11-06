# NVD 演習：学生用 Windows PC の脆弱性トリアージ

## シナリオ

あなたは大学の研究室で、学生が使う Windows PC の管理を手伝っています。

2026年10月20日、研究室の先生から次のように頼まれました。

> 研究室の学生用ノート PC に入っているソフトウェアについて、今年（2026年）公開された脆弱性のうち、次の 6 件が気になっています。
> この PC が影響を受けるかを調べて、**どの順番で対処すればよいか**を、理由とあわせて教えてください。
> 一度に全部は対応できないので、急ぐべきものから順番に並べてほしいです。

## 前提となる環境

対象の PC の情報は次のとおりです（[`data/inventory.csv`](data/inventory.csv) と同じ内容です）。

| ソフトウェア | バージョン | 備考 |
|---|---|---|
| Windows 11 Pro | 24H2 | |
| Google Chrome | 152.0.7920.104 | 普段使いのブラウザ。自動更新は再起動待ちで止まっている |
| Adobe Acrobat Reader（Continuous） | 26.001.21529 | 論文の PDF を読むのに使用 |
| Zoom Workplace for Windows | 6.6.12 | オンラインゼミで使用 |
| 7-Zip | 24.09 | 配布資料の展開に使用 |
| VLC media player | 3.0.21 | 講義動画の再生に使用 |
| PuTTY | 0.83 | 研究室サーバーへの SSH 接続に使用 |
| Visual Studio Code | 1.104.2 | プログラミング課題に使用 |
| Python | 3.13.7 | プログラミング課題に使用 |

- 学内ネットワークにつながったノート PC で、**インターネットから直接アクセスできるサービスは動いていません**（BOD 26-04 でいう「公開状態」は「いいえ」）
- 利用者は 1 人で、普段は管理者権限のないアカウントで使っています

## 使用するデータ

`data/` に、2026年10月20日時点の NVD の情報（NVD CVE API 2.0 形式の JSON）を同梱しています。同じ情報は NVD の Web ページでも確認できます（ただし、内容は今後更新されている可能性があります）。

| CVE | ファイル | NVD の Web ページ |
|---|---|---|
| CVE-2026-87491 | [`data/CVE-2026-87491.json`](data/CVE-2026-87491.json) | https://nvd.nist.gov/vuln/detail/CVE-2026-87491 |
| CVE-2026-34621 | [`data/CVE-2026-34621.json`](data/CVE-2026-34621.json) | https://nvd.nist.gov/vuln/detail/CVE-2026-34621 |
| CVE-2026-53412 | [`data/CVE-2026-53412.json`](data/CVE-2026-53412.json) | https://nvd.nist.gov/vuln/detail/CVE-2026-53412 |
| CVE-2026-48101 | [`data/CVE-2026-48101.json`](data/CVE-2026-48101.json) | https://nvd.nist.gov/vuln/detail/CVE-2026-48101 |
| CVE-2026-102875 | [`data/CVE-2026-102875.json`](data/CVE-2026-102875.json) | https://nvd.nist.gov/vuln/detail/CVE-2026-102875 |
| CVE-2026-48850 | [`data/CVE-2026-48850.json`](data/CVE-2026-48850.json) | https://nvd.nist.gov/vuln/detail/CVE-2026-48850 |

## 問題

### 問1：影響の有無を判定する

6 件の CVE それぞれについて、次のワークシートを埋めてください。

| CVE | 対象のソフトウェア | 影響を受けるバージョン | この PC は影響を受けるか | 判断の根拠（どの項目を見たか） |
|---|---|---|---|---|
| CVE-2026-87491 | | | | |
| CVE-2026-34621 | | | | |
| CVE-2026-53412 | | | | |
| CVE-2026-48101 | | | | |
| CVE-2026-102875 | | | | |
| CVE-2026-48850 | | | | |

### 問2：リスクの判断材料を集める

問1で「影響を受ける」と判定した CVE について、次の表を埋めてください。

| CVE | CVSS 基本スコア（誰が付けたか） | KEV に載っているか | SSVC：悪用状況 | SSVC：自動化可能性 | SSVC：技術的影響 | BOD 26-04 の修正期限 |
|---|---|---|---|---|---|---|
| | | | | | | |

### 問3：対処する順番を決める

問2の結果をもとに、対処する順番を決めてください。それぞれの順位について、**なぜその順番にしたのか**を一言で説明してください。

### 問4：考察

1. もし CVSS 基本スコアの高い順に対処していたら、順番はどう変わりますか。その場合、どんな問題が起きるでしょうか。
2. CVE-2026-102875 の情報を調べるとき、他の CVE と比べてどんな違いがありましたか。
3. CVE-2026-48850 には、CVSS のスコアが 2 つ付いています。それぞれ誰が付けたもので、なぜ違うのでしょうか。

## ヒント

- `vulnStatus` が `Analyzed` 以外のときは、`configurations`（CPE）がないことがあります。そのときは `affected`（CNA が書いた影響範囲）や `descriptions` を読みましょう
- KEV に載っているかは、`cisaExploitAdd` があるかどうかで分かります
- SSVC の判断ポイントは `metrics.ssvcV203` にあります
- `jq` が使える場合は、次のように必要な部分だけを取り出せます

```sh
# CPE とバージョン範囲だけを表示する
jq '.vulnerabilities[0].cve.configurations' data/CVE-2026-48101.json

# CVSS と SSVC を表示する
jq '.vulnerabilities[0].cve.metrics' data/CVE-2026-48101.json
```

- Windows の PowerShell では、次のように JSON を読み込めます

```powershell
$cve = (Get-Content data\CVE-2026-48101.json -Raw | ConvertFrom-Json).vulnerabilities[0].cve
$cve.configurations.nodes.cpeMatch
```
