# 4. 【演習】NVD の情報をもとにした影響判定

> 目安時間: 25分（説明 5分 ＋ 演習 15分 ＋ 解説 5分）

## この演習のねらい

- NVD の脆弱性情報（JSON）から、影響を受ける製品とバージョン範囲を読み取れるようになる
- 手元の環境と照らし合わせて、「影響を受けるか／受けないか」を判定できるようになる
- 第3章で学んだ KEV・SSVC・BOD 26-04 を使って、**CVSS の大小ではなくリスクに基づいて**対処の順番を決められるようになる

---

## 4.1 NVD の脆弱性情報の読み方

NVD の情報は、Web ページ（`https://nvd.nist.gov/vuln/detail/CVE-xxxx-xxxxx`）でも、API（NVD CVE API 2.0）の JSON でも見ることができます。演習では、2026年10月20日時点の JSON を [`exercises/nvd/data/`](../exercises/nvd/data/) に同梱しています。

JSON の `vulnerabilities[0].cve` の中に、次のような項目があります。

| 項目 | 内容 | 演習で見るポイント |
|---|---|---|
| `vulnStatus` | NVD の処理状況 | `Analyzed`（エンリッチ済み）か、`Awaiting Analysis`（未処理）などか |
| `descriptions` | 説明文（CNA が書いたもの） | どの製品の、どんな脆弱性か |
| `affected` | CNA が書いた影響範囲 | NVD のエンリッチメントがない場合の手がかり |
| `configurations` | NVD が付けた **CPE** とバージョン範囲 | 影響判定の主な根拠 |
| `metrics.cvssMetricV31` / `cvssMetricV40` | CVSS のスコアとベクトル | `source` が誰か、`type` が `Primary`（NVD）か `Secondary`（CNA など）か |
| `metrics.ssvcV203` | CISA が付けた SSVC の判断ポイント | `exploitation` / `automatable` / `technicalImpact` |
| `cisaExploitAdd` / `cisaActionDue` | KEV に追加された日、連邦政府機関の対応期限 | **この項目があれば KEV に載っている** |
| `weaknesses` | CWE | 脆弱性の種類 |

> **補足**：`source` が `134c704f-9b21-4f2e-91b3-4a467353bcc0` となっているものは、CISA が ADP（Vulnrichment）として付けた情報です。`nvd@nist.gov` は NVD、それ以外のメールアドレスは各 CNA です。

### CPE の読み方

`configurations` には、影響を受ける製品が **CPE 2.3** という形式で書かれています。

```
cpe:2.3:a:zoom:workplace_desktop:*:*:*:*:*:windows:*:*
```

CPE はコロン（`:`）で区切られた項目の並びです。主な項目は次のとおりです。

| 位置 | 項目 | 上の例の値 | 意味 |
|---:|---|---|---|
| 3 | part | `a` | 種類（`a`: アプリケーション、`o`: OS、`h`: ハードウェア） |
| 4 | vendor | `zoom` | ベンダー名 |
| 5 | product | `workplace_desktop` | 製品名 |
| 6 | version | `*` | バージョン（`*` は「別の項目で範囲を指定する」の意味） |
| 7 | update | `*` | アップデート（Adobe のトラック名 `continuous` などが入ることもある） |
| 11 | target_sw | `windows` | 動作環境（Windows 版だけが対象、など） |

`*` は「何でもよい（すべて）」、`-` は「該当なし」を意味します。

バージョンが `*` のときは、次の項目で範囲が指定されます。

| 項目 | 意味 |
|---|---|
| `versionStartIncluding` | このバージョン**以上**が影響を受ける |
| `versionStartExcluding` | このバージョン**より大きい**ものが影響を受ける |
| `versionEndIncluding` | このバージョン**以下**が影響を受ける |
| `versionEndExcluding` | このバージョン**未満**が影響を受ける（＝このバージョンで修正済み） |

たとえば次の例は「9.21 以上 26.01 未満の 7-Zip が影響を受ける」という意味です。

```json
{
  "vulnerable": true,
  "criteria": "cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*",
  "versionStartIncluding": "9.21",
  "versionEndExcluding": "26.01"
}
```

> **注意**：`configurations` の `operator` が `AND` のときは、「この製品が、この OS の上で動いている場合」のような**組み合わせの条件**を表します。`"vulnerable": false` の CPE（OS など）は、それ自体が脆弱なのではなく、条件として書かれているだけです。

> **注意**：バージョンは文字列ではなく、**区切りごとの数値**として比べます。たとえば `152.0.7920.104` と `153.0.8010.36` では、最初の区切り（152 と 153）で大小が決まります。

---

## 4.2 演習

問題文、対象 PC のソフトウェア一覧、脆弱性情報は [`exercises/nvd/`](../exercises/nvd/README.md) にあります。

### 進め方

| 時間 | やること |
|---|---|
| 0〜5分 | 問題文と対象 PC のソフトウェア一覧を確認する。4.1 の読み方を確認する |
| 5〜15分 | 6 件の CVE それぞれについて、影響の有無とリスクの判断材料をワークシートに記入する（2〜3 人で分担してよい） |
| 15〜20分 | 対処する順番を決め、その理由を説明できるようにする |
| 20〜25分 | 解説 |

## 4.3 解説

解答と解説は [`exercises/nvd/ANSWER.md`](../exercises/nvd/ANSWER.md) にあります（演習が終わってから見てください）。
