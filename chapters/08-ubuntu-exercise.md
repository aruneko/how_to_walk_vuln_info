# 8. 【演習】Ubuntu の USN 情報をもとにした影響判定

> 目安時間: 25分（説明 3分 ＋ 演習 17分 ＋ 解説 5分）

## この演習のねらい

- deb のバージョンの読み方と比べ方を理解し、**バックポート**された修正を正しく判定できるようになる
- USN の**ソースパッケージ**と、`dpkg -l` に表示される**バイナリパッケージ**を対応づけられるようになる
- **USN と CVE の多対多の関係**をふまえて、「当たっていない修正」と「その中に含まれる高リスクの CVE」を見つけられるようになる
- パッケージのバージョンだけでは分からない、**実際に動いているカーネル**の状態を確認できるようになる

---

## 8.1 演習の前に

第7章で紹介したように、Canonical は USN を **OSV 形式**でも公開しています。この演習では、第5章・第6章と同じ OSV 形式の USN を使って、Ubuntu サーバーの影響判定を行います。

OSV 形式の USN は、GitHub の [canonical/ubuntu-security-notices](https://github.com/canonical/ubuntu-security-notices) リポジトリや、[security-metadata.canonical.com/osv/](https://security-metadata.canonical.com/osv/) から入手できます。

GHSA との主な違いは次のとおりです。

| | GHSA（第6章） | USN（この演習） |
|---|---|---|
| `ecosystem` | `PyPI`、`npm` など | `Ubuntu:24.04:LTS` など、**Ubuntu のリリースごと** |
| `package.name` | パッケージ名 | **ソースパッケージ**の名前 |
| バージョン | エコシステムの規則（PEP 440 など） | **deb の規則**（エポック・上流のバージョン・リビジョン） |
| 1 件に含まれる CVE | 通常 1 件 | **数件〜千件以上**（`upstream` に並ぶ） |

## 8.2 演習

問題文、サーバーの情報、USN のデータは [`exercises/ubuntu/`](../exercises/ubuntu/README.md) にあります。

### 進め方

| 時間 | やること |
|---|---|
| 0〜3分 | 8.1 の説明。問題文と `server/web01.txt` を確認する |
| 3〜8分 | 問1・問2：deb のバージョン比較、OpenSSL の判定（NVD と USN の比較） |
| 8〜15分 | 問3：当たっていない USN を洗い出し、その中の KEV を探す（2〜3 人で分担してよい） |
| 15〜20分 | 問4：実際に動いているカーネルを確認し、やるべきことを決める |
| 20〜25分 | 解説 |

問5は発展問題です。時間が余った人や、復習として取り組んでください。

> **補足**：時間があれば、教員の端末で Ubuntu の OVAL を使った `oscap oval eval` の実行結果を見せると、第7章の内容とつながります。

## 8.3 解説

解答と解説は [`exercises/ubuntu/ANSWER.md`](../exercises/ubuntu/ANSWER.md) にあります（演習が終わってから見てください）。
