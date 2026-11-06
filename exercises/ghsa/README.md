# GHSA 演習：公開 Web API の依存パッケージのトリアージ

## シナリオ

研究室では、学生が作った **画像変換 API** を大学のサーバーで公開しています。FastAPI で作られていて、パッケージ管理には uv を使っています。

2026年10月20日、研究室の先生から次のように頼まれました。

> 画像変換 API の依存パッケージに、脆弱性がいくつか報告されているようです。
> 次の 7 件のアドバイザリについて、この API が影響を受けるかを調べて、**どの順番で対処すればよいか**を教えてください。
> 依存パッケージは 2026年2月に `uv lock` してから一度も更新していません。

## 前提となる環境

- サーバーは Ubuntu 24.04 で、uvicorn を**インターネットに直接公開**しています（リバースプロキシなどは使っていません）。BOD 26-04 でいう「公開状態」は「**はい**」です
- `POST /convert` は誰でも使えます。`GET /admin/stats` は管理者だけが使えます
- アプリケーションのコードは [`app/main.py`](app/main.py) です

## 配布物

| ファイル | 内容 |
|---|---|
| [`app/pyproject.toml`](app/pyproject.toml) | プロジェクトの設定。**直接の依存**と、そのバージョンの範囲指定が書かれている |
| [`app/uv.lock`](app/uv.lock) | ロックファイル。**推移的依存を含むすべてのパッケージ**の確定バージョンと、パッケージ同士の依存関係が書かれている |
| [`app/main.py`](app/main.py) | アプリケーションのコード |
| [`data/ghsa/`](data/ghsa/) | 調査対象の 7 件の GHSA（OSV 形式、2026年10月20日時点） |
| [`data/nvd/`](data/nvd/) | 同じ脆弱性の NVD の情報（KEV と SSVC の確認用、2026年10月20日時点） |

### 調査対象のアドバイザリ

| GHSA ID | CVE | パッケージ |
|---|---|---|
| [GHSA-86qp-5c8j-p5mr](data/ghsa/GHSA-86qp-5c8j-p5mr.json) | CVE-2026-48710 | starlette |
| [GHSA-wqp7-x3pw-xc5r](data/ghsa/GHSA-wqp7-x3pw-xc5r.json) | CVE-2026-48818 | starlette |
| [GHSA-7f5h-v6xp-fcq8](data/ghsa/GHSA-7f5h-v6xp-fcq8.json) | CVE-2025-62727 | starlette |
| [GHSA-pp6c-gr5w-3c5g](data/ghsa/GHSA-pp6c-gr5w-3c5g.json) | CVE-2026-42561 | python-multipart |
| [GHSA-cfh3-3jmp-rvhc](data/ghsa/GHSA-cfh3-3jmp-rvhc.json) | CVE-2026-25990 | pillow |
| [GHSA-ffc3-869f-jxw9](data/ghsa/GHSA-ffc3-869f-jxw9.json) | CVE-2026-102268 | pyjwt |
| [GHSA-3w57-8xmc-8v26](data/ghsa/GHSA-3w57-8xmc-8v26.json) | CVE-2026-63349 | anyio |

## 問題

### 問1：pyproject.toml だけで判定できるか

`app/pyproject.toml` だけを見て、7 件のアドバイザリの影響を判定してみてください。判定できないものがあれば、**なぜ判定できないのか**を説明してください。

### 問2：uv.lock で影響を判定する

`app/uv.lock` を使って、次のワークシートを埋めてください。

| GHSA ID | パッケージ | uv.lock のバージョン | 影響を受ける範囲（introduced 〜 fixed） | 影響を受けるか |
|---|---|---|---|---|
| GHSA-86qp-5c8j-p5mr | | | | |
| GHSA-wqp7-x3pw-xc5r | | | | |
| GHSA-7f5h-v6xp-fcq8 | | | | |
| GHSA-pp6c-gr5w-3c5g | | | | |
| GHSA-cfh3-3jmp-rvhc | | | | |
| GHSA-ffc3-869f-jxw9 | | | | |
| GHSA-3w57-8xmc-8v26 | | | | |

### 問3：依存関係をたどる

`starlette` と `anyio` は `pyproject.toml` に書かれていません。`uv.lock` の `dependencies` をたどって、それぞれ**どの直接の依存パッケージから引き込まれているか**を答えてください。

### 問4：NVD で調べていたらどうなったか

`data/nvd/` の NVD の情報を見て、次の問いに答えてください。

1. CVE-2026-48710（starlette）、CVE-2026-25990（pillow）、CVE-2026-102268（pyjwt）の CPE のベンダー名と製品名はそれぞれ何ですか。`uv.lock` に書かれたパッケージ名から、この CPE を導けるでしょうか
2. CVE-2026-42561（python-multipart）の NVD の情報には、何が足りないでしょうか。NVD の CPE だけで脆弱性を検知するツールを使っていたら、どうなるでしょうか

### 問5：対処する順番を決める

問2で「影響を受ける」と判定したものについて、次の表を埋めてから、対処する順番を決めてください。KEV と SSVC の情報は `data/nvd/` にあります（`cisaExploitAdd` と `metrics.ssvcV203`）。

| GHSA ID | GHSA の深刻度 | KEV | 悪用状況 | 自動化可能性 | 技術的影響 | BOD 26-04 の期限 | このアプリで実際に攻撃が成立するか（`main.py` を読んで） |
|---|---|---|---|---|---|---|---|
| | | | | | | | |

順番を決めるときは、BOD 26-04 の期限に加えて、**アドバイザリの `details` に書かれた攻撃の条件が、このアプリに当てはまるか**も考えてください。

### 問6（発展）：どう直すか

starlette を修正版に上げようとして、次のコマンドを実行しました。

```console
$ uv lock --upgrade-package starlette
Resolved 22 packages in 127ms
```

ところが、`uv.lock` の starlette は `0.50.0` のままでした。なお、FastAPI 0.128.0 は、依存として `starlette>=0.40.0,<0.51.0` を指定しています。

1. なぜ starlette が更新されなかったのでしょうか
2. starlette を修正版に上げるには、どうすればよいでしょうか。そのときに気をつけることは何でしょうか

## ヒント

- `uv.lock` の各パッケージは `[[package]]` から始まり、`name` と `version` が書かれています。エディタで `name = "starlette"` のように検索すると見つけやすいです
- GHSA の `affected[].ranges[].events` は、`introduced`（このバージョン**から**影響を受ける）と `fixed`（このバージョン**で**修正された）の組です。`introduced` 以上 `fixed` 未満が影響を受けます
- PyPI のパッケージ名は、大文字・小文字や `-`・`_`・`.` の違いを区別しません（`PyJWT` と `pyjwt` は同じパッケージ）
- Python のバージョンは、区切りごとの数値として比べます（`0.0.22` と `0.0.27` なら 3 つ目の 22 と 27 を比べる）
- `jq` が使える場合は、次のように必要な部分だけを取り出せます

```sh
# GHSA の影響範囲を表示する
jq '.affected' data/ghsa/GHSA-86qp-5c8j-p5mr.json

# NVD の KEV と SSVC の情報を表示する
jq '.vulnerabilities[0].cve | {cisaExploitAdd, ssvc: .metrics.ssvcV203}' data/nvd/CVE-2026-48710.json
```
