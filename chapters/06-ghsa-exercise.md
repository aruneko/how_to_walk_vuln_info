# 6. 【演習】GHSA の情報をもとにした影響判定

> 目安時間: 25分（説明 5分 ＋ 演習 15分 ＋ 解説・答え合わせ 5分）

## この演習のねらい

- ロックファイルと GHSA を突き合わせて、**推移的依存を含めて**影響を判定できるようになる
- `pyproject.toml`（範囲指定）と `uv.lock`（確定バージョン）の違いを説明できるようになる
- アドバイザリに書かれた攻撃の条件と、アプリケーションの実際の使い方を照らし合わせて、**リスクに基づいて**対処の順番を決められるようになる

---

## 6.1 uv と uv.lock

**uv** は、Python のパッケージとプロジェクトを管理するツールです。JavaScript の npm と `package-lock.json` の関係と同じように、uv では次の 2 つのファイルを使います。

| ファイル | 役割 | 例 |
|---|---|---|
| `pyproject.toml` | 人が書く。**直接使うパッケージ**と、許容するバージョンの範囲を書く | `fastapi>=0.115` |
| `uv.lock` | `uv lock` が自動で作る。**推移的依存を含むすべてのパッケージ**の確定バージョンを書く | `fastapi 0.128.0`、`starlette 0.50.0`、… |

`uv.lock` の中身は、パッケージごとに次のような形をしています。

```toml
[[package]]
name = "fastapi"
version = "0.128.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "annotated-doc" },
    { name = "pydantic" },
    { name = "starlette" },
    { name = "typing-extensions" },
]
```

- `name` と `version`：パッケージ名と、実際にインストールされるバージョン
- `dependencies`：このパッケージが依存しているパッケージ（ここから**推移的依存をたどれる**）
- `sdist` と `wheels`：配布ファイルの URL とハッシュ値（演習では読まなくてよい）

> **補足**：`uv.lock` は uv 独自の形式です。Python では、ツールをまたいで使える標準のロックファイル形式として `pylock.toml`（PEP 751）も定められています。

## 6.2 GHSA との突き合わせ方

第5章で見たように、GHSA の `affected` には、エコシステム・パッケージ名・バージョン範囲が書かれています。

```json
"affected": [
  {
    "package": { "ecosystem": "PyPI", "name": "starlette" },
    "ranges": [
      { "type": "ECOSYSTEM", "events": [ { "introduced": "0" }, { "fixed": "1.0.1" } ] }
    ]
  }
]
```

突き合わせは、次の 2 ステップです。

1. **パッケージ名で探す**：GHSA の `package.name` と同じ名前のパッケージを `uv.lock` から探す。PyPI のパッケージ名は、大文字・小文字や `-`・`_`・`.` の違いを区別しない（`PyJWT` と `pyjwt` は同じ）
2. **バージョンを比べる**：`uv.lock` の `version` が「`introduced` 以上、`fixed` 未満」なら影響を受ける

> **注意**：`introduced` が `0` ではないアドバイザリに注意しましょう。そのバージョンより古いものは、まだ脆弱なコードが入っていないので**影響を受けません**。

---

## 6.3 演習

問題文、アプリケーションのコード、アドバイザリは [`exercises/ghsa/`](../exercises/ghsa/README.md) にあります。

### 進め方

| 時間 | やること |
|---|---|
| 0〜5分 | 6.1・6.2 の説明。問題文と `app/main.py` を確認する |
| 5〜15分 | 問1〜問4：`pyproject.toml` と `uv.lock` を使った影響判定、依存関係の追跡、NVD との比較 |
| 15〜20分 | 問5：対処する順番を決める（2〜3 人で相談してよい） |
| 20〜25分 | 解説と、教員の端末での `uv audit` による答え合わせ |

問6は発展問題です。時間が余った人や、復習として取り組んでください。

## 6.4 解説

解答と解説は [`exercises/ghsa/ANSWER.md`](../exercises/ghsa/ANSWER.md) にあります（演習が終わってから見てください）。
