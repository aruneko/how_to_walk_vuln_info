# GHSA 演習：解答と解説

> 演習が終わってから読んでください。データはすべて 2026年10月20日時点の GitHub Advisory Database と NVD の情報にもとづいています。

## 問1：pyproject.toml だけで判定できるか

**判定できません。** 理由は 2 つあります。

1. **バージョンが確定していない**：`pyproject.toml` には `fastapi>=0.115` のような**範囲**しか書かれていません。実際にどのバージョンが入っているかは、`uv lock` を実行した時期によって変わります
2. **推移的依存が書かれていない**：`starlette` と `anyio` は `pyproject.toml` に出てきません。7 件中 4 件は、`pyproject.toml` を見ているだけでは**調べる対象にすら気づけません**

## 問2：uv.lock で影響を判定する

| GHSA ID | パッケージ | uv.lock のバージョン | 影響を受ける範囲 | 影響を受けるか |
|---|---|---|---|---|
| GHSA-86qp-5c8j-p5mr | starlette | 0.50.0 | 0 以上 1.0.1 未満 | **影響あり** |
| GHSA-wqp7-x3pw-xc5r | starlette | 0.50.0 | 0 以上 1.1.0 未満 | **影響あり** |
| GHSA-7f5h-v6xp-fcq8 | starlette | 0.50.0 | 0.39.0 以上 **0.49.1 未満** | 影響なし（すでに修正版） |
| GHSA-pp6c-gr5w-3c5g | python-multipart | 0.0.22 | 0 以上 0.0.27 未満 | **影響あり** |
| GHSA-cfh3-3jmp-rvhc | pillow | 12.1.0 | 10.3.0 以上 12.1.1 未満 | **影響あり** |
| GHSA-ffc3-869f-jxw9 | pyjwt | 2.11.0 | 0 以上 2.14.0 未満 | **影響あり** |
| GHSA-3w57-8xmc-8v26 | anyio | 4.12.1 | **4.14.0 以上** 4.14.2 未満 | 影響なし（まだ脆弱なバージョンではない） |

### ポイント

- **影響なしの 2 件は理由が違います**。GHSA-7f5h-v6xp-fcq8 は `fixed`（0.49.1）より新しいので、すでに修正済みです。GHSA-3w57-8xmc-8v26 は `introduced`（4.14.0）より古いので、脆弱なコードがまだ入っていません。`introduced` を見落として「4.14.2 未満だから影響あり」と判定しないように注意しましょう
- GHSA ではパッケージ名が `PyJWT`、`uv.lock` では `pyjwt` になっています。PyPI のパッケージ名は**大文字・小文字や `-`・`_`・`.` の違いを区別しない**決まり（名前の正規化）になっていて、どちらも同じパッケージを指します
- バージョンの比較は区切りごとの数値で行います。`0.0.22` は `0.0.27` より小さい、`12.1.0` は `12.1.1` より小さい、という具合です

## 問3：依存関係をたどる

`uv.lock` の `dependencies` をたどると、次のようになります。

```
lab-image-api（このプロジェクト）
└── fastapi 0.128.0
    └── starlette 0.50.0
        └── anyio 4.12.1
```

- `starlette` は **fastapi** から引き込まれています
- `anyio` は **starlette**（さらにその先の fastapi）から引き込まれています

FastAPI は Starlette の上に作られたフレームワークなので、FastAPI を使うアプリケーションは必ず Starlette を使っています。「自分では Starlette を使っていない」と思っていても、影響を受けるということです。

> **補足**：uv が使える環境では、`uv tree` で依存関係を木の形で表示できます。`uv tree --invert --package starlette` とすると、starlette を引き込んでいるパッケージを逆向きにたどれます。

## 問4：NVD で調べていたらどうなったか

### 1. CPE のベンダー名と製品名

| CVE | NVD の CPE | uv.lock のパッケージ名 | CNA（GitHub）が書いたベンダー名 |
|---|---|---|---|
| CVE-2026-48710 | `encode:starlette` | `starlette` | Kludex |
| CVE-2026-25990 | `python:pillow` | `pillow` | python-pillow |
| CVE-2026-102268 | `pyjwt_project:pyjwt` | `pyjwt` | jpadilla |

製品名はパッケージ名と一致していますが、**ベンダー名は 3 つともバラバラ**で、`uv.lock` から導くことはできません。starlette のベンダー名は CPE では開発元の組織名（encode）、CNA の情報では現在のメンテナー名（Kludex）と、情報源によっても違っています。GHSA なら「PyPI の `starlette`」で一意に決まります。

### 2. CVE-2026-42561（python-multipart）

NVD の `vulnStatus` は `Deferred` で、エンリッチメントが行われていません。そのため **CPE（`configurations`）がありません**。NVD の CPE だけで検知するツールでは、この脆弱性を**見逃してしまいます**。同じく、CVE-2026-63349（anyio）も `Awaiting Analysis` で CPE がありません。

第1章で見たように、2026年4月以降、NVD は多くの CVE をエンリッチしなくなりました。ライブラリの脆弱性を調べるときに GHSA のようなエコシステムの情報源が欠かせない理由がここにあります。

## 問5：対処する順番

### リスクの判断材料

| GHSA ID | GHSA の深刻度 | KEV | 悪用状況 | 自動化可能性 | 技術的影響 | BOD 26-04 の期限 | このアプリで攻撃が成立するか |
|---|---|---|---|---|---|---|---|
| GHSA-86qp-5c8j-p5mr（starlette） | Moderate（6.5） | **載っている** | **active** | yes | partial | **3 日**（2 行目） | **成立する** |
| GHSA-cfh3-3jmp-rvhc（pillow） | High | 載っていない | none | yes | total | **3 日**（5 行目） | **成立する** |
| GHSA-ffc3-869f-jxw9（pyjwt） | **Critical（9.1）** | 載っていない | poc | yes | total | **3 日**（5 行目） | 成立しない |
| GHSA-pp6c-gr5w-3c5g（python-multipart） | High（7.5） | 載っていない | none | yes | partial | 14 日（6 行目） | **成立する** |
| GHSA-wqp7-x3pw-xc5r（starlette） | High（7.5） | 載っていない | none | yes | partial | 14 日（6 行目） | 成立しない |

### 攻撃が成立するかの判断

- **starlette（GHSA-86qp-5c8j-p5mr）**：`request.url.path` を使ってアクセスを制限しているミドルウェアが、細工した `Host` ヘッダーで回避される脆弱性です。`main.py` の `admin_guard` は、まさに `request.url.path.startswith("/admin")` で管理者向けのページを守っています。リバースプロキシもないため、**誰でも `/admin/stats` にアクセスできてしまいます**
- **pillow（GHSA-cfh3-3jmp-rvhc）**：細工した PSD 画像を読み込むと、メモリの範囲外に書き込みが起きる脆弱性です。`/convert` は誰でも使えて、`Image.open()` で**形式を問わずに**画像を開いているため、PSD 画像を送るだけで攻撃できます。修正版にすぐ上げられない場合は、`Image.open(..., formats=["PNG", "JPEG"])` のように受け付ける形式を絞ることで回避できます
- **pyjwt（GHSA-ffc3-869f-jxw9）**：攻撃が成立するには、`jwt.decode` の `algorithms` に HMAC（HS256 など）と公開鍵暗号（ES256 など）が**混在している**ことが条件です。`main.py` は `algorithms=["HS256"]` だけで、鍵も共通鍵なので、**この条件を満たしません**
- **python-multipart（GHSA-pp6c-gr5w-3c5g）**：`multipart/form-data` のヘッダーを大量に送ることで CPU を使い切らせる DoS（サービス妨害）です。`/convert` はファイルのアップロードを受け付けているので、**誰でも攻撃できます**
- **starlette（GHSA-wqp7-x3pw-xc5r）**：**Windows で** `StaticFiles` を使っている場合の脆弱性です。サーバーは Ubuntu で、`StaticFiles` も使っていないため、**成立しません**

### 対処の順番（解答例）

| 順位 | GHSA ID | 理由 |
|---:|---|---|
| 1 | GHSA-86qp-5c8j-p5mr（starlette） | **KEV に載っていて実際に悪用されている**。このアプリでは管理者ページの認証を回避される。BOD 26-04 でも 3 日 |
| 2 | GHSA-cfh3-3jmp-rvhc（pillow） | 誰でも画像を送れて、乗っ取りにつながりうる（total）。BOD 26-04 でも 3 日 |
| 3 | GHSA-pp6c-gr5w-3c5g（python-multipart） | 誰でも攻撃でき、サービスを止められる。BOD 26-04 では 14 日 |
| 4 | GHSA-ffc3-869f-jxw9（pyjwt） | 深刻度は Critical で BOD 26-04 でも 3 日だが、このアプリの使い方では攻撃が成立しない |
| 5 | GHSA-wqp7-x3pw-xc5r（starlette） | このアプリの環境（Linux、StaticFiles なし）では攻撃が成立しない。1 位の対処で starlette を上げれば同時に直る |

### 考察：深刻度の高い順に並べていたら

GHSA の深刻度（CVSS）の高い順に並べると、**pyjwt（Critical）→ pillow・python-multipart・starlette 48818（High）→ starlette 48710（Moderate）** となり、**実際に悪用されていて、このアプリで攻撃が成立する starlette の脆弱性が最後**になってしまいます。

4 位の pyjwt については、「BOD 26-04 では 3 日なのだから、2 位にすべき」という考え方もあります。BOD 26-04 の判断材料（KEV・自動化可能性・技術的影響）は、**アプリケーションの使い方を知らなくても判断できる**ように作られています。一方で、アドバイザリの `details` を読んで攻撃の条件を確認できれば、より正確に優先度を決められます。ただし、将来 `algorithms` に ES256 を追加するとその時点で攻撃が成立するので、**後回しにしても対処はする**べきです。

> **補足**：実際には、`uv.lock` を最新に更新すれば 5 件すべてがまとめて直ります。順番が重要になるのは、更新によって動作が変わらないかの確認（テスト）に時間がかかる場合や、修正版がまだない場合です。

## 問6（発展）：どう直すか

### 1. なぜ starlette が更新されなかったのか

FastAPI 0.128.0 が `starlette>=0.40.0,<0.51.0` と、Starlette のバージョンに**上限**を付けているためです。`uv lock --upgrade-package starlette` は starlette だけを更新しようとしますが、fastapi 0.128.0 の上限を超えられないので、0.50.0 のままになります。uv はエラーを出さないので、**「更新したつもりで直っていない」**ことに気づきにくい点に注意が必要です。

### 2. どう直すか

starlette の修正版（1.0.1 以上。今回の 2 件をどちらも直すには 1.1.0 以上）を入れるには、**上限のない新しい FastAPI に上げる**必要があります。FastAPI は 0.133.0 で Starlette の上限を外しています。

たとえば `pyproject.toml` に `"starlette>=1.1.0"` を追加して `uv lock` すると、uv は条件を満たすように FastAPI も更新します（2026年10月20日時点では fastapi 0.150.0、starlette 1.9.0 になります）。

気をつけることは次のとおりです。

- **親パッケージの大きな更新を伴う**：FastAPI が 0.128.0 から 0.150.0 に上がるので、動作が変わっていないかをテストで確認する必要がある
- **上書き指定（override）は最後の手段**：uv の `override-dependencies` を使えば FastAPI の上限を無視して starlette だけを上げられますが、FastAPI が想定していない組み合わせになるため、動作の保証がなくなります
- **ほかのパッケージもまとめて直す**：今回の 7 件以外にも、この `uv.lock` には多くの脆弱性があります（次の節）

## 答え合わせ：uv audit

講義では、教員の端末で `uv audit` を実行して答え合わせをします。

```console
$ uv audit
```

`uv audit` は `uv.lock` に書かれたすべてのパッケージを OSV に照会し、該当する脆弱性を一覧にします。この `uv.lock` には、今回調べた 5 件以外にも、pillow・pyjwt・urllib3 などに**数十件**の脆弱性が見つかります（GitHub Advisory Database で数えると 55 件）。

- 2 月に `uv lock` してから 8 か月放置しただけで、これだけの脆弱性が積み上がる
- 手作業で 1 件ずつ調べるのは現実的ではなく、**ツールで網羅的に洗い出し、リスクの高いものから人が判断する**という分担が必要になる

また、`uv audit` の結果には GHSA ID のほかに `PYSEC-` から始まる ID が出てくることがあります。これは PyPI の脆弱性データベース（Python Packaging Advisory Database）の ID です。**同じ脆弱性に CVE・GHSA・PYSEC の複数の ID が付いている**ことにも注目してください。
