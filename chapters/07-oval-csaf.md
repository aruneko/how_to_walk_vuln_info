# 7. OVAL (Ubuntu)、CSAF (Red Hat) の解説

> 目安時間: 25分

## この章のねらい

- Linux ディストリビューションのパッケージでは、NVD や GHSA の情報だけでは**正しく影響を判定できない**理由を説明できるようになる
- Ubuntu が提供する **OVAL**、Red Hat が提供する **CSAF / VEX** が、それぞれ何を表すデータなのかを理解する
- **RHSA や USN と CVE が「多対多」の関係**にあることを理解し、パッチ適用の単位と脆弱性の単位の違いを説明できるようになる

---

## 7.1 Linux サーバーの脆弱性は「誰の」情報を見るべきか

### バックポートという仕組み

第5章の最後で、GHSA は OS のパッケージを扱えないと述べました。では、NVD の CPE を使えばよいかというと、ここにも大きな落とし穴があります。

Ubuntu や Red Hat Enterprise Linux（RHEL）のような**ディストリビューション**は、OS の安定性を保つため、リリース後はソフトウェアの**バージョンを基本的に上げません**。その代わり、上流（開発元）で見つかった脆弱性の**修正部分だけを取り出して、古いバージョンに組み込みます**。これを**バックポート**と呼びます。

実際の例を見てみましょう。Linux カーネルの脆弱性 **CVE-2026-31431**（KEV に掲載）について、NVD は次のように影響範囲を示しています（一部）。

```
cpe:2.3:o:linux:linux_kernel  5.11 以上 5.15.204 未満  → 影響を受ける
cpe:2.3:o:linux:linux_kernel  6.7  以上 6.12.85  未満  → 影響を受ける
...
```

一方、RHEL 9 でこの脆弱性を修正したカーネルのバージョンは次のとおりです。

```
kernel-5.14.0-687.5.3.el9_8
       └────┘ └────────────┘
     上流の    Red Hat 独自の
    バージョン  リリース番号
```

RHEL 9 のカーネルは、リリースから現在まで**ずっと「5.14.0」**です。NVD の CPE で判定すると「5.11 以上 5.15.204 未満」に当てはまるので、**修正済みなのに「影響あり」と判定されてしまいます**（偽陽性）。修正されたかどうかは、後ろの `687.5.3.el9_8` の部分で決まるのです。

Ubuntu も同じです。Ubuntu 24.04 LTS の OpenSSL は、上流の `3.0.13` をもとにしたまま、`3.0.13-0ubuntu3.16` のように**後ろの番号を上げて**修正を重ねています。

| ディストリビューション | パッケージのバージョンの形 | 例 |
|---|---|---|
| RHEL（RPM） | `名前-エポック:バージョン-リリース.アーキテクチャ` | `kernel-0:5.14.0-687.5.3.el9_8.x86_64` |
| Ubuntu（deb） | `エポック:上流のバージョン-ディストリビューションのリビジョン` | `3.0.13-0ubuntu3.16` |

バージョンの大小の比べ方も、RPM と deb でそれぞれ独自の規則があります（たとえば deb では `~` が付くと**小さい**とみなされる）。

### ディストリビューションごとの判断

ディストリビューションは、修正を配布するだけでなく、**自分たちのパッケージに対する独自の判断**も公開しています。

- **影響を受けない**：脆弱なコードがビルドに含まれていない、該当する機能が無効になっている、など
- **修正しない**：影響が小さい、またはサポート対象外のため対応しない
- **独自の深刻度**：Red Hat は Critical / Important / Moderate / Low、Ubuntu は critical / high / medium / low / negligible という独自の評価を付ける。NVD の CVSS とは一致しないことがある

つまり、Linux サーバーの脆弱性は、**そのパッケージを配布しているディストリビューション自身の情報**を見る必要があります。

| ディストリビューション | 修正の告知 | 機械可読なデータ |
|---|---|---|
| Red Hat（RHEL） | **RHSA**（Red Hat Security Advisory） | **CSAF**（アドバイザリ）、**VEX**（CVE ごと）。OVAL は縮小中 |
| Ubuntu | **USN**（Ubuntu Security Notice） | **OVAL**、OSV、VEX |
| Debian | DSA / DLA | Debian Security Tracker、OVAL |

この章では、Ubuntu の OVAL と Red Hat の CSAF を取り上げます。

## 7.2 OVAL — 「この状態なら脆弱」を判定するための言語

### OVAL とは

**OVAL（Open Vulnerability and Assessment Language）**は、「システムがどういう状態なら脆弱か」を記述するための XML の言語です。もともと MITRE が開発し、CIS を経て現在は NIWC Atlantic の SCC チームが管理しています。

OVAL のデータは、**OpenSCAP**（`oscap` コマンド）などの評価ツールに読み込ませて、**対象のシステムの上で実行**します。ツールはインストールされているパッケージを調べ、OVAL に書かれた条件と照らし合わせて、結果を報告します。

OVAL の定義（definition）は、次のような入れ子の構造になっています。

```
definition（定義：「USN-8847-1 の修正が当たっていない」など）
└── criteria（条件の組み合わせ：AND / OR）
    └── criterion → test（テスト：「パッケージ X のバージョンが Y 未満か」）
                    ├── object（何を調べるか：パッケージ X）
                    └── state （どういう状態なら当てはまるか：バージョンが Y 未満）
```

### Ubuntu の OVAL

Canonical は、サポート中のすべての Ubuntu リリースについて、次の 2 種類の OVAL を公開しています。

| 種類 | 内容 | 主な用途 |
|---|---|---|
| **USN OVAL** | USN（修正の告知）ごとの定義。「この USN の修正版より古いパッケージが入っているか」 | **適用されていない修正**を見つける |
| **CVE OVAL** | CVE ごとの定義。Canonical が CVE を調べた結果（影響の有無、修正版）をもとに作られる | **残っている脆弱性**を見つける |

たとえば、Ubuntu 24.04 LTS（コードネーム noble）の USN OVAL は、次のように使います。

```console
$ wget https://security-metadata.canonical.com/oval/com.ubuntu.$(lsb_release -cs).usn.oval.xml.bz2
$ bunzip2 com.ubuntu.$(lsb_release -cs).usn.oval.xml.bz2
$ oscap oval eval --report report.html com.ubuntu.$(lsb_release -cs).usn.oval.xml
```

USN OVAL の定義は、おおむね次のような形をしています（2026年9月の OpenSSL の修正 USN-8847-1 を例に、**説明のために大幅に簡略化**したもの）。

```xml
<definition class="patch" id="oval:com.ubuntu.noble:def:...">
  <metadata>
    <title>USN-8847-1 -- OpenSSL vulnerabilities</title>
    <affected family="unix"><platform>Ubuntu 24.04 LTS</platform></affected>
    <reference source="USN" ref_id="USN-8847-1" />
    <reference source="CVE" ref_id="CVE-2026-35189" />
    <reference source="CVE" ref_id="CVE-2026-35191" />
    <!-- … ほかの CVE … -->
  </metadata>
  <criteria>
    <criterion test_ref="oval:com.ubuntu.noble:tst:..."
               comment="openssl のバージョンが修正版より古い" />
  </criteria>
</definition>

<!-- test が参照する state（状態）：Debian 形式のバージョンで「3.0.13-0ubuntu3.16 未満」 -->
<linux-def:dpkginfo_state id="oval:com.ubuntu.noble:ste:...">
  <linux-def:evr datatype="debian_evr_string" operation="less than">0:3.0.13-0ubuntu3.16</linux-def:evr>
</linux-def:dpkginfo_state>
```

ポイントは次の 2 つです。

- 比較の基準が、上流の `3.0.x` ではなく、Ubuntu のパッケージのバージョン `3.0.13-0ubuntu3.16` になっている。そのため**バックポートを正しく扱える**
- 比較の方法（`datatype="debian_evr_string"`）まで指定されていて、deb の規則でバージョンを比べることが保証される

### OVAL の課題

OVAL は 20 年以上使われてきた実績のある形式ですが、XML が大きく複雑で、「判定のロジック」まで含むため扱いにくいという課題もあります。Red Hat は OVAL（v2）を**メンテナンスモード**に移し、**RHEL 10 以降の OVAL は公開しない**ことを決めています。代わりに推奨しているのが、次に紹介する CSAF と VEX です。

> **補足**：Ubuntu は OVAL に加えて、USN を **OSV 形式**でも公開しています（第5章で紹介した GHSA と同じ形式）。OSV では、`ecosystem` が `Ubuntu:24.04:LTS` のように、Ubuntu のリリースごとのエコシステムとして表されます。

## 7.3 CSAF — 機械可読なセキュリティアドバイザリ

### CSAF とは

**CSAF（Common Security Advisory Framework）**は、セキュリティアドバイザリを機械可読な形で表すための標準です。標準化団体 OASIS が 2022年に CSAF 2.0 として標準化しました。データは **JSON** で表され、旧来の CVRF という形式の後継にあたります。

OVAL が「システムの状態を判定するロジック」を書くのに対して、CSAF は「**どの製品のどのバージョンが、どの脆弱性に対して、どういう状態か**」という**事実**を書きます。判定のロジックはスキャナ側が持ちます。

CSAF にはいくつかの種類（プロファイル）があり、Red Hat は主に次の 2 つを公開しています。

| 種類 | 単位 | 内容 | 公開場所 |
|---|---|---|---|
| **セキュリティアドバイザリ**（`csaf_security_advisory`） | **RHSA ごと** | その RHSA で修正された CVE と、修正版のパッケージ | `security.access.redhat.com/data/csaf/v2/advisories/` |
| **VEX**（`csaf_vex`） | **CVE ごと** | その CVE が、Red Hat のすべての製品に対してどういう状態か（修正済み・影響あり・影響なし・調査中） | `security.access.redhat.com/data/csaf/v2/vex/` |

### RHSA の CSAF を読む

2026年5月19日に公開された **RHSA-2026:19225**（RHEL 9 のカーネルの修正）の CSAF を見てみましょう（実際のデータから一部を抜き出したもの）。

**document：アドバイザリ全体の情報**

```json
"document": {
  "category": "csaf_security_advisory",
  "title": "Red Hat Security Advisory: kernel security update",
  "aggregate_severity": { "text": "Important" },
  "tracking": {
    "id": "RHSA-2026:19225",
    "initial_release_date": "2026-05-19T20:12:17+00:00"
  }
}
```

**product_tree：製品とパッケージの一覧**

```json
{
  "category": "product_name",
  "name": "Red Hat Enterprise Linux BaseOS (v. 9)",
  "product": {
    "product_id": "BaseOS-9.8.0.Z.MAIN.EUS",
    "product_identification_helper": { "cpe": "cpe:/o:redhat:enterprise_linux:9::baseos" }
  }
}
```

```json
{
  "category": "product_version",
  "name": "kernel-0:5.14.0-687.5.3.el9_8.x86_64",
  "product": {
    "product_id": "kernel-0:5.14.0-687.5.3.el9_8.x86_64",
    "product_identification_helper": {
      "purl": "pkg:rpm/redhat/kernel@5.14.0-687.5.3.el9_8?arch=x86_64"
    }
  }
}
```

製品（RHEL 9 の BaseOS）には CPE が、パッケージには第5章で紹介した **PURL** が付いています。この 2 つは `relationships` で結び付けられ、`BaseOS-9.8.0.Z.MAIN.EUS:kernel-0:5.14.0-687.5.3.el9_8.x86_64` という「**どの製品に含まれる、どのパッケージか**」を表す ID になります。

**vulnerabilities：修正された脆弱性**

```json
{
  "cve": "CVE-2026-31431",
  "title": "kernel: crypto: algif_aead - Revert to operating out-of-place",
  "product_status": {
    "fixed": [ "BaseOS-9.8.0.Z.MAIN.EUS:kernel-0:5.14.0-687.5.3.el9_8.x86_64", "…（計 303 件）" ]
  },
  "remediations": [
    { "category": "vendor_fix", "url": "https://access.redhat.com/errata/RHSA-2026:19225" }
  ],
  "threats": [
    { "category": "impact", "details": "Important" },
    { "category": "exploit_status", "date": "2026-05-01T00:00:00+00:00",
      "details": "CISA: https://www.cisa.gov/known-exploited-vulnerabilities-catalog" }
  ],
  "scores": [
    { "cvss_v3": { "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "baseScore": 7.8 } }
  ]
}
```

- `product_status.fixed`：このパッケージのこのバージョンで**修正済み**
- `remediations`：対処方法。`vendor_fix` は「ベンダーの修正版を適用する」
- `threats`：Red Hat 独自の深刻度（`impact`）と、**KEV に載った日**（`exploit_status`）
- Red Hat は、この脆弱性を Critical ではなく Important とした理由を「攻撃にはローカルからのアクセスが必要なため」と説明しています。第3章で見たように、**KEV に載っていても、各社の深刻度の評価は別**です

### VEX — CVE ごとの「影響の有無」

**VEX（Vulnerability Exploitability eXchange）**は、「**この製品はこの脆弱性の影響を受けるか**」を表すための文書です。特に重要なのは、「**影響を受けない**」ことを、理由とともに明示できる点です。

CSAF の VEX では、`product_status` に次のような状態を書きます。

| 状態 | 意味 |
|---|---|
| `fixed` | 修正済み |
| `known_affected` | 影響を受ける（修正はまだ、または修正しない） |
| `known_not_affected` | 影響を受けない |
| `under_investigation` | 調査中 |

`known_not_affected` には、`flags` で理由を付けます。たとえば `component_not_present`（その部品が含まれていない）、`vulnerable_code_not_present`（脆弱なコードが含まれていない）などです。

実際に、CVE-2026-31431 の Red Hat の VEX（2026年10月時点）を見ると、次のようになっていました。

- **fixed**：3,276 件の製品とパッケージの組み合わせ。RHEL 8・9・10、その延長サポート版、OpenShift など、**36 件の RHSA** で修正されている
- **known_not_affected**：42 件。RHEL 6・7 のカーネルは、理由 `vulnerable_code_not_present`（脆弱なコードが含まれていない）で**影響を受けない**

スキャナが VEX を使えば、「RHEL 9 のカーネル 5.14.0 は、NVD の範囲には入るが、`5.14.0-687.5.3.el9_8` 以降なら修正済み」「RHEL 6 のカーネルは、そもそも影響を受けない」といった判断を、**Red Hat 自身の判断にもとづいて**行えます。7.1 節で見た偽陽性も、これで解消できます。

> **補足**：Red Hat は 2026年4月、VEX の形式を改善すると発表しました。製品を「RHEL 9」のような大きな単位ではなく「RHEL 9.6」「RHEL 9.4 EUS」のような**サポートの流れ（ストリーム）ごと**に表すようにし、CPE や PURL による製品の識別も強化する予定です。

## 7.4 RHSA と CVE は「多対多」

NVD や GHSA では「1 つの CVE（またはアドバイザリ）」を単位に考えてきました。しかし、Linux ディストリビューションでは、**修正は RHSA や USN という単位で配布されます**。そして、RHSA・USN と CVE は**多対多**の関係にあります。

### 1 つの RHSA に、複数の CVE が束ねられる

RHSA は「**パッケージの更新**」の単位です。同じパッケージの複数の脆弱性は、1 つの更新にまとめて修正されます。

| RHSA | 公開日 | 対象 | 含まれる CVE |
|---|---|---|---|
| RHSA-2026:19225 | 2026-05-19 | RHEL 9 の kernel | CVE-2026-23060、**CVE-2026-31431（KEV）**、CVE-2026-31677、CVE-2026-43284 の **4 件** |
| RHSA-2026:34911 | 2026-07-02 | RHEL 10 の kernel | CVE-2025-10263、CVE-2026-43112、CVE-2026-45998、CVE-2026-46209、CVE-2026-46244、CVE-2026-46316、**CVE-2026-53362**、CVE-2026-53366 の **8 件** |

RHSA 全体の深刻度（`aggregate_severity`）は、含まれる CVE の中で**最も高いもの**になります。

注目したいのは RHSA-2026:34911 です。含まれている CVE-2026-53362 は、RHSA の公開から約 2 か月後の **2026年8月27日に KEV に追加**されました。つまり、

- RHSA の公開時点では「8 件まとめた、Important のカーネル更新」の 1 つにすぎなかった
- しかし、その中の 1 件が後から**実際に悪用され**、この RHSA を適用していないサーバーは、BOD 26-04 なら 3 日〜14 日で対応が必要な状態になった

ということです。RHSA の見出しだけを見ていると、中に含まれる CVE の**状況の変化**を見落としてしまいます。

Ubuntu の USN では、この束がさらに大きくなることがあります。カーネルの USN は特に大きく、2026年5月の **USN-8278-1 には 196 件**、9月の **USN-8728-1 には 1,417 件**の CVE が含まれていました。

### 1 つの CVE が、複数の RHSA で修正される

逆向きの関係もあります。同じ CVE でも、RHEL のバージョンやサポートの種類（通常版、延長サポート版など）ごとに、**別々の RHSA で修正**されます。

- CVE-2026-31431 は、Red Hat の **36 件の RHSA** で修正されている（7.3 節の VEX）
- Ubuntu でも、同じ CVE-2026-31431 が、カーネルの種類（AWS 向け、Azure 向けなど）ごとに **30 件の USN** に含まれている

### 何が変わるのか

この多対多の関係から、次のようなことが言えます。

| 観点 | NVD・GHSA での考え方 | ディストリビューションでの考え方 |
|---|---|---|
| 対処の単位 | CVE ごと | **パッケージの更新（RHSA・USN）ごと** |
| 「何件の脆弱性があるか」 | CVE の数 | CVE が 1,417 件あっても、**適用する更新はカーネル 1 つ**（＋再起動）ということもある |
| 優先度 | CVE ごとに判断 | 束の中に **1 件でも KEV や高リスクの CVE があれば、その更新全体が急ぎ**になる |
| 自分の環境で必要な修正 | CVE の影響範囲から判断 | **自分の RHEL のバージョン・サポートの種類**に対応する RHSA を探す |

> **ポイント**：Linux サーバーでは、「CVE ごとに影響を調べる」よりも、「**自分のサーバーに当たっていない RHSA・USN はどれか**」を調べ、その中に含まれる CVE のリスクで優先度を決める、という順番で考えるのが現実的です。ディストリビューションのパッケージは通常、**最新版に更新すれば、それまでの修正もすべて含まれる**ため、「最新版に上げる」ことが基本的な対処になります。

## 7.5 4 つの情報源の比較

| | NVD | GHSA | OVAL（Ubuntu） | CSAF / VEX（Red Hat） |
|---|---|---|---|---|
| 提供者 | NIST | GitHub | Canonical | Red Hat |
| 主な対象 | すべての CVE | オープンソースのパッケージ | Ubuntu のパッケージ | Red Hat の製品・パッケージ |
| ソフトウェアの識別 | CPE | エコシステム＋パッケージ名 | パッケージ名（deb） | CPE（製品）＋ PURL（パッケージ） |
| バージョンの基準 | 上流のバージョン | エコシステムのバージョン | **Ubuntu のパッケージのバージョン** | **RHEL のパッケージのバージョン** |
| 単位 | CVE | アドバイザリ（GHSA） | USN または CVE | RHSA（アドバイザリ）または CVE（VEX） |
| 形式 | JSON | JSON（OSV） | XML | JSON |
| 「影響なし」の表現 | なし | なし | Ubuntu の CVE トラッカーで公開 | **VEX で理由とともに表現** |

---

## この章のまとめ

- Linux ディストリビューションは、修正を古いバージョンに**バックポート**するため、上流のバージョンで判定する NVD の CPE では**偽陽性**が起きる。ディストリビューション自身の情報を見る必要がある
- **OVAL** は「この状態なら脆弱」を判定するための XML の言語で、Ubuntu は USN と CVE の OVAL を公開している。Red Hat は OVAL を縮小し、RHEL 10 以降は公開していない
- **CSAF** は機械可読なアドバイザリの標準で、Red Hat は RHSA ごとの CSAF と、CVE ごとの **VEX** を公開している。VEX は「影響を受けない」ことを理由とともに表せる
- **RHSA・USN と CVE は多対多**。1 つの RHSA に複数の CVE が束ねられ、1 つの CVE が複数の RHSA で修正される。対処の単位はパッケージの更新であり、束の中に 1 件でも高リスクの CVE があれば、その更新全体が急ぎになる

次の章では、Ubuntu の USN（OSV 形式）を使って、Ubuntu サーバーの影響判定を行います。

## 参考文献

- Canonical, [Ubuntu OVAL data](https://documentation.ubuntu.com/security/security-updates/oval/)
- Canonical, [Ubuntu OSV data](https://documentation.ubuntu.com/security/security-updates/osv/)
- Canonical, [canonical/ubuntu-security-notices](https://github.com/canonical/ubuntu-security-notices)（本章の USN の集計データの出典。2026年10月21日時点）
- OASIS, [Common Security Advisory Framework Version 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html)
- Red Hat, [Security Data](https://access.redhat.com/security/data)
- Red Hat, [OVAL v2 Announcement](https://access.redhat.com/security/oval-v2-deprecation-announcement)
- Red Hat Blog, [The future of Red Hat security data](https://www.redhat.com/en/blog/future-red-hat-security-data)（2023年4月）
- Red Hat Blog, [Red Hat VEX files for CVEs are now generally available](https://www.redhat.com/en/blog/red-hat-vex-files-cves-are-now-generally-available)
- Red Hat Blog, [Redefining security data: Red Hat's new VEX experience heading to Red Hat Summit 2026](https://www.redhat.com/en/blog/redefining-security-data-red-hats-new-vex-experience-heading-red-hat-summit-2026)（2026年4月27日）
- Red Hat, [RHSA-2026:19225](https://access.redhat.com/errata/RHSA-2026:19225)、[RHSA-2026:34911](https://access.redhat.com/errata/RHSA-2026:34911)
- Red Hat, [CSAF: RHSA-2026:19225](https://security.access.redhat.com/data/csaf/v2/advisories/2026/rhsa-2026_19225.json)、[VEX: CVE-2026-31431](https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-31431.json)
- NVD, [CVE-2026-31431](https://nvd.nist.gov/vuln/detail/CVE-2026-31431)
