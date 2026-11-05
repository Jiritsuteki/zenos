# ZENOS and the National Cybersecurity Office's guidance of 5 November 2026

On 5 November 2026 Japan's National Cybersecurity Office (内閣官房国家サイバー統括室) published guidance to businesses,
「個人情報の漏えい等につながる不正アクセスへの対策について ～ウェブサイトやモバイルアプリに関する基本的な対策の徹底～」
(https://www.cyber.go.jp/pdf/press/261105_taiou.pdf). It asks, among other things, that the software bill of
materials be matched against vulnerability information continuously, through to a fix or a mitigation, as one
operation; that CISA's KEV catalogue, NVD and JVN be checked continuously; that management screens and debug entries
exposed to the internet be stopped; and that AI used for diagnosis and monitoring leave the final decision to people.

The table lists the guidance's measures by their titles (対策例), as printed in the document, and what in ZENOS
answers each. "Not yet" means ZENOS has nothing for it so far. The numbering of some measures in the PDF's text
layer is ambiguous, so they are listed by title rather than by number.

## 1. 運用・管理段階におけるセキュリティ対策の徹底 (operation and management)

| Measure | In ZENOS |
|---|---|
| ソフトウェア構成情報の把握・管理 (know and keep the software inventory; SBOM, SCA) | Each release publishes ZENOS's own SBOM in SPDX 2.3 and CycloneDX 1.6 (`tools/sbom.py`): the ZENOS packages, the Node.js packages they ship, pinned binaries and the image's Debian packages, each with a package URL. On the PC, the installed packages are read from dpkg each time vulnerabilities are matched. Packages and AI models are installed only as released records (the update path, `Supply.lean`, `Model.lean`). |
| 脆弱性情報の継続的な収集及び影響確認 (collect vulnerability information, KEV first; match against the inventory) | `zenos-vulnwatch` (every 6 hours): CISA KEV, the Debian security tracker, NVD and JVN, matched against the installed packages, and OSV's npm list (downloaded whole, never queried) matched against the Node.js packages ZENOS ships; affected, fixed, mitigated or not affected per part (`Vuln.lean`). |
| 脆弱性対処の優先順位及び対応期限の決定 (set priorities and deadlines from criteria fixed in advance) | The order is fixed and proved: exploited (KEV) first, then by CVSS, then reachable from the network (`kev_first`, `severity_before_reach`). Security fixes install themselves; the System Monitor turns amber while one is waiting and red after 24 hours. |
| 緩和策の実施及び是正状況の管理 (mitigate when a patch cannot be applied at once; track it) | A mitigation (a kernel setting off, a module kept from loading) is a record signed by release officers and applied only when `zenos-decide` allows it (`mitigation_needs_signatures`); its state stays "mitigated" until the fix is installed, and each change is in the ledger. |
| アタックサーフェスの把握 (know what is exposed) | Inbound connections are dropped by default (`zenos-firewall`). The network sentinel reports and closes a listening port a program opens to other machines; the monitor shows remote operation of the PC. |
| 不要な公開機能の停止・制限 (stop management screens, debug entries and test environments exposed to the internet) | No ZENOS service opens a management screen to other machines without TLS, and none has a debug or administration path; checked on every build (`tests/test_no_exposed_admin.py`). |
| 継続的な外部露出の監視 (watch exposure after every change) | The sentinel's check of listening ports runs all the time, not only after changes. |
| 継続的なセキュリティ診断及び点検 (AI may assist; people make the final decision) | No AI decides anything in ZENOS. Decisions are made by `zenos-decide` (proved in Lean) from facts; mitigations need officers' signatures; text from outside sources, including prompts written for AI agents, is dropped before anything is decided. |
| ログ及びワークロードの継続的な監視・検知 (monitor logs and workloads) | A hash-chained ledger of file openings, approvals, sign-ins and installations, shipped to audit nodes of other parties that refuse a rewritten history; the System Monitor's alerts. |
| インシデントの調査・対処の迅速化 (respond quickly, under human oversight) | Signs of a leak stop the PC; it starts again only when officers approve on their phones. Alerts reach the officers through ZENOS Messages. |

## 2. 設計・開発段階におけるセキュリティ対策の徹底 (design and development)

| Measure | In ZENOS |
|---|---|
| セキュアなアーキテクチャの検討 (threat modelling; no careless exposure of management functions) | docs/THREAT_MODEL.md lists what each protection covers and what it does not; management is done from outside the PC's desktop (no terminal inside ZENOS). |
| SAST, SCA の活用 | SCA: the SBOM and `npm audit` at each release. SAST: not yet. |
| DAST, IAST の活用 | Not yet. |
| 認可不備の排除 (check permissions on the server side) | The key service, the key agent and ZENOS Data's key peers each decide on their own facts, never on what the PC or the server says; the decisions are proved. |
| 認証情報の安全な管理 (no credentials in code) | `packaging/check-secrets.sh` at each release; the PC's identity key in the TPM; officers' keys as passkeys in their phones. |
| API レート制限 | The key service and ZENOS Data's key peers limit releases per person and per machine; prompts to the phone are limited per time window (proved: `key_rate_bounded`, `ask_bounded`). |

## 3. サプライチェーンを通じた侵害への対策 (the supply chain)

| Measure | In ZENOS |
|---|---|
| OSS や外部ライブラリ等の適切な管理 | Every package and model goes in only as a record signed by two or more release officers and held by a majority of audit nodes; the SBOM lists every third-party component. |
| 委託開発における SBOM の提出と確認 | ZENOS publishes its SBOM with each release, so an organization taking ZENOS in can load it into its own inventory. |
| ゼロトラストの考え方に基づくアクセス制御 | Each file's key is released for that file, that person and that request; nothing is trusted for being inside a network. |
| 深刻な脆弱性の公表時における初動対応手順の明確化 | An exploited vulnerability that affects the PC turns the monitor red at once and is reported to the audit nodes. Who reports to whom in the organization is for the organization to set. |
