# Self-audit

Before an independent audit, ZENOS audits its own source with Cloudflare's open-source
[security-audit-skill](https://github.com/cloudflare/security-audit-skill), pinned to commit `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`
after reading every file of it. It runs at least three times, and again before every release. Code it has to run is
run only inside ZENOS's own sandbox (bubblewrap with every namespace unshared, its seccomp filter, no network, an
unprivileged user, size-capped memory, files and time). What it finds is fixed with tests before it goes in; what
it found is published once the fixes are released (SECURITY.md).

## Run 1 (source at `16c844b`, fixed in 0.2.0, published 6 Nov 2026)

28 weaknesses found; 27 fixed with tests in commit `8b65896`, which the 0.2.0 image is built from; one is not fixed
and needs a change of design (the last row). "Who" is who could use it before the fix.

| Part | Who | What could happen | Fix |
|---|---|---|---|
| Messenger, the PC's local port | another account on the PC, or a web page open in a browser (DNS rebinding, cross-site requests) | use the messenger as the user: read, send, link devices, answer approvals | the port answers only the PC's own window: the request must name 127.0.0.1/localhost at that port, carry no other site's Origin, and show a key written to a file only the account can read |
| Messenger relay, request bodies | anyone who can reach the relay | stop the relay with a body that is not JSON, or exhaust memory with a large one | bodies capped at 1 MiB; bad JSON is a 400, not a crash |
| Messenger relay, who an account is | any account on the relay | claim any organization and clearance (L5) in its own key bundle | name, organization and clearance come from the relay's directory, kept by its administrator; an unlisted account is L1 |
| Messenger relay, new channels | any account | create a channel with other people already in it, above its own clearance | a new channel holds only its creator, at most at the creator's clearance; others come in through the checked invitation |
| Messenger relay and federation, message levels | any account | send or fetch a message marked above the sender's or recipient's clearance | the relay refuses levels above either clearance |
| Federation, safety-check answers | anyone who can reach the relay | fill the "safe / need help" counts with made-up answers | an answer must be signed by a device registered on the relay; one per person |
| Messenger window | another device in a conversation | run script in the window through a reaction, a level field or a message kind | what another device sends is checked when it arrives (known kinds, level 1-5, plain short emoji) and escaped in the window |
| Guard, pre-filed operations | the desk user | reset how much of an approved plan was used, extend its time, or point the plan file at a system file that the guard (root) then overwrites | the guard keeps the use count itself, ends a plan at the earliest of its limits, and reads the user's files without following links |
| Guard, what keeps running during a stop | the desk user | keep a program running while the PC is stopped by naming it like the messenger or the display | only programs only root can change are kept running, checked by the program the kernel runs, not by its name |
| Guard, the USB folder | the desk user | have root copy a linked system file into quarantine, or stop the guard with a pipe named like a sealed file | links and pipes are not followed; a file is copied without following links |
| Network cut while an L4+ file is open | the desk user | lift the cut by writing 0 to a file in their own folder | the cut holds while the process given the plaintext, or any process it started, is alive; the file can only add to it |
| AI guard | any account on the PC | make the guard learn an unlimited list of addresses | at most 20 new addresses per account per hour and 256 in all, host names only |
| Key agent, AI guard not running | anyone who can stop it | open L3+ files while the AI guard is stopped | when the AI guard is installed and not running, L3+ files stay closed |
| Approval page (demo) | another account on the PC, or a web page | approve as an officer, or inject markup through a request file | the page answers only who shows its key (a file only the account can read); every shown value is escaped or a number |
| Audit node | an enrolled PC | stop a request handler with a record that is not an object | every record is checked to be an object first |
| ZENOS Data, storage reads | someone who saw one signed read | replay it within the time window | each read carries a nonce that is refused the second time |
| ZENOS Data, sign-in tokens | a server holding a person's token | use it at another server | a token names the server it was made for and lives at most an hour |
| Vulnerability watch, mitigations | whoever obtained the officers' signatures on a malformed record | write extra lines into a system setting file | the record's id and CVE list are accepted only in their plain shapes |
| Package wrapper (dpkg) | an administrator tricked into installing | install a package that skips the checks by giving it another name, or a whole folder with -R | every file argument is checked as a package; -R is refused while checks are on |
| API model pins | whoever can change the model setting | point a pinned model at another port, plain HTTP or another path of the same host | the pin covers the whole address; only https |
| App windows | a page shown inside an app window | use the app's bridge to read files anywhere in the home folder (keys, settings) | the bridge answers only the app's own page; paths are held to the person's folders (no hidden folders), drives, and the opened file |
| Office AI relay | a web page open in a browser | make the relay call any address, including local services | only the app's own page, with a JSON request; only https (http only for this PC) |
| Storage grid, manifests | another peer | place a different manifest under a file's id first and block the real one | the id is bound to the uploader's key and the manifest is signed by it |
| Storage grid, no administrator key | a peer that says nothing | be treated as cleared for L5 | a peer that claims nothing is L1 |
| Repository automation | a step running the repository's code | use a token that can write to the repository | collecting and publishing are separate jobs; the job with the write token runs none of the repository's code |
| Feedback board, AI answers | someone posting on the board | steer the AI reviewer into posting links under its name | an AI answer with a link or address waits for a maintainer |
| Credentials vault (not fixed) | a program of the same user | pose as the browser or messenger and ask for a password after the phone approval | needs the browser in its own account; tracked in the roadmap |

Changes others may notice are in the [CHANGELOG](../CHANGELOG.md) under 0.2.0.
