# ZENOS as the conductor

Status: in 0.2.0 (Developer Preview). First version; the parts not built yet are listed at the end.

## Why

People hand more and more work to AI agents. Today that means one provider receives everything the work touches:
the files, the mail, the customer list, the code. ZENOS takes the opposite position. ZENOS is the conductor: it
runs the task itself, calls several frontier models through their APIs, and makes sure no single provider ever
holds enough to reconstruct the person's data. ZENOS contains no AI model of its own.

## The parts

- The conductor: `zenos-conductor` (system/sbin/zenos_conductor.py, system/lib/zorch.py). It runs as the person.
  It keeps the task, the data and the token table, and every step goes through proven decisions
  (formal/ZenosFormal/Orchestrator.lean, run by zenos-decide as "step", "route" and "vote").
- Providers: frontier models reached over their APIs, with keys the person enters (~/.config/zenos/conductor.json
  and key files of mode 0600). Nothing is configured by default and no key ships with ZENOS. Some providers are
  refused whatever the configuration says: Google, Qwen, and providers subject to laws that let a state compel
  access to data without due process (matched on the API host).
- The sandbox (system/lib/zsandbox.py): every program a model writes runs on the PC in bubblewrap, in an empty root
  with /usr, /etc and /opt read-only, no network, no /home, /var or /run, and a seccomp filter that refuses sockets
  other than AF_UNIX, io_uring, ptrace, bpf, keyctl, module loading and the other calls listed in the file. The
  approach follows openai/codex's Linux sandbox (codex-rs/linux-sandbox: bubblewrap plus seccomp, io_uring
  blocked); the filter itself is written here, in classic BPF, with no library.

## Masked work: models never see the plain data

`zenos-conductor run "TASK" table.csv ...`

1. Before anything leaves the PC, the conductor replaces with tokens: the person's own terms (names, project
   names), e-mail addresses, URLs, phone numbers, dates, numbers of three or more digits, file names, and every
   column name and cell value of the tables given (plural and possessive forms included). The token table stays in
   the conductor's memory.
2. Each provider gets the masked task and a masked description of each table (column tokens, a type per column,
   the row count) and writes one Python program that uses the tokens.
3. Before sending, the conductor checks that no real value is in what came from the person's data; if one is, the
   proven step refuses (`payload_masked`) and no provider is asked anything.
4. The conductor puts the real values into each program on the PC, runs it in the sandbox, and compares the
   results. The result goes to the person; nothing goes back to the providers.

The decryption never becomes a model tool. If a model could ask for the plain value, the plain value would go to
the provider in the next API request.

## Split work: what has to be read

Some work needs the content itself. For that the conductor splits the material across providers so that no
provider holds a linkable whole: never what a record is about (a name, a label) together with its value (a number,
a diagnosis) at the same provider.

`zenos-conductor split report.md table.csv`: the table's numbers go to one provider with the row and column names
masked; the text goes to another provider with the names and the table's values masked. Each returns its part,
and the conductor puts both back together on the PC. Which provider gets which part is decided by decideRoute;
with only one provider, the task is refused rather than merged.

Splitting costs quality: each model sees less. Cross-checking and the checks on the PC are there to win it back.

## Weights

Each provider carries a weight per kind of work (tables, reports ...), from 0 to 1000, starting at 100. Weights are
measured on the PC: +10 when a provider's result was the accepted one, -20 when it differed or failed. They are
never taken from what a model says about itself. They are kept in ~/.local/state/zenos/conductor/weights.json.

Weights decide two things:

- routing: among the routes decideRoute allows, the conductor tries the providers weighted highest first;
- cross-checking: a result is accepted only when its backers hold more than half of the weight of everyone who
  answered, and at least two distinct providers back it.

Weights never enter decideRoute, so no weight can let a linked pair through. However heavy one provider is made,
it never decides alone. When no result is accepted, the conductor shows each provider's result and says so.

Accuracy is to be measured before anything is said about it outside: the same tasks on one provider with the whole
material, and through the conductor, compared on checks run on the PC.

## Outside content and destinations

Every step that would reach a destination (a tool that uses the network, an act that cannot be taken back) is
checked against the destinations the person set for the task ("dests"). Once the material came from outside (web,
mail, a file from someone else: `--outside`), only the destinations also marked safe after outside content
("after_taint") remain. Nothing a model writes is an input to that decision, so text in outside content cannot add
a destination.

## What is proven (Lean, formal/ZenosFormal/Orchestrator.lean)

- decideRoute: route_sound (only allowed providers), no_linked_pair (no provider receives a record's identifier
  and value), one_provider_not_whole (for every protected record, every provider misses part of it); the chart
  example (split allowed, both halves to one provider refused, an unlisted provider refused).
- decideVote: vote_sound, one_provider_never_decides.
- decideStep: send_to_allowed, local_sends_nothing, masked_only_out, split_needs_route, taint_narrows,
  dest_from_person (every destination reached was set by the person), confirm_irreversible (an act runs only
  after confirmation).

What the proofs rely on, outside them: the masker finding the values (it is pattern- and table-based; a name that
is neither in the person's terms nor in a table can pass), and the roles given to each piece.

## Weak spots

- The conductor holds the token table, so it is the target. A kernel or root takeover defeats it, as it defeats
  the rest of ZENOS today (THREAT_MODEL).
- Masking can leak through structure: a task about "[[T1]]'s blood test results" says something even without the
  name. Use `zenos-conductor preview` to see exactly what would leave.
- A value can identify on its own (a listed company's quarterly figures, a rare amount). Transforming such values
  before they leave is not built yet.
- Providers can see request metadata (account, address, timing). Splitting lowers what one provider learns; it does
  not hide that the person uses them.
- API data is not used for training by default at OpenAI and Anthropic, according to their own pages; logs are
  still kept for abuse monitoring (OpenAI: up to 30 days unless Zero Data Retention is approved). Masking is aimed
  at those logs, legal requests and breaches, not only at training.

## Not built yet

- Multi-step plans (this version: one program per task, or one table-and-text split).
- Acts that cannot be taken back (sending, deleting, paying): the decision is proven, but there is no act command
  yet, and the confirmation is to go through the person's phone (the key service's Messages flow).
- Sealing the API keys and the conductor's record with the key service, and shipping that record to the audit
  nodes (this version keeps its record in ~/.local/state/zenos/conductor/ledger.jsonl, digests only).
- Splitting code by module; transforming values that identify on their own.
- The user interface (Figma first, reviewed before anything ships), and the accuracy measurement.
