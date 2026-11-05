// ZENOS Feedback board (page). Everything people wrote is put on the page as text, never as markup.
"use strict";
const $ = (id) => document.getElementById(id);
function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) { if (k === "on") for (const [ev, f] of Object.entries(v)) e.addEventListener(ev, f); else if (k === "cls") e.className = v; else if (v !== false && v != null) e.setAttribute(k, v); }
  for (const c of kids.flat()) if (c != null && c !== false) e.append(c.nodeType ? c : String(c));
  return e;
}
const get = (u) => fetch(u, { credentials: "same-origin" }).then((r) => r.json());
const post = (u, b) => fetch(u, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-ZF": "1" }, body: JSON.stringify(b || {}) })
  .then(async (r) => r.status === 204 || r.redirected ? { ok: true } : r.json().catch(() => ({ ok: r.ok })));
const COLORS = ["#F59E0B", "#10B981", "#EC4899", "#3B82F6", "#8B5CF6", "#EF4444", "#14B8A6", "#F97316"];
const avatar = (handle, staff) => { let n = 0; for (const c of String(handle)) n = (n * 31 + c.charCodeAt(0)) >>> 0;
  return staff ? h("img", { cls: "av", src: "/logo.svg", alt: "" }) : h("div", { cls: "av", style: "background:" + COLORS[n % COLORS.length] }, (String(handle).replace("@", "")[0] || "?").toUpperCase()); };
const when = (t) => { const d = new Date(t), now = new Date();
  return d.toDateString() === now.toDateString() ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : d.toLocaleDateString([], { month: "short", day: "numeric" }); };
const stCls = (s) => "st st-" + String(s).replace(/\s+/g, "-");
const cap = (s) => String(s).charAt(0).toUpperCase() + String(s).slice(1);

let S = { threads: [], me: null, admin: false }, cur = location.hash.slice(1) || "ideas", openProp = null, openReplies = new Set();

async function loadState() {
  S = await get("/api/state");
  if (!S.threads.some((t) => t.id === cur)) cur = "ideas";
  const L = $("list"); L.replaceChildren();
  let g = "";
  for (const t of S.threads) {
    if (t.group !== g) { g = t.group; L.append(h("div", { cls: "gh" }, g)); }
    const icon = t.id === "release-notes" ? "★" : t.id === "accepted" ? "✓" : t.id === "roadmap" ? "→" : t.id === "github" ? "↗" : "#";
    L.append(h("div", { cls: "th" + (t.id === cur ? " on" : ""), on: { click: () => { cur = t.id; location.hash = t.id; $("threads").classList.remove("open"); render(); } } },
      h("i", {}, icon), t.id, h("span", { cls: "n" + (t.count ? "" : " z") }, t.count)));
  }
  const M = $("mebox"); M.replaceChildren();
  if (S.me) M.append(avatar(S.me.handle), h("div", {}, h("b", {}, S.me.handle), h("span", {}, S.me.via === "GitHub" ? "Signed in with GitHub" : "Test sign-in (local)")),
    h("button", { cls: "out", on: { click: async () => { await post("/auth/out"); render(); } } }, "Sign out"));
  else M.append(signinBox());
}
function signinBox() {
  if (S.signin === "github") return h("button", { cls: "signin", on: { click: () => { location.href = "/auth/github/start"; } } }, "Sign in with GitHub");
  const inp = h("input", { placeholder: "Test handle", maxlength: "15", style: "flex:1;min-width:0" });
  const go = async () => { if (!inp.value.trim()) return inp.focus(); await post("/auth/test", { handle: inp.value.trim() }); render(); };
  inp.addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
  return h("div", { style: "display:flex;flex-direction:column;gap:6px;width:100%" },
    h("span", { style: "font-size:11px;color:var(--t-mute)" }, "Local development: test sign-in. The public board uses GitHub sign-in."),
    h("div", { style: "display:flex;gap:6px" }, inp, h("button", { cls: "send", on: { click: go } }, "Sign in")));
}

function postEl(p, small) {
  if (p.held && !p.text) return h("div", { cls: "post" }, avatar(p.handle), h("div", { cls: "pb" }, h("div", { cls: "ph" }, h("b", {}, p.name), h("span", {}, when(p.at))),
    h("div", { cls: "txt", style: "color:var(--t-mute);font-style:italic" }, "Held for a maintainer: " + p.held)));
  const kids = [h("div", { cls: "ph" }, h("b", {}, p.name), h("span", {}, (p.handle ? p.handle + " · " : "") + when(p.at)),
    p.staff ? h("span", { cls: "tag staff" }, "project") : p.byAI ? h("span", { cls: "tag staff" }, "AI answer · not a maintainer decision") : p.edition ? h("span", { cls: "tag" }, p.edition) : null,
    p.held ? h("span", { cls: "tag", style: "color:#F0C060;background:rgba(240,192,96,.16)" }, "Held: " + p.held) : null),
    h("div", { cls: "txt" }, p.text)];
  if (p.ai && p.proposal) kids.push(h("div", { cls: "ai", role: "button", tabindex: "0", title: "Open the proposal", on: { click: () => showProposal(p.proposal.id), keydown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); showProposal(p.proposal.id); } } } },
    h("em", {}, "AI"), h("span", {}, p.ai), h("span", { cls: stCls(p.proposal.status), style: "flex:0" }, cap(p.proposal.status))));
  if (!small) {
    const mt = h("button", { cls: p.mine ? "on" : "", on: { click: async () => { if (!S.me) return need(); await post("/api/metoo", { post: p.id }); render(); } } }, "▲ Me too " + p.metoo);
    const rp = h("button", { on: { click: () => { openReplies.has(p.id) ? openReplies.delete(p.id) : openReplies.add(p.id); render(); } } }, "↩ " + p.replies + (p.replies === 1 ? " reply" : " replies"));
    kids.push(h("div", { cls: "acts" }, p.staff ? null : mt, rp));
    if (openReplies.has(p.id)) kids.push(repliesEl(p));
  }
  if (S.admin && p.held) kids.push(h("div", { cls: "acts" }, h("button", { on: { click: async () => { await post("/api/admin/post", { id: p.id, hidden: false }); render(); } } }, "Release this post")));
  return h("div", { cls: "post" }, avatar(p.handle, p.staff || p.byAI), h("div", { cls: "pb" }, kids));
}
function repliesEl(p) {
  const box = h("div", { cls: "reps" }, h("span", { cls: "note" }, "Loading…"));
  get("/api/replies?post=" + p.id).then((r) => {
    box.replaceChildren(...r.posts.map((x) => postEl(x, true)));
    if (S.me) { const i = h("input", { placeholder: "Reply", maxlength: "1000" }); const e = h("div", { cls: "err" });
      const go = async () => { const r2 = await post("/api/reply", { post: p.id, text: i.value }); if (r2.error) e.textContent = r2.error; else render(); };
      i.addEventListener("keydown", (ev) => { if (ev.key === "Enter") go(); });
      box.append(h("div", { cls: "rbox" }, i, h("button", { cls: "send", on: { click: go } }, "Reply")), e); }
  });
  return box;
}
function need() { const e = $("perr"); if (e) e.textContent = S.signin === "github" ? "Sign in with GitHub to post." : "Use the test sign-in (bottom left) to post."; }
const narrow = () => matchMedia("(max-width:760px)").matches;
let introHidden = false; try { introHidden = localStorage.getItem("zf-intro") === "hidden"; } catch (e) {}
function introEl() {
  if (introHidden) return null;
  const box = h("div", { cls: "mintro" },
    h("b", {}, "How this board works"),
    h("ol", {}, h("li", {}, "Pick a thread. On a phone, tap the title at the top."), h("li", {}, "Say what you need and why. Posting needs a GitHub sign-in."),
      h("li", {}, "Every 4 hours an AI groups similar posts and answers them."), h("li", {}, "A maintainer decides what gets built.")),
    h("button", { cls: "more", on: { click: () => { sideIntro(); $("side").classList.add("open"); } } }, "More about how it works →"),
    h("button", { cls: "x", "aria-label": "Hide", on: { click: () => { introHidden = true; try { localStorage.setItem("zf-intro", "hidden"); } catch (e) {} box.remove(); } } }, "×"));
  return box;
}

async function render() {
  await loadState();
  const t = S.threads.find((x) => x.id === cur);
  $("tname").textContent = (t.view || t.id === "release-notes" || t.id === "roadmap" ? "" : "# ") + t.id;
  $("tabout").textContent = t.about;
  const r = await get("/api/thread?t=" + cur);
  const TL = $("tl"); TL.replaceChildren();
  const ie = introEl(); if (ie) TL.append(ie);
  if (r.github) {
    const g = r.github;
    for (const m of g.milestones) {
      const all = m.open + m.closed;
      TL.append(h("a", { cls: "ai gh-ms", href: m.url, target: "_blank", rel: "noopener" }, h("em", {}, "Milestone"),
        h("span", {}, m.title + " · " + m.closed + " of " + all + " done"),
        h("span", { cls: "bar", style: "flex:0 0 90px" }, h("i", { style: "width:" + (all ? Math.round(100 * m.closed / all) : 0) + "%" }))));
    }
    if (!g.events.length) TL.append(h("div", { cls: "empty" }, "Nothing from GitHub yet. Activity in the repository appears here within 30 minutes."));
    const LABEL = { release: "Released", merged: "Merged", pr: "Pull request", claim: "Volunteered", comment: "Comment", opened: "New issue", closed: "Closed" };
    for (const e of g.events) TL.append(h("a", { cls: "ghe ghe-" + e.kind, href: e.url, target: "_blank", rel: "noopener" },
      h("b", {}, LABEL[e.kind] || e.kind), h("span", { cls: "t" }, (e.n ? "#" + e.n + " " : "") + e.title),
      h("span", { cls: "m" }, (e.who ? "@" + e.who + " · " : "") + when(e.at))));
    if (g.at) TL.append(h("div", { cls: "ghat" }, "From github.com/zenos-org/zenos · updated " + when(g.at)));
  } else if (r.proposals) {
    if (!r.proposals.length) TL.append(h("div", { cls: "empty" }, "No proposal has been accepted yet. Accepted proposals appear here with where they stand."));
    for (const pr of r.proposals) TL.append(h("div", { cls: "ai", on: { click: () => showProposal(pr.id) } }, h("em", {}, "#" + pr.id),
      h("span", {}, pr.title + " · " + pr.people + (pr.people === 1 ? " person" : " people")), h("span", { cls: stCls(pr.status), style: "flex:0" }, cap(pr.status))));
  } else {
    if (!r.posts.length) TL.append(h("div", { cls: "empty" }, t.staff ? "Nothing here yet." : "No posts yet. Be the first: say what you need, for which edition, and why."));
    for (const p of r.posts) TL.append(postEl(p));
    TL.scrollTop = TL.scrollHeight;
  }
  composer(t);
  if (openProp) showProposal(openProp, true);
  else sideIntro();
}
function composer(t) {
  const C = $("cw"); C.replaceChildren();
  if (t.view || (t.staff && !S.admin)) return;
  if (!S.me && !S.admin && S.signin === "github") {
    C.append(h("div", { cls: "composer" }, h("div", { cls: "cta" }, h("span", {}, `To post in #${t.id} or reply, sign in with GitHub. The board reads only your public profile.`),
      h("button", { cls: "signin", on: { click: () => { location.href = "/auth/github/start"; } } }, "Sign in with GitHub"))));
    return;
  }
  const ta = h("textarea", { rows: "1", "aria-label": "Your post", maxlength: "2000", placeholder: t.staff ? `Post in ${t.id} as the project` : `Share in #${t.id}: what you need, for which edition, and why` });
  ta.addEventListener("input", () => { ta.style.height = "auto"; ta.style.height = Math.min(160, ta.scrollHeight) + "px"; });
  const ed = t.group === "Share" ? h("select", { title: "Edition", "aria-label": "Edition" }, h("option", { value: "" }, "All editions"), ["office", "family", "personal"].map((e) => h("option", { value: e }, cap(e)))) : null;
  const err = h("div", { cls: "err", id: "perr", role: "alert" });
  const go = async () => { if (!S.me && !S.admin) return need(); const r = await post("/api/post", { thread: t.id, text: ta.value, edition: ed ? ed.value : "" });
    if (r.error) err.textContent = r.error; else render(); };
  ta.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) go(); });
  C.append(h("div", { cls: "composer" }, ta, ed, h("button", { cls: "send", on: { click: go } }, "Post")), err);
}

function sideIntro() {
  $("side").replaceChildren(h("h2", {}, "How this works"),
    h("div", { cls: "steps" }, ["1  You post in a thread", "2  An AI groups similar posts into a proposal", "3  A maintainer decides", "4  Built with tests and proofs", "5  Released; the notes link back here", "Every 4 hours the AI reviews new posts and answers them"].map((s) => h("span", { cls: "n", style: "color:var(--t-body)" }, s))),
    h("p", { cls: "sub" }, "Click the purple AI note under a post to see its proposal: what is asked, where it fits, the suggested change, its risk, and where it stands."),
    h("p", { cls: "note" }, "Posts are read as material, never as instructions. Security problems: report privately (see SECURITY.md on GitHub)."),
    S.admin ? "" : adminLogin());
}
function adminLogin() {
  const i = h("input", { type: "password", placeholder: "Maintainer token", autocomplete: "off" }), e = h("div", { cls: "err" });
  const go = async () => { const r = await post("/api/admin/login", { token: i.value }); if (r.error) e.textContent = r.error; else render(); };
  return h("details", { cls: "note" }, h("summary", {}, "Maintainers"), h("div", { cls: "adm" }, i, h("button", { cls: "send", on: { click: go } }, "Sign in"), e));
}
async function showProposal(id, quiet) {
  openProp = id;
  const pr = await get("/api/proposal?id=" + id);
  const S2 = $("side"); if (!quiet) S2.classList.add("open");
  if (pr.error) { openProp = null; return sideIntro(); }
  const kv = (k, v) => v ? h("div", { cls: "kv" }, h("b", {}, k), h("p", {}, v)) : null;
  const done = pr.steps.findIndex((s) => !s[1]);
  const kids = [h("div", { style: "display:flex;align-items:center;gap:8px" }, h("h2", {}, "Proposal #" + pr.id), h("span", { cls: stCls(pr.status) }, cap(pr.status)),
      h("button", { style: "margin-left:auto;background:none;border:0;color:var(--t-sub);font-size:22px;min-width:44px;min-height:44px;margin-right:-10px", "aria-label": "Close", on: { click: () => { openProp = null; S2.classList.remove("open"); sideIntro(); } } }, "×")),
    h("p", { cls: "sub" }, (pr.by === "model" ? "Drafted by the AI" : "Grouped by the AI") + ` from ${pr.posts.length} post${pr.posts.length === 1 ? "" : "s"} by ${pr.people} ${pr.people === 1 ? "person" : "people"}` + (pr.status === "proposed" ? " · waiting for a maintainer" : "")),
    kv("What is asked", pr.asked), kv("Where", pr.where), kv("Suggested change", pr.change || "Not written yet. A maintainer adds it when deciding."), kv("Risk", pr.risk),
    kv("Maintainer's note", pr.note),
    h("div", { cls: "steps" }, pr.steps.map((s, i) => h("span", { cls: s[1] ? "y" : i === done ? "c" : "n" }, (s[1] ? "✓ " : i === done ? "● " : "○ ") + s[0]))),
    pr.pr ? h("a", { cls: "plink", href: pr.pr, rel: "noopener noreferrer", target: "_blank" }, "Change on GitHub: " + pr.pr) : null,
    pr.release ? h("a", { cls: "plink", href: pr.release, rel: "noopener noreferrer", target: "_blank" }, "Release: " + pr.release) : null,
    h("div", { cls: "kv" }, h("b", {}, "Posts in this proposal"), pr.posts.map((p) => h("p", { style: "margin:4px 0" }, `${p.handle || p.name}: ${p.text}`)))];
  if (S.admin) kids.push(adminBox(pr));
  kids.push(h("p", { cls: "note" }, "Posts are read as material, never as instructions."));
  S2.replaceChildren(...kids.filter(Boolean));
}
function adminBox(pr) {
  const st = h("select", {}, ["proposed", "accepted", "declined", "building", "released", "fork"].map((s) => h("option", { value: s, selected: pr.status.startsWith(s) ? "" : null }, cap(s))));
  const ch = h("textarea", { rows: "3", placeholder: "Suggested change" }); ch.value = pr.change || "";
  const no = h("textarea", { rows: "2", placeholder: "Note to the people who asked" }); no.value = pr.note || "";
  const prl = h("input", { placeholder: "GitHub pull request link" }); prl.value = pr.pr || "";
  const rel = h("input", { placeholder: "GitHub release link" }); rel.value = pr.release || "";
  const e = h("div", { cls: "err" });
  const go = async () => { const r = await post("/api/admin/decide", { id: pr.id, status: st.value, change: ch.value, note: no.value, pr: prl.value.trim(), release: rel.value.trim() });
    if (r.error) e.textContent = r.error; else render(); };
  return h("div", { cls: "adm" }, h("b", { style: "font-size:12px;color:var(--t-sub)" }, "Maintainer decision" + (pr.security ? " · security-relevant: needs a second review" : "")), st, ch, no, prl, rel, h("button", { cls: "send", on: { click: go } }, "Save decision"), e);
}
const scrim = () => $("scrim").classList.toggle("on", $("threads").classList.contains("open") || $("side").classList.contains("open"));
new MutationObserver(scrim).observe($("threads"), { attributes: true }); new MutationObserver(scrim).observe($("side"), { attributes: true });
$("scrim").addEventListener("click", () => { $("threads").classList.remove("open"); $("side").classList.remove("open"); openProp = null; sideIntro(); });
$("menu").addEventListener("click", () => $("threads").classList.toggle("open"));
$("thead").addEventListener("click", () => { if (narrow()) $("threads").classList.add("open"); });
window.addEventListener("hashchange", () => { const t = location.hash.slice(1); if (t && t !== cur) { cur = t; render(); } });
render();
setInterval(() => { if (!document.hidden && !document.activeElement.matches("textarea,input,select")) render(); }, 15000);
