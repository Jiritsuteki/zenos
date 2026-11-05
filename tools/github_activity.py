#!/usr/bin/env python3
"""The repository's recent activity as one JSON file, for the feedback board's 'github' thread.

Run by .github/workflows/activity.yml with the workflow's own GITHUB_TOKEN (no other key), and published on the
`activity` branch; the board reads it from raw.githubusercontent.com. (The board cannot ask the GitHub API itself:
the API's limit for requests without a key is shared by every Cloudflare server on the same address.)
  github_activity.py OUT.json"""
import json, os, re, sys, time, urllib.request
from datetime import datetime

REPO = os.environ.get("GITHUB_REPOSITORY", "zenos-org/zenos")
TOKEN = os.environ.get("GITHUB_TOKEN", "")
# Comments by the project's own accounts are left out (their work already shows as issues and merges); a comment
# that offers to take an issue is marked as a volunteer, so a reader sees who is working on what.
TEAM = {"OWNER", "MEMBER", "COLLABORATOR"}
# The workflow's own key does not see private organization membership, so the project's account is also named.
TEAM_LOGINS = {"zenos-maintainer"}
CLAIM = re.compile(r"\b(work on (this|it)|(i('|\u2019)?ll take|i will take|let me take|taking) (this|it)|pick (this|it) up|assign (this|it|me)|i('|\u2019)?d like to (work|help|contribute|take|do)|i would like to (work|help|contribute|take|do)|can i (work|take|help|do)|i want to (work|take|do)|(gonna|going to) (start|work|do|take))\b", re.I)


def get(path):
    h = {"Accept": "application/vnd.github+json", "User-Agent": "zenos-activity"}
    if TOKEN:
        h["Authorization"] = "Bearer " + TOKEN
    with urllib.request.urlopen(urllib.request.Request(f"https://api.github.com/repos/{REPO}{path}", headers=h), timeout=30) as r:
        return json.load(r)


def ms(t):
    return int(datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ").timestamp() * 1000) if t else 0


def cut(t):
    return str(t or "")[:200]


def main():
    ev = []
    for r in get("/releases?per_page=5"):
        if not r.get("draft"):
            ev.append({"kind": "release", "title": cut(r.get("name") or r.get("tag_name")), "url": r["html_url"], "at": ms(r.get("published_at")), "who": ""})
    for p in get("/pulls?state=closed&sort=updated&direction=desc&per_page=20"):
        if p.get("merged_at"):
            ev.append({"kind": "merged", "n": p["number"], "title": cut(p["title"]), "url": p["html_url"], "at": ms(p["merged_at"]), "who": cut((p.get("user") or {}).get("login"))})
    for p in get("/pulls?state=all&sort=created&direction=desc&per_page=20"):
        ev.append({"kind": "pr", "n": p["number"], "title": cut(p["title"]), "url": p["html_url"], "at": ms(p["created_at"]), "who": cut((p.get("user") or {}).get("login"))})
    titles = {}
    for c in get("/issues/comments?sort=created&direction=desc&per_page=40"):
        u = c.get("user") or {}
        if u.get("type") != "User" or c.get("author_association") in TEAM or u.get("login") in TEAM_LOGINS:
            continue
        n = int(str(c.get("issue_url", "")).rsplit("/", 1)[-1] or 0)
        if n not in titles:
            i = get(f"/issues/{n}")
            titles[n] = (i.get("title", ""), bool(i.get("pull_request")))
        # Only who and where are shown, never the comment's text: the board does not republish what others wrote.
        title, is_pr = titles[n]
        kind = "claim" if not is_pr and CLAIM.search(c.get("body") or "") else "comment"
        ev.append({"kind": kind, "n": n, "title": cut(title), "url": c["html_url"], "at": ms(c.get("created_at")), "who": cut(u.get("login"))})
    for i in get("/issues?state=all&sort=updated&direction=desc&per_page=40"):
        if i.get("pull_request"):
            continue
        ev.append({"kind": "opened", "n": i["number"], "title": cut(i["title"]), "url": i["html_url"], "at": ms(i["created_at"]), "who": cut((i.get("user") or {}).get("login"))})
        if i.get("closed_at"):
            ev.append({"kind": "closed", "n": i["number"], "title": cut(i["title"]), "url": i["html_url"], "at": ms(i["closed_at"]), "who": ""})
    ev.sort(key=lambda e: -e["at"])
    mss = [{"title": cut(m["title"]), "open": m["open_issues"], "closed": m["closed_issues"], "url": m["html_url"]}
           for m in get("/milestones?state=open&sort=due_on")]
    out = {"events": ev[:60], "milestones": mss, "at": int(time.time() * 1000)}
    with open(sys.argv[1], "w") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
