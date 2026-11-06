"""ZENOS file format, levels and approval requests: the part both the desktop and the root services rely on.

Kept in the root-owned library so that root services never import code from the desktop program directory.
"""
import hashlib, json, os

MAGIC = b"ZENOS1\n"
FOLDERS = {"Basic · L1": (1, 1), "Green · L2-L3": (2, 3), "Red · L4": (4, 4), "Black · L5": (5, 5)}
LABEL = {1: "Public", 2: "Confidentiality 2", 3: "Confidentiality 3",
         4: "Important Economic Security Information", 5: "Specially Designated Secret"}
# approvals a level needs
REQUIRED = {1: 0, 2: 1, 3: 1, 4: 2, 5: 3}
CORE_KEYS = ("id", "kind", "requester", "file", "file_hash", "level", "reason", "created", "scope")


def request_core(r):
    return {k: r[k] for k in CORE_KEYS if k in r}


def request_digest(r):
    return hashlib.sha256(json.dumps(request_core(r), sort_keys=True, ensure_ascii=False).encode()).digest()


def desk_level(path, desk=None):
    """the level of the Desktop level folder a path is in, at any depth (1 elsewhere). Decided by the real path's
    place: a folder elsewhere that merely has a level folder's name in it ("~/x/Red · L4 copy") is not one."""
    desk = os.path.realpath(desk or os.path.join(os.path.expanduser("~"), "Desktop"))
    try:
        rel = os.path.relpath(os.path.realpath(path or "/"), desk)
    except ValueError:
        return 1
    if rel == "." or rel.startswith(".."):
        return 1
    return FOLDERS.get(rel.split(os.sep, 1)[0], (1, 1))[0]
