"""ZENOS Images · Library and Studio: music and pictures on this PC, audio trimming, a picture on the audio, and
(optionally) motion made by an AI the person registered themselves.

Rules:
- Only plain files are listed (Basic · L1 on the desktop, ~/Music, ~/Pictures, ~/Videos). Sealed files (.zen) of the
  higher levels never appear here.
- Audio and video are written next to the source or into ~/Videos/ZENOS Studio; originals are never overwritten.
- Motion with AI: only for an L1 picture, only when /etc/zenos/policy.conf does not say "studio_ai = off", and only to
  the endpoint and key the person entered. ZENOS ships no video model and keeps no key on disk.
"""
import base64
import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request

HOME = os.path.expanduser("~")
AUDIO = (".mp3", ".m4a", ".aac", ".wav", ".flac", ".ogg", ".oga", ".opus")
IMAGES = (".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif", ".avif", ".tif", ".tiff")
VIDEO = (".mp4", ".m4v", ".mov", ".webm", ".mkv")
META = os.path.join(HOME, ".config/zenos/studio.json")
OUT = os.path.join(HOME, "Videos", "ZENOS Studio")
POLICY = "/etc/zenos/policy.conf"


def folder_level(p):
    import sys
    for lib in ("/usr/lib/zenos", "/usr/local/lib/zenos",
                os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "system", "lib")):
        if os.path.isdir(lib) and lib not in sys.path:
            sys.path.append(lib)
    import zformat
    return zformat.desk_level(p, os.path.join(HOME, "Desktop"))


def _roots():
    roots = []
    desk = os.path.join(HOME, "Desktop")
    if os.path.isdir(desk):
        for n in sorted(os.listdir(desk)):
            if " · L1" in n and os.path.isdir(os.path.join(desk, n)):
                roots.append(os.path.join(desk, n))
    for n in ("Music", "Pictures", "Videos"):
        p = os.path.join(HOME, n)
        if os.path.isdir(p):
            roots.append(p)
    return roots


def _info(p, kind):
    try:
        st = os.stat(p)
    except OSError:
        return None
    return {"path": p, "url": "file://" + urllib.request.pathname2url(p), "name": os.path.basename(p),
            "size": st.st_size, "mtime": int(st.st_mtime), "dir": os.path.dirname(p), "level": folder_level(p), "kind": kind}


def library(limit=5000):
    """every plain audio, picture and video file in the L1 places, newest first"""
    out = {"audio": [], "images": [], "videos": []}
    seen = set()
    n = 0
    for root in _roots():
        for d, dirs, files in os.walk(root):
            if d[len(root):].count(os.sep) >= 4:
                dirs[:] = []
            dirs[:] = [x for x in dirs if not x.startswith(".")]
            if folder_level(d) > 1:        # never list anything from a higher-level folder
                dirs[:] = []
                continue
            for f in files:
                low = f.lower()
                kind = "audio" if low.endswith(AUDIO) else "images" if low.endswith(IMAGES) else "videos" if low.endswith(VIDEO) else None
                p = os.path.join(d, f)
                if not kind or p in seen or f.startswith("."):
                    continue
                seen.add(p)
                i = _info(p, kind)
                if i:
                    out[kind].append(i)
                    n += 1
                if n >= limit:
                    break
    for k in out:
        out[k].sort(key=lambda x: -x["mtime"])
    return out


def meta_load():
    try:
        with open(META) as f:
            m = json.load(f)
    except Exception:
        m = {}
    for k, v in (("playlists", []), ("albums", []), ("pairs", {}), ("projects", [])):
        m.setdefault(k, v)
    return m


def meta_save(m):
    os.makedirs(os.path.dirname(META), exist_ok=True)
    with open(META + ".tmp", "w") as f:
        json.dump(m, f, ensure_ascii=False, indent=1)
    os.replace(META + ".tmp", META)
    return True


def _ffmpeg():
    exe = shutil.which("ffmpeg")
    if not exe:
        raise RuntimeError("ffmpeg is not installed on this PC.")
    return exe


def _plain(p):
    """a path the studio may read: an existing plain file in an L1 place"""
    if not p or not os.path.isfile(p):
        raise ValueError("The file is not there any more.")
    if p.lower().endswith(".zen") or "/dev/shm/" in p:
        raise ValueError("Sealed files cannot be used in the Studio.")
    if folder_level(p) > 1:
        raise ValueError("Only L1 files can be used in the Studio.")
    return p


def peaks(path, n=600):
    """the loudness outline of an audio file (n buckets, 0..1) and its length in seconds"""
    _plain(path)
    rate = 4000
    r = subprocess.run([_ffmpeg(), "-v", "error", "-i", path, "-ac", "1", "-ar", str(rate), "-f", "s16le", "-"],
                       capture_output=True, timeout=300)
    if r.returncode != 0:
        raise RuntimeError("This audio file could not be read.")
    import array
    a = array.array("h")
    a.frombytes(r.stdout[: len(r.stdout) // 2 * 2])
    total = len(a)
    if not total:
        return {"peaks": [0] * n, "duration": 0}
    step = max(1, total // n)
    out = []
    for i in range(0, total, step):
        chunk = a[i:i + step]
        out.append(max(abs(min(chunk)), abs(max(chunk))) / 32768.0)
    top = max(out) or 1
    return {"peaks": [round(x / top, 3) for x in out[:n]], "duration": total / rate}


def _fades(start, end, fin, fout):
    dur = max(0.0, end - start)
    f = []
    if fin > 0:
        f.append("afade=t=in:st=0:d=%.3f" % min(fin, dur))
    if fout > 0:
        f.append("afade=t=out:st=%.3f:d=%.3f" % (max(0.0, dur - fout), min(fout, dur)))
    return dur, ",".join(f)


def _free_name(path):
    base, ext = os.path.splitext(path)
    i = 1
    while os.path.exists(path):
        path = "%s (%d)%s" % (base, i, ext)
        i += 1
    return path


def export_audio(src, start, end, fin, fout, dest):
    _plain(src)
    if os.path.abspath(dest) == os.path.abspath(src):
        raise ValueError("Choose a new name: the original is never overwritten.")
    dur, af = _fades(float(start), float(end), float(fin), float(fout))
    if dur <= 0:
        raise ValueError("The selection is empty.")
    ext = os.path.splitext(dest)[1].lower()
    codec = {".m4a": ["-c:a", "aac", "-b:a", "192k"], ".mp3": ["-c:a", "libmp3lame", "-q:a", "2"],
             ".wav": ["-c:a", "pcm_s16le"], ".flac": ["-c:a", "flac"], ".ogg": ["-c:a", "libvorbis", "-q:a", "5"]}.get(ext)
    if not codec:
        raise ValueError("Save as .m4a, .mp3, .wav, .flac or .ogg.")
    cmd = [_ffmpeg(), "-v", "error", "-y", "-ss", "%.3f" % float(start), "-t", "%.3f" % dur, "-i", src, "-vn"]
    if af:
        cmd += ["-af", af]
    cmd += codec + [dest]
    r = subprocess.run(cmd, capture_output=True, timeout=600)
    if r.returncode != 0:
        raise RuntimeError("The audio could not be saved: " + r.stderr.decode("utf-8", "replace")[-300:])
    return _info(dest, "audio")


def export_video(audio, image, clip, start, end, fin, fout, dest):
    """the trimmed audio with the picture (or the AI clip, looped) as one MP4 (H.264 + AAC)"""
    _plain(audio)
    if clip:
        _plain(clip)
    else:
        _plain(image)
    dur, af = _fades(float(start), float(end), float(fin), float(fout))
    if dur <= 0:
        raise ValueError("The selection is empty.")
    vin = ["-stream_loop", "-1", "-i", clip] if clip else ["-loop", "1", "-framerate", "30", "-i", image]
    vf = "[0:v]scale=1920:1080:force_original_aspect_ratio=decrease,pad=1920:1080:(ow-iw)/2:(oh-ih)/2:color=black,setsar=1,fps=30,format=yuv420p[v]"
    fa = "[1:a]" + (af if af else "anull") + "[a]"
    cmd = [_ffmpeg(), "-v", "error", "-y"] + vin + ["-ss", "%.3f" % float(start), "-t", "%.3f" % dur, "-i", audio,
           "-filter_complex", vf + ";" + fa, "-map", "[v]", "-map", "[a]", "-c:v", "libx264", "-preset", "veryfast",
           "-crf", "20"] + ([] if clip else ["-tune", "stillimage"]) + ["-c:a", "aac", "-b:a", "192k", "-t", "%.3f" % dur,
           "-movflags", "+faststart", dest]
    r = subprocess.run(cmd, capture_output=True, timeout=1800)
    if r.returncode != 0:
        raise RuntimeError("The video could not be made: " + r.stderr.decode("utf-8", "replace")[-300:])
    return _info(dest, "videos")


def ai_allowed():
    try:
        with open(POLICY) as f:
            for line in f:
                k, _, v = line.partition("=")
                if k.strip() == "studio_ai" and v.strip().lower() in ("off", "no", "false", "0"):
                    return False
    except OSError:
        pass
    return True


def _local(u):
    """a test server on this PC (plain http is allowed only there)"""
    return u.startswith("http://127.0.0.1:") or u.startswith("http://localhost:")


def _post(url, key, payload, timeout=120):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "Authorization": "Bearer " + key,
                                          "Accept": "video/mp4, application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.headers.get("Content-Type", ""), r.read()


def _get(url, key, timeout=120):
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + key, "Accept": "video/mp4, application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.headers.get("Content-Type", ""), r.read()


def _video_url(j):
    for k in ("video_url", "url", "video"):
        if isinstance(j.get(k), str) and (j[k].startswith("https://") or _local(j[k])):
            return j[k]
    out = j.get("output")
    if isinstance(out, list) and out and isinstance(out[0], str) and out[0].startswith("http"):
        return out[0]
    if isinstance(out, str) and out.startswith("http"):
        return out
    return None


def ai_video(image, prompt, seconds, endpoint, key, model="", poll_every=5, give_up=900):
    """send one L1 picture and the person's words to the AI they registered; save the clip it returns.

    The endpoint gets POST {model, prompt, image (data URL), duration_seconds} with "Authorization: Bearer <key>".
    It may answer with the video itself, with {"video_url"|"url"|"output": ...}, or with {"status_url": ...} (or
    "poll_url") to be asked again until it reports a video URL. See docs/STUDIO.md."""
    if not ai_allowed():
        raise PermissionError("Motion with AI is turned off on this PC by the administrator.")
    _plain(image)
    if folder_level(image) != 1:
        raise PermissionError("Only L1 pictures can be sent to an AI.")
    if not (endpoint.startswith("https://") or _local(endpoint)):
        raise ValueError("The AI address must start with https://")
    if not key:
        raise ValueError("Enter the API key of your video AI first.")
    ext = os.path.splitext(image)[1].lower().lstrip(".")
    mime = "image/" + ("jpeg" if ext in ("jpg", "jpeg") else ext)
    with open(image, "rb") as f:
        data_url = "data:%s;base64,%s" % (mime, base64.b64encode(f.read()).decode())
    payload = {"model": model, "prompt": prompt, "image": data_url, "duration_seconds": int(seconds)}
    ctype, body = _post(endpoint, key, payload)
    t0 = time.time()
    while True:
        if ctype.startswith("video/"):
            vid = body
            break
        try:
            j = json.loads(body.decode("utf-8", "replace") or "{}")
        except ValueError:
            raise RuntimeError("The AI answered with something that is not a video.")
        if j.get("error"):
            raise RuntimeError("The AI said: %s" % (j["error"] if isinstance(j["error"], str) else json.dumps(j["error"])[:300]))
        u = _video_url(j)
        if u:
            ctype, vid = _get(u, key, timeout=300)
            if not ctype.startswith("video/") and b"ftyp" not in vid[:16]:
                raise RuntimeError("The AI's video link did not give a video.")
            break
        poll = j.get("status_url") or j.get("poll_url")
        if not poll or not (poll.startswith("https://") or _local(poll)):
            raise RuntimeError("The AI did not return a video or a status address.")
        if str(j.get("status", "")).lower() in ("failed", "error", "cancelled", "canceled"):
            raise RuntimeError("The AI could not make the video.")
        if time.time() - t0 > give_up:
            raise TimeoutError("The AI took too long. Try again later.")
        time.sleep(poll_every)
        ctype, body = _get(poll, key)
    os.makedirs(OUT, exist_ok=True)
    base = os.path.splitext(os.path.basename(image))[0]
    dest = _free_name(os.path.join(OUT, "%s — motion.mp4" % base))
    with open(dest, "wb") as f:
        f.write(vid)
    try:
        import zenos
        zenos.audit("studio-ai", file=os.path.basename(image), endpoint=endpoint.split("/")[2], seconds=int(seconds))
    except Exception:
        pass
    return _info(dest, "videos")
