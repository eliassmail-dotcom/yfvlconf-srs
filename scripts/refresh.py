#!/usr/bin/env python3
"""Validate every SRS, then publish a single complete last-known-good generation."""
import argparse, base64, hashlib, json, os, pathlib, subprocess, tempfile, urllib.parse, urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
MAX_SIZE = 4 * 1024 * 1024

def get(url, api=False):
    headers = {"User-Agent": "yfvlconf-srs-mirror"}
    if api:
        headers["Accept"] = "application/vnd.github+json"
        if os.environ.get("GITHUB_TOKEN"):
            headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=45) as res:
        data = res.read(MAX_SIZE * 2 + 1)
    if len(data) > MAX_SIZE * 2:
        raise ValueError("oversized response")
    return data

def blob_sha(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\x00" + data).hexdigest()

def verify(data, expected):
    if blob_sha(data) != expected or not 4 < len(data) <= MAX_SIZE or data[:3] != b"SRS":
        raise ValueError("wrong Git blob or invalid SRS")
    return data

def download(s):
    path = urllib.parse.quote(s["path"], safe="/")
    ref = urllib.parse.quote(s["ref"], safe="")
    api = f'https://api.github.com/repos/{s["repository"]}'
    head = json.loads(get(f"{api}/commits/{ref}", api=True))["sha"]
    meta = json.loads(get(f"{api}/contents/{path}?ref={head}", api=True))
    expected = meta["sha"]
    try:
        return verify(get(f'https://raw.githubusercontent.com/{s["repository"]}/{head}/{path}'), expected), head
    except Exception:
        blob = json.loads(get(f"{api}/git/blobs/{expected}", api=True))
        return verify(base64.b64decode(blob["content"]), expected), head

def collect(node, keys):
    if isinstance(node, dict):
        for k, v in node.items():
            if k in keys and isinstance(v, list):
                yield from v
            else:
                yield from collect(v, keys)
    elif isinstance(node, list):
        for v in node:
            yield from collect(v, keys)

def inspect(core, source, target):
    out = target.with_suffix(".json")
    subprocess.run([core, "rule-set", "decompile", str(target), "-o", str(out)], check=True, timeout=90)
    rules = json.loads(out.read_text()).get("rules", [])
    keys = {"ip_cidr"} if source["kind"] == "ip" else {"domain", "domain_suffix", "domain_keyword", "domain_regex"}
    count = len(list(collect(rules, keys)))
    if not count:
        raise ValueError("empty or wrong rule type: " + source["tag"])
    if source["tag"] == "openai-domains" and not {"openai.com", "chatgpt.com"} <= set(collect(rules, {"domain", "domain_suffix"})):
        raise ValueError("required OpenAI domains missing")
    out.unlink()
    return count

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--core", required=True)
    p.add_argument("--seed", action="store_true")
    args = p.parse_args()
    core = str(pathlib.Path(args.core).resolve())
    sources = json.loads((ROOT / "sources.json").read_text())
    seed = {s["tag"]: s for s in json.loads((ROOT / "seed-provenance.json").read_text())}
    manifest_path = ROOT / "manifest.json"
    previous = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    prior = {s["tag"]: s for s in previous.get("files", [])}
    records = []
    with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
        stage = pathlib.Path(tmp)
        for s in sources:
            tag = s["tag"]
            target = stage / (tag + ".srs")
            if args.seed:
                data = verify((ROOT / "srs" / target.name).read_bytes(), seed[tag]["git_blob"])
                revision = seed[tag]["seed_commit"]
            else:
                data, revision = download(s)
            target.write_bytes(data)
            count = inspect(core, s, target)
            if tag in prior and count < max(1, prior[tag]["entries"] // 2):
                raise ValueError("unexpected >50% decrease: " + tag)
            records.append({**s, "upstream_commit": revision, "git_blob": blob_sha(data), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "entries": count})
        # No changes to published files until every source passes; a single git commit publishes all.
        for s in sources:
            name = s["tag"] + ".srs"
            os.replace(stage / name, ROOT / "srs" / name)
        manifest_path.write_text(json.dumps({"schema": 1, "files": records}, indent=2, sort_keys=True) + "\n")
    print(f"Validated {len(records)} SRS files")

if __name__ == "__main__":
    main()
