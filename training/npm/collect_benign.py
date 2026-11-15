"""
Benign npm packages for training: their latest tarball and their registry document as it is now, in three groups like
the PyPI training data.

    python3 collect_benign.py --out DIR [--top 1500] [--longtail 1500] [--new 1500] [--exclude-manifests ...]
                              [--datadog-manifest <clone>/samples/npm/manifest.json]
    python3 collect_benign.py --out DIR --recheck        # drop packages reported malicious since they were collected

  top       popular packages: registry search by popularity over many search words, ranked by last month's downloads
  longtail  ordinary packages: registry search for random words, 1 to 1,000 downloads last month
  new       packages created in the last 30 days (registry search for random words, kept when `time.created` is
            recent). These are the hardest benign cases, as for PyPI: new and small, like most malicious packages.

Left out: names in the DataDog manifest or with an OSV MAL- record, npm's security placeholders (0.0.1-security),
benchmark names (--exclude-manifests), deprecated versions, tarballs over 30MB.
Each package: DIR/<group>/<name>@<version>.tgz and .json ({name, version, group, collected_at, packument: time,
maintainers}). Nothing is run or installed; tarballs are only stored.
The npm registry has no list of new packages: the search below finds a sample of them. If a better source is reachable
(the replication feed), --new-names FILE takes a list of names instead.
"""
import argparse
import json
import random
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from common import excluded_names, iso, now_utc, parse_t, trim_packument

REG = "https://registry.npmjs.org"
UA = {"User-Agent": "aegis-npm-ml-training (research)"}
MAX_DOC = 64 << 20
MAX_TGZ = 30 << 20
SEED = 20261115
WORDS = ("util array string date time json http server client config parse format color log logger cli test mock "
         "react vue angular svelte node express router api auth token crypto hash file path stream buffer image "
         "pdf csv xml yaml markdown html css sass webpack babel eslint plugin loader react-native graphql sql mongo "
         "redis cache queue event emitter promise async retry debounce throttle math random uuid id validate schema "
         "form input button modal table chart map geo i18n locale email sms slack discord bot ai openai llm vector "
         "embed search index sort merge diff deep clone copy object type typescript types tool kit helper sdk "
         "wrapper adapter driver socket websocket proxy dns net ssh git github docker aws cloud storage s3 upload "
         "download compress zip tar gzip encode decode base64 binary bit byte color theme icon font svg canvas "
         "animation game audio video stream player music midi serial usb bluetooth iot mqtt blockchain web3 ethers "
         "wallet solana nft payment stripe shop cart store state redux mobx hook context component ui design system "
         "layout grid flex responsive mobile native electron desktop terminal shell command process env dotenv "
         "secret password otp captcha security lint prettier format style commit release version semver changelog "
         "monorepo workspace build bundle rollup vite esbuild swc jest mocha chai cypress playwright puppeteer "
         "scrape crawl spider rss feed news weather time zone calendar cron schedule job worker thread cluster").split()


def _get(url, limit=MAX_DOC, timeout=30, accept="application/json"):
    req = urllib.request.Request(url, headers={**UA, "Accept": accept})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(limit + 1)
    if len(data) > limit:
        raise ValueError("too large")
    return data


def search(text, size=250, frm=0, popularity=1.0):
    q = urllib.parse.urlencode({"text": text, "size": size, "from": frm, "popularity": popularity,
                                "quality": 0.0 if popularity else 0.5, "maintenance": 0.0 if popularity else 0.5})
    try:
        return json.loads(_get(f"{REG}/-/v1/search?{q}")).get("objects", [])
    except Exception as e:
        print("  search failed:", text, e, file=sys.stderr)
        return []


def downloads(names):
    """Last month's downloads (the bulk endpoint takes up to 128 unscoped names; scoped ones one by one)."""
    out = {}
    plain = [n for n in names if not n.startswith("@")]
    for i in range(0, len(plain), 128):
        chunk = plain[i:i + 128]
        try:
            d = json.loads(_get("https://api.npmjs.org/downloads/point/last-month/" + ",".join(chunk)))
            for n in chunk:
                v = d.get(n) if len(chunk) > 1 else d
                out[n] = (v or {}).get("downloads", 0) if isinstance(v, dict) else 0
        except Exception as e:
            print("  downloads failed:", e, file=sys.stderr)
        time.sleep(0.3)
    for n in names:
        if n.startswith("@"):
            try:
                out[n] = json.loads(_get("https://api.npmjs.org/downloads/point/last-month/" + n)).get("downloads", 0)
            except Exception:
                out[n] = 0
    return out


def osv_malicious(names):
    """Names with an OSV MAL- record (any version)."""
    bad = set()
    for i in range(0, len(names), 500):
        chunk = names[i:i + 500]
        body = json.dumps({"queries": [{"package": {"name": n, "ecosystem": "npm"}} for n in chunk]}).encode()
        try:
            req = urllib.request.Request("https://api.osv.dev/v1/querybatch", data=body,
                                         headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=60) as resp:
                res = json.loads(resp.read()).get("results", [])
        except Exception as e:
            print("  OSV failed:", e, file=sys.stderr)
            continue
        for n, r in zip(chunk, res):
            if any(str(v.get("id", "")).startswith("MAL-") for v in (r or {}).get("vulns", [])):
                bad.add(n)
    return bad


def candidates_top(n, rnd):
    names = {}
    for w in WORDS:
        for o in search(w, 250, 0, 1.0):
            names[o["package"]["name"]] = 1
        time.sleep(0.2)
    dl = downloads(sorted(names))
    ranked = sorted(dl, key=lambda k: -dl[k])
    return ranked[: n * 2]


def candidates_random(n, rnd, low=1, high=1000, new_days=None):
    """Random-word searches with little weight on popularity; kept by downloads (longtail) or creation date (new)."""
    seen, out = set(), []
    words = list(WORDS)
    rnd.shuffle(words)
    for w in words * 3:
        frm = rnd.randrange(0, 1000, 250)
        objs = search(w, 250, frm, 0.0)
        for o in objs:
            p = o["package"]
            if p["name"] in seen:
                continue
            seen.add(p["name"])
            if new_days is not None:
                d = parse_t(p.get("date"))
                if d is None or (now_utc() - d).days > new_days:
                    continue
            out.append(p["name"])
        if len(out) >= n * 3:
            break
        time.sleep(0.2)
    if new_days is None:
        dl = downloads(out)
        out = [k for k in out if low <= dl.get(k, 0) <= high]
    return out


def fetch_one(name, group, out_dir, new_days=None):
    try:
        doc = json.loads(_get(f"{REG}/{urllib.parse.quote(name, safe='@')}"))
        ver = (doc.get("dist-tags") or {}).get("latest")
        v = (doc.get("versions") or {}).get(ver) or {}
        if not ver or ver.endswith("-security") or v.get("deprecated"):
            return None
        t = doc.get("time") or {}
        if new_days is not None:
            created = parse_t(t.get("created"))
            if created is None or (now_utc() - created).days > new_days:
                return None
        url = (v.get("dist") or {}).get("tarball", "")
        if not url.startswith(REG + "/"):
            return None
        tgz = _get(url, MAX_TGZ, 120, "application/octet-stream")
        base = out_dir / group / f"{name.replace('/', '__')}@{ver}"
        base.parent.mkdir(parents=True, exist_ok=True)
        Path(str(base) + ".tgz").write_bytes(tgz)
        side = {"name": name, "version": ver, "group": group, "collected_at": iso(now_utc()),
                "packument": trim_packument(doc)}
        Path(str(base) + ".json").write_text(json.dumps(side))
        return name
    except Exception as e:
        print("  fetch failed:", name, type(e).__name__, str(e)[:80], file=sys.stderr)
        return None


def collect(group, names, want, out_dir, bad, new_days=None, workers=8):
    names = [n for n in names if n.lower() not in bad]
    got = []
    with ThreadPoolExecutor(workers) as pool:
        for i in range(0, len(names), workers * 4):
            if len(got) >= want:
                break
            for r in pool.map(lambda n: fetch_one(n, group, out_dir, new_days), names[i:i + workers * 4]):
                if r:
                    got.append(r)
    print(f"{group}: {len(got)} collected (of {len(names)} candidates)")
    return got


def recheck(out_dir, dd_manifest):
    bad = set(json.loads(Path(dd_manifest).read_text())) if dd_manifest else set()
    sides = list(Path(out_dir).glob("*/*.json"))
    names = [json.loads(p.read_text())["name"] for p in sides]
    bad |= osv_malicious(names)
    dropped = 0
    for p, n in zip(sides, names):
        if n in bad:
            gone = Path(str(p)[:-5] + ".dropped")
            gone.mkdir(exist_ok=True)
            p.rename(gone / p.name)
            Path(str(p)[:-5] + ".tgz").rename(gone / (p.stem + ".tgz"))
            dropped += 1
    print(f"recheck: {dropped} of {len(names)} dropped (reported malicious since collection)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--top", type=int, default=1500)
    ap.add_argument("--longtail", type=int, default=1500)
    ap.add_argument("--new", type=int, default=1500)
    ap.add_argument("--new-names", default=None, help="a file of npm names created recently (instead of the search)")
    ap.add_argument("--exclude-manifests", nargs="*", default=[])
    ap.add_argument("--exclude-dirs", nargs="*", default=[], help="earlier collections whose names stay out")
    ap.add_argument("--datadog-manifest", default=None)
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--recheck", action="store_true")
    a = ap.parse_args()
    out_dir = Path(a.out)
    if a.recheck:
        return recheck(out_dir, a.datadog_manifest)
    rnd = random.Random(a.seed)
    bad = excluded_names(a.exclude_manifests)
    if a.datadog_manifest:
        bad |= {n.lower() for n in json.loads(Path(a.datadog_manifest).read_text())}
    for d in a.exclude_dirs:
        bad |= {json.loads(p.read_text())["name"].lower() for p in Path(d).glob("*/*.json")}
    if a.top:
        names = candidates_top(a.top, rnd)
        collect("top", names, a.top, out_dir, bad | osv_malicious(names))
    if a.longtail:
        names = candidates_random(a.longtail, rnd)
        collect("longtail", names, a.longtail, out_dir, bad | osv_malicious(names))
    if a.new:
        names = Path(a.new_names).read_text().split() if a.new_names else candidates_random(a.new, rnd, new_days=30)
        collect("new", names, a.new, out_dir, bad | osv_malicious(names), new_days=30)


if __name__ == "__main__":
    main()
