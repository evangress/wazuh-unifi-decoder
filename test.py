#!/usr/bin/env python3
"""Run samples/events.log through wazuh-logtest and check each "# expect:" line.

Needs a running Wazuh manager container that loads this repo (and, for rule checks,
../wazuh-unifi-rules). See "Lab testing in Docker" in CLAUDE.md.

Usage: ./test.py [--container NAME] [--no-reload] [--verbose] [samples-file]
       ./test.py --scan-archives [--days N] [--container NAME] [--verbose]

--scan-archives reads the manager's archive log (logall_json) instead of running the samples. It
lists the UniFi versions seen, CEF keys with no decoder, event types with no sample, and event
types no specific rule handles (they stop at base rule 100010). Run it after every UniFi upgrade.
"""
import argparse
import collections
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent
DECODER_FILE = REPO / "ubiquiti_decoders.xml"
BASE_RULE = "100010"
CEF_HEADER = re.compile(r"\|Ubiquiti\|([^|]*)\|([^|]*)\|(\d+)\|([^|]*)\|(\d+)\|(.*)$")


def decoded_keys():
    return set(re.findall(r"\\b([A-Za-z0-9]+)=", DECODER_FILE.read_text()))


def parse_cef(log):
    """Return (product, version, event id, event name, severity, extension keys), or None."""
    m = CEF_HEADER.search(log)
    if not m:
        return None
    product, version, eid, name, sev, ext = m.groups()
    keys = re.findall(r"(?:^|\s)([A-Za-z][A-Za-z0-9_]*)=", ext)
    return product, version, eid, name, sev, keys


def load_samples(path):
    samples, expect, comment_line = [], None, None
    for n, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.rstrip("\n")
        if line.startswith("# expect:"):
            expect = dict(kv.split("=", 1) for kv in line[len("# expect:"):].split())
            comment_line = n
        elif not line.strip() or line.startswith("#"):
            continue
        else:
            if expect is None:
                sys.exit(f"{path}:{n}: log line without a preceding '# expect:' line")
            samples.append({"line": n, "expect_line": comment_line, "log": line, "expect": expect})
            expect = None
    return samples


def undecoded_keys(samples):
    """Static check: every key=value key in a CEF extension needs a decoder."""
    known = decoded_keys()
    problems = []
    for s in samples:
        cef = parse_cef(s["log"])
        if not cef:
            continue
        for key in cef[5]:
            if key not in known:
                problems.append(f"line {s['line']}: no decoder for key '{key}'")
    return problems


def read_archives(container, days):
    """Yield archive entries for UniFi CEF events from the manager's dated archive files."""
    # Dated files only: archives.json is a hard link to today's file and would double-count it.
    cmd = ("find /var/ossec/logs/archives -type f -mtime -{days} "
           "\\( -name 'ossec-archive-*.json' -o -name 'ossec-archive-*.json.gz' \\) -print0"
           " | xargs -0 -r zcat -f | grep -F '|Ubiquiti|' || true").format(days=int(days))
    proc = subprocess.run(["docker", "exec", container, "sh", "-c", cmd],
                          capture_output=True, text=True, encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        sys.exit(f"reading archives failed: {proc.stderr.strip()}")
    for line in proc.stdout.splitlines():
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def scan_archives(args):
    known = decoded_keys()
    sampled = set()
    for s in load_samples(args.samples):
        if cef := parse_cef(s["log"]):
            sampled.add(cef[3])

    versions = collections.Counter()
    events = collections.Counter()            # (event id, name, severity) -> count
    rules_for = collections.defaultdict(collections.Counter)  # name -> Counter of (rule id, level)
    missing = collections.defaultdict(collections.Counter)    # key -> Counter of event names
    examples = {}
    total = 0
    for entry in read_archives(args.container, args.days):
        cef = parse_cef(entry.get("full_log", ""))
        if not cef:
            continue
        total += 1
        product, version, eid, name, sev, keys = cef
        versions[f"{product} {version}"] += 1
        events[(eid, name, sev)] += 1
        rule = entry.get("rule") or {}
        rules_for[name][(rule.get("id", "none"), rule.get("level", "-"))] += 1
        for key in keys:
            if key not in known:
                missing[key][name] += 1
                examples.setdefault(key, entry["full_log"])

    print(f"Scanned {total} UniFi CEF events from the last {args.days} day(s) in {args.container}.")
    if not total:
        print("Nothing to report. Is the controller sending SIEM syslog here, and is logall_json on?")
        return 0
    print("\nUniFi versions:")
    for v, n in versions.most_common():
        print(f"  {n:6}  {v}")

    print("\nEvent types:")
    unsampled, unhandled = [], []
    for (eid, name, sev), n in sorted(events.items(), key=lambda kv: -kv[1]):
        rules = ", ".join(f"{r}/L{lvl}" for (r, lvl), _ in rules_for[name].most_common())
        flags = []
        if name not in sampled:
            flags.append("NO SAMPLE")
            unsampled.append(name)
        if set(r for r, _ in rules_for[name]) <= {BASE_RULE, "none"}:
            flags.append("base rule only")
            unhandled.append(name)
        print(f"  {n:6}  {eid:>4} {name} (sev {sev})  rule {rules}" + (f"  [{', '.join(flags)}]" if flags else ""))

    print("\nCEF keys with no decoder:" + ("" if missing else " none"))
    for key, names in sorted(missing.items()):
        print(f"  {key}  ({sum(names.values())}x in: {', '.join(sorted(names))})")
        if args.verbose:
            print(f"      e.g. {examples[key]}")

    print("\nSummary:")
    print(f"  {len(missing)} undecoded key(s), {len(unsampled)} event type(s) with no sample, "
          f"{len(unhandled)} handled only by base rule {BASE_RULE}.")
    if unhandled:
        print("  'base rule only' is expected for routine events (client connect/disconnect/roam);"
              " decide for the rest whether they deserve a rule.")
    if missing or unsampled:
        print("  Anonymize new events (hostnames, client names, MACs, IPs) before adding them to samples/events.log.")
        return 1
    return 0


def run_logtest(container, logs):
    proc = subprocess.run(
        ["docker", "exec", "-i", container, "/var/ossec/bin/wazuh-logtest"],
        input="\n".join(logs) + "\n", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=True,
    )
    results = []
    for block in proc.stdout.split("**Phase 1:")[1:]:
        res = {"decoder": None, "fields": {}, "rule": None, "level": None}
        phase2 = block.split("**Phase 2:", 1)[-1].split("**Phase 3:", 1)
        for m in re.finditer(r"^\t([^:\n]+): '(.*)'$", phase2[0], re.M):
            res["fields"][m.group(1)] = m.group(2)
        res["decoder"] = res["fields"].pop("name", None)
        if len(phase2) > 1:
            if m := re.search(r"^\tid: '(\d+)'", phase2[1], re.M):
                res["rule"] = m.group(1)
            if m := re.search(r"^\tlevel: '(\d+)'", phase2[1], re.M):
                res["level"] = m.group(1)
        results.append(res)
    return results


def check(sample, res):
    exp, errors = sample["expect"], []
    want = exp.get("decoder")
    if want == "none":
        if res["decoder"]:
            errors.append(f"decoder: expected none, got {res['decoder']}")
    elif want and want.startswith("!"):
        if res["decoder"] == want[1:]:
            errors.append(f"decoder: must not be {want[1:]}")
    elif want and res["decoder"] != want:
        errors.append(f"decoder: expected {want}, got {res['decoder']}")
    for key in ("rule", "level"):
        if key in exp and res[key] != exp[key]:
            errors.append(f"{key}: expected {exp[key]}, got {res[key]}")
    for field in filter(None, exp.get("fields", "").split(",")):
        if not res["fields"].get(field):
            errors.append(f"field '{field}' missing or empty")
    return errors


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("samples", nargs="?", default=REPO / "samples" / "events.log", type=Path)
    ap.add_argument("--container", default="wazuh-lab")
    ap.add_argument("--no-reload", action="store_true", help="skip restarting Wazuh before testing")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="also list passing samples (with --scan-archives: show an example line per undecoded key)")
    ap.add_argument("--scan-archives", action="store_true",
                    help="report undecoded keys and unhandled event types in the manager's archive log")
    ap.add_argument("--days", type=int, default=7, help="with --scan-archives: how many days of archives to read (default 7)")
    args = ap.parse_args()

    if args.scan_archives:
        if args.days < 1:
            ap.error("--days must be 1 or more")
        return scan_archives(args)

    samples = load_samples(args.samples)
    failures = undecoded_keys(samples)

    if not args.no_reload:
        def ossec_log():
            return subprocess.run(["docker", "exec", args.container, "cat", "/var/ossec/logs/ossec.log"],
                                  capture_output=True, text=True, check=True).stdout.splitlines()
        before = len(ossec_log())
        restart = subprocess.run(["docker", "exec", args.container, "/var/ossec/bin/wazuh-control", "restart"],
                                 capture_output=True, text=True)
        new = [l for l in ossec_log()[before:] if re.search(r"analysisd.*(ERROR|CRITICAL|WARNING)", l)]
        for l in new:
            print(f"ossec.log: {l}")
        if restart.returncode != 0 or any(re.search(r"ERROR|CRITICAL", l) for l in new):
            sys.exit("Wazuh failed to load the decoders/rules cleanly; see above.")
        failures.extend(f"ossec.log: {l}" for l in new)

    results = run_logtest(args.container, [s["log"] for s in samples])
    if len(results) != len(samples):
        sys.exit(f"logtest returned {len(results)} results for {len(samples)} samples")

    for s, res in zip(samples, results):
        errors = check(s, res)
        summary = f"line {s['line']:>3}  {res['decoder'] or '-':<10} rule {res['rule'] or '-':<6} level {res['level'] or '-':<2}"
        if errors:
            failures.extend(f"line {s['line']}: {e}" for e in errors)
            print(f"FAIL {summary}  " + "; ".join(errors))
        elif args.verbose:
            print(f"ok   {summary}")

    if failures:
        print(f"\n{len(failures)} problem(s) across {len(samples)} samples:")
        for f in failures:
            print(f"  {f}")
        return 1
    print(f"All {len(samples)} samples passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
