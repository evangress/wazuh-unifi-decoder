#!/usr/bin/env python3
"""Run samples/events.log through wazuh-logtest and check each "# expect:" line.

Needs a running Wazuh manager container that loads this repo (and, for rule checks,
../wazuh-unifi-rules). See "Lab testing in Docker" in CLAUDE.md.

Usage: ./test.py [--container NAME] [--no-reload] [--verbose] [samples-file]
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent
DECODER_FILE = REPO / "ubiquiti_decoders.xml"


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
    decoders = DECODER_FILE.read_text()
    known = set(re.findall(r"\\b([A-Za-z0-9]+)=", decoders))
    problems = []
    for s in samples:
        if "|Ubiquiti|" not in s["log"]:
            continue
        extension = s["log"].split("|", 7)[-1]
        for key in re.findall(r"(?:^|\s)([A-Za-z][A-Za-z0-9_]*)=", extension):
            if key not in known:
                problems.append(f"line {s['line']}: no decoder for key '{key}'")
    return problems


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
    ap.add_argument("--verbose", "-v", action="store_true", help="also list passing samples")
    args = ap.parse_args()

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
