"""Offline independent JSON and semantic checker; standard Python only, no networking."""
import json
import pathlib
import re
import subprocess
import sys

exe = pathlib.Path(sys.argv[1]).resolve()
fixtures = pathlib.Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else None
checks = 0

def require(condition, message):
    global checks
    checks += 1
    if not condition:
        raise AssertionError(message)

def run(args, allowed=(0, 1), program=exe):
    result = subprocess.run([str(program), *args], capture_output=True, timeout=30)
    require(result.returncode in allowed, f"exit {result.returncode}: {result.stderr!r}")
    require(not result.stderr, f"unexpected stderr {result.stderr!r}")
    require(not result.stdout.startswith(b"\xef\xbb\xbf"), "UTF-8 BOM")
    text = result.stdout.decode("utf-8", errors="strict")
    if "--json" in args and program == exe:
        data = json.loads(text)
        complete = data["interfaces_complete"] and data["netcfg_complete"] and all(a["bindings_complete"] and not a["errors"] for a in data["adapters"])
        require(result.returncode == (0 if complete else 1), "completeness exit code")
    return text

def pairs(items):
    out = {}
    for key, value in items:
        require(key not in out, f"duplicate JSON key {key}")
        out[key] = value
    return out

def document(text):
    data = json.loads(text, object_pairs_hook=pairs)
    require(data["schema_version"] == "1.0.0", "schema version")
    require(data["application_version"] == "1.0.0", "application version")
    adapters = data["adapters"]
    require(adapters == sorted(adapters, key=lambda a: (a["guid"], a["index"] or 0, a["name"])), "adapter ordering")
    for a in adapters:
        require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", a["guid"]) is not None, "GUID")
        require(a["errors"] == sorted(a["errors"]), "error order")
        for component, actual in a["known_components"].items():
            states = {p["state"] for p in a["paths"] if any(c["id"] == component for c in p["components"])}
            if not a["bindings_complete"]:
                expected = "unavailable"
            elif not states:
                expected = "absent"
            elif "unknown" in states:
                expected = "unknown"
            elif len(states) == 2:
                expected = "mixed"
            else:
                expected = next(iter(states))
            require(actual == expected, f"independent component aggregation: {component} {actual} != {expected}")
    return data

live_text = run(["--json"])
live = document(live_text)
if fixtures:
    fixture_text = run(["--json"], (0,), fixtures)
    fixture = document(fixture_text)
    require("網路 адаптер 😀" in fixture_text, "Unicode fixture")
    states = {a["known_components"]["ms_tcpip"] for a in fixture["adapters"]}
    require(states == {"enabled", "disabled", "mixed", "absent", "unavailable", "unknown"}, "all six states in fixtures")
    require(run(["--json"], (0,), fixtures) == fixture_text, "fixture byte stability")
    require(len(fixture["adapters"]) == 10, "fixture count")
    pathlib.Path("artifacts/fixture.json").write_text(fixture_text, encoding="utf-8")
require(run(["--version"], (0,)).strip() == "windows-network-binding-auditor 1.0.0", "version")
require("Usage:" in run(["--help"], (0,)), "help")
for args in (["--bad"], ["--adapter"], ["--adapter", "this-identifier-does-not-exist"], ["--json", "--json"], ["--summary", "--adapters"]):
    result = subprocess.run([str(exe), *args], capture_output=True, timeout=30)
    require(result.returncode == 2 and not result.stdout and bool(result.stderr), "invalid CLI")
for mode in ([], ["--summary"], ["--adapters"]):
    require("Adapters:" in run(mode), "text mode")
if live["adapters"]:
    a = next((a for a in live["adapters"] if a["bindings_complete"]), live["adapters"][0])
    for selector in (a["guid"], "{" + a["guid"].upper() + "}"):
        selected = document(run(["--adapter", selector, "--json"]))
        require(len(selected["adapters"]) == 1 and selected["adapters"][0]["guid"] == a["guid"], "GUID filter")
    if a["index"]:
        selected = document(run(["--adapter", str(a["index"]), "--json"]))
        require(selected["adapters"][0]["guid"] == a["guid"], "index filter")
    if sum(x["name"] == a["name"] for x in live["adapters"]) == 1:
        selected = document(run(["--adapter", a["name"], "--json"]))
        require(selected["adapters"][0]["guid"] == a["guid"], "name filter")
pathlib.Path("artifacts/live.json").write_text(live_text, encoding="utf-8")
print(f"{checks} independent JSON/CLI/semantic checks passed; {len(live['adapters'])} live adapters")