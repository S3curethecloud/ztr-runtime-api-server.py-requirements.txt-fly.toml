#!/usr/bin/env python3
"""
MGF Compliance Patch Engine
- deterministic patch generation (unified diff)
- anchor-based surgical edits
- refuses ambiguous matches
- produces compliance attestation
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple


# -----------------------------
# Utilities
# -----------------------------

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())

def now_utc_compact() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")

def run(cmd: List[str]) -> Tuple[int, str, str]:
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate()
    return p.returncode, out, err

def die(msg: str, code: int = 2) -> None:
    print(f"[MGF] ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


# -----------------------------
# Deterministic edit rules
# -----------------------------

@dataclass(frozen=True)
class Anchor:
    """Exact/regex anchor that must match exactly once."""
    pattern: str
    is_regex: bool = False

    def find_once(self, text: str) -> Tuple[int, int]:
        if self.is_regex:
            matches = list(re.finditer(self.pattern, text, flags=re.MULTILINE))
            if len(matches) != 1:
                die(f"Anchor regex must match exactly once. pattern={self.pattern!r}, matches={len(matches)}")
            m = matches[0]
            return m.start(), m.end()
        else:
            idx = text.find(self.pattern)
            if idx == -1:
                die(f"Anchor literal not found: {self.pattern!r}")
            # ensure only once
            if text.find(self.pattern, idx + 1) != -1:
                die(f"Anchor literal appears multiple times (ambiguous): {self.pattern!r}")
            return idx, idx + len(self.pattern)

@dataclass(frozen=True)
class ReplaceOnce:
    """Replace a literal or regex exactly once."""
    needle: str
    replacement: str
    is_regex: bool = False

    def apply(self, text: str) -> Tuple[str, dict]:
        if self.is_regex:
            matches = list(re.finditer(self.needle, text, flags=re.MULTILINE))
            if len(matches) != 1:
                die(f"Replace regex must match exactly once. needle={self.needle!r}, matches={len(matches)}")
            new_text, n = re.subn(self.needle, self.replacement, text, count=1, flags=re.MULTILINE)
            if n != 1:
                die("Regex replace failed unexpectedly.")
            return new_text, {"type": "replace_regex_once", "needle": self.needle}
        else:
            idx = text.find(self.needle)
            if idx == -1:
                die(f"Replace literal not found: {self.needle!r}")
            if text.find(self.needle, idx + 1) != -1:
                die(f"Replace literal appears multiple times (ambiguous): {self.needle!r}")
            new_text = text.replace(self.needle, self.replacement, 1)
            return new_text, {"type": "replace_literal_once", "needle": self.needle}

@dataclass(frozen=True)
class InsertAfterAnchor:
    """Insert content after an anchor that must match exactly once."""
    anchor: Anchor
    insert_text: str

    def apply(self, text: str) -> Tuple[str, dict]:
        start, end = self.anchor.find_once(text)
        new_text = text[:end] + self.insert_text + text[end:]
        return new_text, {"type": "insert_after_anchor", "anchor": self.anchor.pattern}

@dataclass(frozen=True)
class DeleteLineOnce:
    """Delete a single line (exact match) exactly once."""
    line_text: str

    def apply(self, text: str) -> Tuple[str, dict]:
        lines = text.splitlines(keepends=True)
        hits = [i for i, ln in enumerate(lines) if ln.rstrip("\n") == self.line_text]
        if len(hits) != 1:
            die(f"DeleteLineOnce must match exactly once. line={self.line_text!r}, matches={len(hits)}")
        del lines[hits[0]]
        return "".join(lines), {"type": "delete_line_once", "line": self.line_text}


# -----------------------------
# Patch building
# -----------------------------

def unified_diff(old: str, new: str, path: str) -> str:
    import difflib
    old_lines = old.splitlines(keepends=True)
    new_lines = new.splitlines(keepends=True)
    diff = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
        lineterm=""
    )
    return "\n".join(diff) + "\n"

def ensure_git_repo() -> None:
    code, out, err = run(["git", "rev-parse", "--is-inside-work-tree"])
    if code != 0 or out.strip() != "true":
        die("Not inside a git repo. Run from repo root or inside repo.")

def apply_patch_file(patch_path: Path) -> None:
    code, out, err = run(["git", "apply", "--index", str(patch_path)])
    if code != 0:
        die(f"git apply failed.\n{err}")

def compute_file_lines_changed(diff_text: str) -> dict:
    adds = sum(1 for l in diff_text.splitlines() if l.startswith("+") and not l.startswith("+++"))
    dels = sum(1 for l in diff_text.splitlines() if l.startswith("-") and not l.startswith("---"))
    return {"added_lines": adds, "deleted_lines": dels}

def write_attestation(attest_dir: Path, payload: dict) -> Path:
    attest_dir.mkdir(parents=True, exist_ok=True)
    name = f"{payload['ts_utc']}_{payload['target_path'].replace('/', '_')}.json"
    p = attest_dir / name
    p.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return p


# -----------------------------
# Main engine
# -----------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="MGF deterministic patch engine")
    ap.add_argument("--target", required=True, help="Target file path (repo-relative)")
    ap.add_argument("--mode", required=True, choices=["apply"], help="Mode")
    ap.add_argument("--patch-out", default="", help="Optional patch output path")
    ap.add_argument("--attest-dir", default="mgf_attest", help="Attestation output directory")
    ap.add_argument("--patch-dir", default="mgf_patches", help="Patch output directory")
    ap.add_argument("--rule", action="append", default=[], help="Rule in JSON (see docs)")
    args = ap.parse_args()

    ensure_git_repo()

    target_path = Path(args.target)
    if not target_path.exists():
        die(f"Target file does not exist: {target_path}")

    old_bytes = target_path.read_bytes()
    old_text = old_bytes.decode("utf-8")
    before_hash = sha256_bytes(old_bytes)

    # Parse rules (deterministic)
    edits = []
    applied_rules_meta = []

    for rj in args.rule:
        try:
            spec = json.loads(rj)
        except json.JSONDecodeError as e:
            die(f"Invalid --rule JSON: {e}")

        rtype = spec.get("type")
        if rtype == "replace_once":
            edits.append(ReplaceOnce(
                needle=spec["needle"],
                replacement=spec["replacement"],
                is_regex=bool(spec.get("is_regex", False))
            ))
        elif rtype == "insert_after_anchor":
            edits.append(InsertAfterAnchor(
                anchor=Anchor(spec["anchor"], is_regex=bool(spec.get("is_regex", False))),
                insert_text=spec["insert_text"]
            ))
        elif rtype == "delete_line_once":
            edits.append(DeleteLineOnce(line_text=spec["line_text"]))
        else:
            die(f"Unknown rule type: {rtype}")

    # Apply edits in order, refusing ambiguity
    new_text = old_text
    for e in edits:
        new_text, meta = e.apply(new_text)
        applied_rules_meta.append(meta)

    if new_text == old_text:
        die("No changes produced (patch would be empty). Refusing to proceed.")

    diff_text = unified_diff(old_text, new_text, args.target)
    patch_hash = sha256_bytes(diff_text.encode("utf-8"))

    patch_dir = Path(args.patch_dir)
    patch_dir.mkdir(parents=True, exist_ok=True)
    patch_name = f"{now_utc_compact()}_{args.target.replace('/', '_')}.patch"
    patch_path = Path(args.patch_out) if args.patch_out else (patch_dir / patch_name)
    patch_path.write_text(diff_text, encoding="utf-8")

    # Apply patch deterministically
    apply_patch_file(patch_path)

    after_hash = sha256_file(target_path)

    attest_payload = {
        "mgf_engine": "patch_engine_v1",
        "ts_utc": now_utc_compact(),
        "target_path": args.target,
        "before_sha256": before_hash,
        "after_sha256": after_hash,
        "patch_path": str(patch_path),
        "patch_sha256": patch_hash,
        "diff_stats": compute_file_lines_changed(diff_text),
        "rules_applied": applied_rules_meta,
        "verification": {
            "git_apply_indexed": True,
            "target_exists": True,
            "non_empty_patch": True,
        }
    }

    attest_path = write_attestation(Path(args.attest_dir), attest_payload)

    print("[MGF] OK")
    print(f"[MGF] Patch: {patch_path}")
    print(f"[MGF] Attestation: {attest_path}")
    print(f"[MGF] Target: {args.target}")
    print(f"[MGF] Before sha256: {before_hash}")
    print(f"[MGF] After  sha256: {after_hash}")


if __name__ == "__main__":
    main()
