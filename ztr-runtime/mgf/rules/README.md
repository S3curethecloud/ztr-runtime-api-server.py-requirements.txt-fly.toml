# MGF Deterministic Patch Rules

This directory documents rule formats used by the MGF Patch Engine.

The engine applies deterministic edits to repository files without rewriting
entire files.

Governance constraints:

- NO DRIFT
- NO GUESSING
- NO HALLUCINATION
- ONE deterministic change per rule
- Anchors must match exactly once
- Ambiguous matches abort execution

## Supported Rule Types

### replace_once

Replace a literal or regex exactly one time.

Example:

{
  "type": "replace_once",
  "needle": "payload = entry.get(\"payload\", {})",
  "replacement": "payload = safe_payload(entry)",
  "is_regex": false
}

### insert_after_anchor

Insert text after a deterministic anchor.

Example:

{
  "type": "insert_after_anchor",
  "anchor": "app = FastAPI(title=\"Zero Trust Runtime\")",
  "insert_text": "\n# inserted code\n",
  "is_regex": false
}

### delete_line_once

Delete a line that must appear exactly once.

Example:

{
  "type": "delete_line_once",
  "line_text": "raise HTTPException(status_code=404, detail=\"decision_not_found\")"
}

## Execution

Run the patch engine:
