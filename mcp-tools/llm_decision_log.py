"""
LLM Decision Log — JSONL-based logger for recording LLM reasoning decisions.

Used by the new MCP tools to record every LLM decision for ablation study analysis.
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

LOG_FILE = Path(__file__).parent / "llm_decisions.jsonl"


def log_decision(
    category: str,
    input_data: Dict[str, Any],
    map_result: Optional[Dict[str, Any]],
    llm_result: Dict[str, Any],
    agreed: bool,
) -> str:
    record = {
        "id": uuid.uuid4().hex[:12],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "category": category,
        "input": input_data,
        "map_result": map_result,
        "llm_result": llm_result,
        "agreed": agreed,
    }
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record["id"]


def query_decisions(
    category: Optional[str] = None,
) -> list:
    if not LOG_FILE.exists():
        return []
    results = []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if category and record.get("category") != category:
                continue
            results.append(record)
    return results


def get_statistics() -> Dict[str, Any]:
    decisions = query_decisions()
    if not decisions:
        return {"total": 0, "categories": {}}
    cats: Dict[str, Any] = {}
    for d in decisions:
        cat = d["category"]
        if cat not in cats:
            cats[cat] = {"total": 0, "agreed": 0, "disagreed": 0}
        cats[cat]["total"] += 1
        if d["agreed"]:
            cats[cat]["agreed"] += 1
        else:
            cats[cat]["disagreed"] += 1
    return {
        "total": len(decisions),
        "categories": cats,
    }
