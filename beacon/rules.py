import re

from .models import ForwardingRule, Message


def rule_matches_message(rule: ForwardingRule, message: Message) -> bool:
    f = rule.filter_json or {}

    ingest_ids = f.get("ingest_endpoint_ids")
    if ingest_ids is not None:
        if str(message.ingest_endpoint_id) not in {str(x) for x in ingest_ids}:
            return False

    text_filter = f.get("text") or {}
    contains = text_filter.get("contains")
    if contains is not None:
        hay = (message.payload_text or "").lower()
        needles = [str(s).lower() for s in contains if str(s).strip()]
        if needles and not any(n in hay for n in needles):
            return False

    regex = text_filter.get("regex")
    if regex is not None and str(regex).strip():
        try:
            pat = re.compile(str(regex), flags=re.IGNORECASE)
        except re.error:
            return False
        if pat.search(message.payload_text or "") is None:
            return False

    return True
