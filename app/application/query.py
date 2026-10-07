import re
from datetime import date


def filters(q="", vendor="", product_key="", ransomware="", severity="", date_from: date | None = None, date_to: date | None = None):
    result = {}
    if q:
        result["$or"] = [{k: {"$regex": re.escape(q), "$options": "i"}} for k in ("cve_id", "title", "product", "vendor")]
    for field, value in (("vendor", vendor), ("product_key", product_key), ("ransomware", ransomware)):
        if value:
            result[field] = value
    if severity:
        result["nvd.primary.severity"] = None if severity == "UNASSESSED" else severity
    if date_from or date_to:
        result["date_added"] = {}
        if date_from:
            result["date_added"]["$gte"] = date_from.isoformat()
        if date_to:
            result["date_added"]["$lte"] = date_to.isoformat()
    return result
