import logging
from pathlib import Path

try:
    import yara
except ImportError:
    yara = None

logger = logging.getLogger(__name__)
RULES_PATH = Path(__file__).resolve().parent.parent / "yara_rules" / "threatlens_rules.yar"


def scan_file(file_path: str, rules_path: Path = RULES_PATH):
    result = {
        "available": False,
        "matched": False,
        "match_count": 0,
        "matches": [],
    }

    if yara is None:
        logger.warning("YARA scanning unavailable: yara-python is not installed")
        return result

    if not rules_path.exists():
        logger.warning("YARA rules file is missing: %s", rules_path)
        return result

    try:
        rules = yara.compile(filepath=str(rules_path))
        result["available"] = True
        matches = rules.match(filepath=file_path)
        unique_matches = {}

        for match in matches:
            rule_name = getattr(match, "rule", str(match))
            tags = list(getattr(match, "tags", []) or [])
            unique_matches[rule_name] = {
                "rule": rule_name,
                "tags": tags,
            }

        result["matches"] = list(unique_matches.values())
        result["match_count"] = len(result["matches"])
        result["matched"] = result["match_count"] > 0
    except Exception as error:
        logger.exception("YARA scan failed for %s: %s", file_path, error)

    return result
