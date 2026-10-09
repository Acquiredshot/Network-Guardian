def score(detections: list[dict[str, str]]) -> int:
    weights = {"low": 20, "medium": 50, "high": 75, "critical": 100}
    return min(100, max((weights.get(item.get("severity", "low"), 0) for item in detections), default=0))
