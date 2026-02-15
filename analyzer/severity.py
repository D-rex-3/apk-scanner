def calculate_risk(findings):
    score_map = {
        "Critical": 10,
        "High" : 7,
        "Medium": 4,
        "Low": 2
    }
    total_score = 0

    for f in findings:
        total_score += score_map.get(f["severity"], 0)

    max_possible = len(findings) * 10 if findings else 1

    risk_percentage = (total_score / max_possible) * 100

    return round(risk_percentage, 2)