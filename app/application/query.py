from datetime import date


def filters(
    q="",
    vendor="",
    product_key="",
    ransomware="",
    severity="",
    date_from: date | None = None,
    date_to: date | None = None,
):
    return {
        key: value
        for key, value in {
            "q": q,
            "vendor": vendor,
            "product_key": product_key,
            "ransomware": ransomware,
            "severity": severity,
            "date_from": date_from.isoformat() if date_from else None,
            "date_to": date_to.isoformat() if date_to else None,
        }.items()
        if value
    }
