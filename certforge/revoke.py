import datetime as dt


def status(row, now=None):
    if row["revoked_at"]:
        return "revoked"

    now = now or dt.datetime.now(dt.timezone.utc)
    not_after = dt.datetime.fromisoformat(row["not_after"])
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=dt.timezone.utc)

    if now > not_after:
        return "expired"
    return "valid"
