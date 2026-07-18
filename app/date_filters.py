from datetime import datetime, timedelta

LOCAL_OFFSET = timedelta(hours=5, minutes=30)


def local_day_to_utc_range(start):
    local_start = datetime(start.year, start.month, start.day)
    local_end = local_start + timedelta(days=1)
    return local_start - LOCAL_OFFSET, local_end - LOCAL_OFFSET


def date_range_from_request(args):
    day_text = (args.get("date") or "").strip()
    month_text = (args.get("month") or "").strip()
    year_text = (args.get("year") or "").strip()
    try:
        if day_text:
            return local_day_to_utc_range(datetime.fromisoformat(day_text))
        if month_text and "-" in month_text:
            year_part, month_part = month_text.split("-", 1)
            year_text = year_part or year_text
            month_text = month_part
        year = int(year_text) if year_text else None
        month = int(month_text) if month_text else None
        if month and not year:
            year = datetime.utcnow().year
        if year and month:
            local_start = datetime(year, month, 1)
            local_end = datetime(year + (1 if month == 12 else 0), 1 if month == 12 else month + 1, 1)
            return local_start - LOCAL_OFFSET, local_end - LOCAL_OFFSET
        if year:
            return datetime(year, 1, 1) - LOCAL_OFFSET, datetime(year + 1, 1, 1) - LOCAL_OFFSET
    except (TypeError, ValueError):
        return None, None
    return None, None


def has_date_filter(args):
    return any((args.get(key) or "").strip() for key in ("date", "month", "year"))


def apply_date_filter(query, column, args):
    start, end = date_range_from_request(args)
    if start and end:
        return query.filter(column >= start, column < end)
    return query


def active_date_filter(args):
    return {
        "date": (args.get("date") or "").strip(),
        "month": (args.get("month") or "").strip(),
        "year": (args.get("year") or "").strip(),
    }


def date_filter_label(args):
    filters = active_date_filter(args)
    if filters["date"]:
        return f"Date {filters['date']}"
    if filters["month"]:
        return f"Month {filters['month']}"
    if filters["year"]:
        return f"Year {filters['year']}"
    return None
