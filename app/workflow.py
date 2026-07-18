from datetime import timedelta

from app.models import utcnow

ALERT_NEW = "NEW"
ALERT_PENDING_REVIEW = "PENDING_REVIEW"
ALERT_FALSE_POSITIVE = "FALSE_POSITIVE"
ALERT_PROMOTED = "PROMOTED"
ALERT_ARCHIVED = "ARCHIVED"

CASE_ASSIGNED = "ASSIGNED"
CASE_INVESTIGATING = "INVESTIGATING"
CASE_SUBMITTED_FOR_REVIEW = "SUBMITTED_FOR_REVIEW"
CASE_CLOSED = "CLOSED"

SEVERITY_LABELS = ["Critical", "High", "Medium", "Low"]

ALERT_STATUS_LABELS = {
    ALERT_NEW: "New",
    ALERT_PENDING_REVIEW: "Pending Review",
    ALERT_FALSE_POSITIVE: "False Positive",
    ALERT_PROMOTED: "Promoted",
    ALERT_ARCHIVED: "Archived",
    "Pending Review": "New",
    "Submitted for Review": "Pending Review",
    "False Positive": "False Positive",
    "Promoted": "Promoted",
}

CASE_STATUS_LABELS = {
    CASE_ASSIGNED: "Assigned",
    CASE_INVESTIGATING: "Investigating",
    CASE_SUBMITTED_FOR_REVIEW: "Pending Review",
    CASE_CLOSED: "Closed",
    "Assigned": "Assigned",
    "Investigating": "Investigating",
    "Submitted for Review": "Pending Review",
    "Pending Review": "Pending Review",
    "New": "Pending Review",
    "Closed": "Closed",
    "False Positive": "Closed",
}

ALERT_STATUS_GROUPS = {
    ALERT_NEW: [ALERT_NEW, "New", "Pending Review"],
    ALERT_PENDING_REVIEW: [ALERT_PENDING_REVIEW, "Submitted for Review"],
    ALERT_FALSE_POSITIVE: [ALERT_FALSE_POSITIVE, "False Positive"],
    ALERT_PROMOTED: [ALERT_PROMOTED, "Promoted"],
    ALERT_ARCHIVED: [ALERT_ARCHIVED, "Archived"],
}

CASE_STATUS_GROUPS = {
    CASE_ASSIGNED: [CASE_ASSIGNED, "Assigned"],
    CASE_INVESTIGATING: [CASE_INVESTIGATING, "Investigating", "Containment", "Eradication", "Recovery"],
    CASE_SUBMITTED_FOR_REVIEW: [CASE_SUBMITTED_FOR_REVIEW, "Submitted for Review", "Pending Review", "New"],
    CASE_CLOSED: [CASE_CLOSED, "Closed", "False Positive"],
}

PERIODS = {
    "all": ("All", None),
    "daily": ("Daily", timedelta(days=1)),
    "weekly": ("Weekly", timedelta(days=7)),
    "monthly": ("Monthly", timedelta(days=30)),
    "yearly": ("Yearly", timedelta(days=365)),
}


def alert_statuses(status):
    return ALERT_STATUS_GROUPS.get(status, [status])


def case_statuses(status):
    return CASE_STATUS_GROUPS.get(status, [status])


def status_label(status):
    return ALERT_STATUS_LABELS.get(status) or CASE_STATUS_LABELS.get(status) or str(status or "Unknown").replace("_", " ").title()


def normalize_period(period):
    return period if period in PERIODS else "all"


def period_cutoff(period):
    _, delta = PERIODS[normalize_period(period)]
    if delta is None:
        return None
    return utcnow() - delta
