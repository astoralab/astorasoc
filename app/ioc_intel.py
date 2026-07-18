import ipaddress
import os
import re
from dataclasses import dataclass
from urllib.parse import urlparse


DOMAIN_LIKE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
URL = re.compile(r"https?://[^\s\"'<>]+", re.I)
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
REGISTRY = re.compile(r"\b(?:HKLM|HKCU|HKCR|HKU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\s\"']+", re.I)
WINDOWS_PATH = re.compile(r"\b[A-Za-z]:\\[^\s\"<>|]+", re.I)
UNIX_PATH = re.compile(r"(?<!\w)/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+\.[A-Za-z0-9]{1,8}\b")
FILE_NAME = re.compile(r"\b[\w$@%+=,{}~#-]+\.(?:exe|dll|sys|bat|cmd|ps1|vbs|js|jar|msi|scr|lnk|tmp|log|conf|json|xml|txt|zip|rar|7z|gz|pdf|docx?|xlsx?|png|jpe?g|gif|bin)\b", re.I)
PROCESS_NAME = re.compile(r"\b[A-Za-z0-9_$@%+=,{}~#-]+\.(?:exe|dll|sys|bat|cmd|ps1|vbs|js|jar|msi|scr)\b", re.I)
COMMAND_LINE = re.compile(r"(?im)(?:^|\s)(?:cmd\.exe|powershell(?:\.exe)?|pwsh(?:\.exe)?|wmic(?:\.exe)?|rundll32(?:\.exe)?|regsvr32(?:\.exe)?|mshta(?:\.exe)?|certutil(?:\.exe)?|curl(?:\.exe)?|wget(?:\.exe)?|python(?:\.exe)?|bash|sh)\s+[^\r\n]{3,260}")
USERNAME = re.compile(r"(?i)\b(?:user(?:name)?|srcuser|dstuser|account|login)\s*[=:]\s*([A-Za-z0-9._\\$@-]{2,80})")

FILE_EXTENSIONS = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jar", "msi", "scr", "lnk",
    "tmp", "log", "conf", "json", "xml", "txt", "zip", "rar", "7z", "gz", "pdf", "doc",
    "docx", "xls", "xlsx", "png", "jpg", "jpeg", "gif", "bin",
}
RESERVED_DOMAINS = {"localhost", "localdomain"}
INTERNAL_HOST_TLDS = {"local", "lan", "home", "internal", "corp", "domain", "manager"}
PUBLIC_TLDS = {
    "com", "net", "org", "edu", "gov", "mil", "int", "io", "co", "us", "uk", "in", "dev",
    "app", "info", "biz", "me", "cloud", "security", "site", "online", "ru", "cn", "de",
    "fr", "jp", "au", "ca", "br", "nl", "es", "it",
}
SURROUNDING = "\"'`“”‘’()[]{}<>"
TRAILING = ".,;:!?)]}'\"`"


@dataclass(frozen=True)
class ExtractedIOC:
    type: str
    value: str
    normalized: str
    confidence: str = "Medium"


TYPE_ALIASES = {
    "Domain": "DOMAIN",
    "Hostname": "HOST",
    "Host": "HOST",
    "Username": "USER",
    "User": "USER",
    "Process": "PROCESS",
    "File": "FILE",
    "Registry": "REGISTRY",
    "CommandLine": "PROCESS",
    "Hash": "HASH",
    "Hash-MD5": "HASH",
    "Hash-SHA1": "HASH",
    "Hash-SHA256": "HASH",
    "Email": "EMAIL",
    "Url": "URL",
    "URL": "URL",
    "IP": "IP",
    "Service": "SERVICE",
}

TYPE_LABELS = {
    "IP": "IP Address",
    "DOMAIN": "Domain",
    "HOST": "Hostname",
    "URL": "URL",
    "USER": "Username",
    "EMAIL": "Email",
    "PROCESS": "Process",
    "FILE": "File",
    "REGISTRY": "Registry Key",
    "HASH": "File Hash",
    "SERVICE": "Service",
}


def canonical_ioc_type(kind):
    if not kind:
        return "FILE"
    value = str(kind).strip()
    return TYPE_ALIASES.get(value, TYPE_ALIASES.get(value.title(), value.upper()))


def ioc_type_label(kind):
    return TYPE_LABELS.get(canonical_ioc_type(kind), canonical_ioc_type(kind).replace("_", " ").title())


def ioc_type_class(kind):
    return canonical_ioc_type(kind).lower().replace("_", "-")


def normalize_ioc(kind, value):
    kind = canonical_ioc_type(kind)
    value = sanitize_ioc_value(kind, value)
    if not value:
        return ""
    if kind in {"DOMAIN", "HOST", "EMAIL", "PROCESS", "FILE", "REGISTRY", "SERVICE"}:
        return value.lower()
    if kind == "HASH":
        return value.lower()
    if kind == "URL":
        parsed = urlparse(value)
        scheme = (parsed.scheme or "http").lower()
        host = (parsed.netloc or "").lower()
        path = parsed.path or ""
        return f"{scheme}://{host}{path}".rstrip("/")
    return value


def clean_value(value):
    return sanitize_ioc_value("Text", value) or ""


def sanitize_ioc_value(kind, value):
    kind = canonical_ioc_type(kind)
    if value is None:
        return None
    text = re.sub(r"[\x00-\x1f\x7f]", " ", str(value))
    text = text.strip().strip(SURROUNDING)
    text = re.sub(r"\s+", " ", text)
    text = text.rstrip(TRAILING).strip()
    text = text.strip(SURROUNDING)
    if not text or len(text) < 2:
        return None
    if len(text) > 500:
        text = text[:500].rstrip()
    if kind == "IP":
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            return None
    if kind in {"DOMAIN", "HOST"}:
        text = text.lower().rstrip(".")
        if "\\" in text or "/" in text or "@" in text or " " in text:
            return None
        if kind == "DOMAIN" and "." not in text:
            return None
    elif kind == "HASH":
        text = text.lower()
        if len(text) not in {32, 40, 64} or not re.fullmatch(r"[a-f0-9]+", text):
            return None
    elif kind == "USER":
        text = text.replace("\\\\", "\\").strip()
        if any(ch in text for ch in "/\r\n\t"):
            return None
    elif kind in {"PROCESS", "FILE", "SERVICE"}:
        text = os.path.basename(text.replace("\\", "/")) if kind == "PROCESS" else text
    return text


def hash_type(value):
    return "HASH"


def is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_domain_candidate(value):
    value = sanitize_ioc_value("Domain", value)
    if not value:
        return False
    if value in RESERVED_DOMAINS or "\\" in value or "/" in value or "@" in value:
        return False
    labels = value.split(".")
    if len(labels) < 2 or labels[-1] in FILE_EXTENSIONS:
        return False
    if any(not label or label.startswith("-") or label.endswith("-") for label in labels):
        return False
    return labels[-1] in PUBLIC_TLDS and labels[-1] not in INTERNAL_HOST_TLDS and not is_valid_ip(value)


def is_hostname_candidate(value):
    value = sanitize_ioc_value("Hostname", value)
    if not value:
        return False
    labels = value.split(".")
    return len(labels) >= 2 and labels[-1] not in FILE_EXTENSIONS and not is_domain_candidate(value)


def add_ioc(found, kind, value, confidence="Medium"):
    kind = canonical_ioc_type(kind)
    value = sanitize_ioc_value(kind, value)
    if not value:
        return
    normalized = normalize_ioc(kind, value)
    key = (kind, normalized)
    if key in found:
        return
    found[key] = ExtractedIOC(kind, value, normalized, confidence)


def extract_iocs(text):
    text = str(text or "")
    text_without_urls = URL.sub(" ", text)
    found = {}

    for match in URL.findall(text):
        add_ioc(found, "URL", match, "High")
        host = urlparse(match).hostname
        if host:
            add_ioc(found, "DOMAIN" if is_domain_candidate(host) else "HOST", host, "Medium")

    for match in EMAIL.findall(text):
        add_ioc(found, "EMAIL", match, "High")

    for match in HASH.findall(text):
        add_ioc(found, hash_type(match), match, "High")

    for match in REGISTRY.findall(text):
        add_ioc(found, "REGISTRY", match, "High")

    for match in COMMAND_LINE.findall(text):
        add_ioc(found, "PROCESS", match.strip(), "High")

    for match in PROCESS_NAME.findall(text):
        add_ioc(found, "PROCESS", match, "High")

    for pattern in (WINDOWS_PATH, UNIX_PATH):
        for match in pattern.findall(text_without_urls):
            add_ioc(found, "FILE", match, "High")

    for match in FILE_NAME.findall(text):
        base = os.path.basename(match.replace("\\", "/"))
        if base:
            if not any(ioc.normalized == normalize_ioc("PROCESS", base) for (kind, _), ioc in found.items() if kind == "PROCESS"):
                add_ioc(found, "FILE", base, "Medium")

    for match in IP.findall(text):
        if is_valid_ip(match):
            add_ioc(found, "IP", match, "High")

    for match in USERNAME.findall(text):
        if "." not in match or "\\" in match or "@" in match:
            add_ioc(found, "USER", match, "Medium")

    for match in DOMAIN_LIKE.findall(text):
        if not any(normalize_ioc(kind, match) == ioc.normalized for (kind, _), ioc in found.items() if kind in {"PROCESS", "FILE"}):
            if is_domain_candidate(match):
                add_ioc(found, "DOMAIN", match, "Medium")
            elif is_hostname_candidate(match):
                add_ioc(found, "HOST", match, "Medium")

    return list(found.values())
