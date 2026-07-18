from io import BytesIO

from PIL import Image, ImageDraw, ImageFont


WIDTH = 980
HEIGHT = 340
MARGIN_X = 56
TOP = 58
BAR_HEIGHT = 22
BAR_GAP = 20

SOC_COLORS = {
    "critical": "#dc2626",
    "high": "#f97316",
    "medium": "#f59e0b",
    "low": "#2563eb",
    "closed": "#16a34a",
    "remediated": "#16a34a",
    "completed": "#16a34a",
    "pending": "#f59e0b",
    "failed": "#dc2626",
    "rejected": "#dc2626",
    "residual risk": "#16a34a",
    "initial risk": "#f97316",
    "before remediation": "#dc2626",
    "after remediation": "#16a34a",
    "detected": "#dc2626",
    "validated": "#f59e0b",
    "verified": "#16a34a",
    "approved": "#16a34a",
    "executed": "#16a34a",
    "requested": "#f59e0b",
}

PALETTE = ["#2563eb", "#7c3aed", "#0f766e", "#f97316", "#dc2626", "#64748b", "#0891b2"]
RISK_LABELS = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


def render_report_charts(chart_rows):
    images = []
    for chart in chart_rows or []:
        rows = normalized_rows(chart)
        if not meaningful_chart(chart.get("title", ""), rows):
            continue
        png = render_horizontal_chart(chart.get("title") or "Summary", rows)
        images.append({
            "title": chart.get("title") or "Summary",
            "caption": caption_for(chart.get("title") or "Summary"),
            "png": png,
        })
        if len(images) >= 3:
            break
    return images


def normalized_rows(chart):
    rows = []
    for label, value in chart.get("rows", []):
        try:
            numeric = int(value or 0)
        except (TypeError, ValueError):
            continue
        if numeric >= 0:
            rows.append((str(label), numeric))
    return rows


def meaningful_chart(title, rows):
    if not rows or max(value for _, value in rows) <= 0:
        return False
    if title == "IOC Distribution" and len([value for _, value in rows if value > 0]) < 2:
        return False
    if title in {"Evidence Summary", "MITRE Technique Distribution", "Severity Distribution"} and len([value for _, value in rows if value > 0]) < 2:
        return False
    if title == "Remediation Progress" and len([value for _, value in rows if value > 0]) < 3:
        return False
    return True


def render_horizontal_chart(title, rows):
    row_count = max(len(rows), 2)
    height = max(HEIGHT, TOP + row_count * (BAR_HEIGHT + BAR_GAP) + 76)
    image = Image.new("RGB", (WIDTH, height), "#ffffff")
    draw = ImageDraw.Draw(image)
    title_font = load_font(24, bold=True)
    label_font = load_font(17, bold=True)
    value_font = load_font(16, bold=True)
    small_font = load_font(14)

    draw.rounded_rectangle((8, 8, WIDTH - 8, height - 8), radius=22, fill="#ffffff", outline="#d7e4e2", width=2)
    draw.text((MARGIN_X, 28), title, fill="#063b39", font=title_font)

    max_value = max(value for _, value in rows) or 1
    tick_values = ticks_for(max_value)
    label_width = 170
    bar_x = MARGIN_X + label_width
    bar_width = WIDTH - bar_x - 120
    chart_bottom = TOP + len(rows) * (BAR_HEIGHT + BAR_GAP)

    for tick in tick_values:
        x = bar_x + int(bar_width * tick / tick_values[-1]) if tick_values[-1] else bar_x
        draw.line((x, TOP - 8, x, chart_bottom), fill="#edf3f2", width=1)
        draw.text((x - 8, chart_bottom + 8), compact_number(tick), fill="#6b7d82", font=small_font)

    for index, (label, value) in enumerate(rows):
        y = TOP + index * (BAR_HEIGHT + BAR_GAP)
        color = color_for(label, title, value)
        fill_width = int(bar_width * value / tick_values[-1]) if tick_values[-1] else 0
        label_text = display_label(title, label, value)
        draw.text((MARGIN_X, y - 1), label_text[:26], fill="#315e60", font=label_font)
        draw.rounded_rectangle((bar_x, y, bar_x + bar_width, y + BAR_HEIGHT), radius=11, fill="#edf5f3")
        if fill_width:
            draw.rounded_rectangle((bar_x, y, bar_x + max(fill_width, 8), y + BAR_HEIGHT), radius=11, fill=color)
        draw.text((bar_x + min(fill_width + 10, bar_width + 12), y + 1), compact_number(value), fill="#172b2f", font=value_font)

    buffer = BytesIO()
    image.save(buffer, format="PNG", optimize=True)
    return buffer.getvalue()


def load_font(size, bold=False):
    names = ["DejaVuSans-Bold.ttf", "Arialbd.ttf"] if bold else ["DejaVuSans.ttf", "Arial.ttf"]
    for name in names:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def ticks_for(max_value):
    if max_value <= 4:
        return [0, 1, 2, 3, 4]
    if max_value <= 10:
        return [0, max_value // 2 or 1, max_value]
    magnitude = 10 ** (len(str(max_value)) - 1)
    step = max(1, round(max_value / 4 / magnitude) * magnitude)
    ticks = list(range(0, max_value + step, step))
    if ticks[-1] < max_value:
        ticks.append(max_value)
    return ticks[:6] if len(ticks) > 6 else ticks


def color_for(label, title, value):
    key = str(label).strip().lower()
    if title == "Risk Summary":
        if key == "residual risk" and value <= 1:
            return "#16a34a"
        return {4: "#dc2626", 3: "#f97316", 2: "#f59e0b", 1: "#16a34a"}.get(value, "#64748b")
    if title == "Risk Reduction":
        if "after" in key:
            if value < 25:
                return "#16a34a"
            if value < 50:
                return "#f59e0b"
            if value < 75:
                return "#f97316"
            return "#dc2626"
        return "#dc2626" if value >= 75 else "#f97316"
    for token, color in SOC_COLORS.items():
        if token in key:
            return color
    return PALETTE[abs(hash(key)) % len(PALETTE)]


def display_label(title, label, value):
    if title == "Risk Summary":
        return f"{label} ({RISK_LABELS.get(value, value)})"
    if title == "Risk Reduction":
        return f"{label} ({risk_rating(value)})"
    return label


def caption_for(title):
    captions = {
        "Risk Summary": "Risk reduction from initial severity to residual risk.",
        "Risk Reduction": "Risk reduction from pre-remediation exposure to post-remediation residual risk.",
        "Remediation Progress": "Major remediation lifecycle milestones completed during the investigation.",
        "Task Completion": "Investigation task completion status.",
        "IOC Distribution": "IOC type distribution observed in the case.",
        "MITRE Technique Distribution": "MITRE ATT&CK techniques observed across related case activity.",
        "Severity Distribution": "Severity distribution across related alerts.",
        "Timeline Activity": "Major investigation activity by phase.",
        "Containment Status": "Containment action status summary.",
        "Evidence Summary": "Evidence collected by artifact type.",
    }
    return captions.get(title, f"{title} summary.")


def risk_rating(value):
    value = int(value or 0)
    if value >= 75:
        return "Critical"
    if value >= 50:
        return "High"
    if value >= 25:
        return "Medium"
    return "Low"


def compact_number(value):
    value = int(value or 0)
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}m"
    if value >= 10_000:
        return f"{value / 1_000:.1f}k"
    return str(value)
