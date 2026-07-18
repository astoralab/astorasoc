import json
import os
import shutil
import subprocess
import urllib.error
import urllib.request
import zipfile
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path

from flask import current_app
from sqlalchemy import inspect

from app import db
from app.models import AppSetting, utcnow
from app.utils import audit, set_setting, setting

ASTORA_REPO = "astoralab/astorasoc"
GITHUB_API_LATEST = f"https://api.github.com/repos/{ASTORA_REPO}/releases/latest"
GITHUB_MAIN_ARCHIVE = f"https://github.com/{ASTORA_REPO}/archive/refs/heads/main.zip"
SENSITIVE_NAME_PARTS = ("secret", "password", "token", "api_key", "apikey", "key")
STATUS_KEYS = {
    "system_update_last_status",
    "system_update_last_message",
    "system_update_last_backup",
    "system_update_last_release",
    "system_update_last_commands",
    "system_update_last_at",
}


class SystemUpdateError(RuntimeError):
    pass


def run_system_update(actor_id):
    result = {
        "status": "failed",
        "message": "Update failed.",
        "backup": "",
        "release": "",
        "commands": [],
    }
    audit("system_update_started", "Admin started system update workflow.", actor_id)
    try:
        backup_path = create_system_backup()
        result["backup"] = backup_path.name
        audit("system_update_backup_created", f"Verified backup created: {backup_path.name}", actor_id)
    except Exception as exc:
        result["message"] = f"Backup failed. Update stopped: {safe_error(exc)}"
        audit("system_update_failed", "Backup failed. Update stopped.", actor_id)
        _persist_update_status(result)
        return result

    try:
        release = fetch_latest_release_package()
        result["release"] = release["label"]
        audit("system_update_package_fetched", f"Fetched update package: {release['label']}", actor_id)
        if running_in_docker():
            result["status"] = "manual_required"
            result["message"] = "Backup and update package are ready. Docker deployments require a controlled restart from the host."
            result["commands"] = docker_update_commands()
            audit("system_update_manual_required", "Docker deployment detected. Manual host restart commands displayed.", actor_id)
        else:
            apply_result = apply_git_update()
            run_database_migrations()
            health_check()
            result["status"] = "success"
            result["message"] = apply_result
            audit("system_update_success", "System update completed and health check passed.", actor_id)
    except Exception as exc:
        result["status"] = "failed"
        result["message"] = f"Update failed after backup: {safe_error(exc)}"
        audit("system_update_failed", "Update failed after verified backup.", actor_id)
    _persist_update_status(result)
    return result


def last_system_update_status():
    commands = setting("system_update_last_commands", "[]")
    try:
        command_list = json.loads(commands or "[]")
    except json.JSONDecodeError:
        command_list = []
    status = {
        "status": setting("system_update_last_status"),
        "message": setting("system_update_last_message"),
        "backup": setting("system_update_last_backup"),
        "release": setting("system_update_last_release"),
        "commands": command_list,
        "at": setting("system_update_last_at"),
    }
    return status if any(status.get(key) for key in ("status", "message", "backup", "release")) else None


def create_system_backup():
    upload_root = Path(current_app.config["UPLOAD_FOLDER"]).resolve()
    backup_dir = upload_root / "system_backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = utcnow().strftime("%Y%m%d%H%M%S")
    backup_path = backup_dir / f"astorasoc-update-backup-{timestamp}.zip"
    manifest = {
        "created_at": utcnow().isoformat(),
        "product": "AstoraSOC",
        "purpose": "pre-update backup",
        "database_tables": [],
        "upload_files": 0,
        "settings_keys": [],
    }
    with zipfile.ZipFile(backup_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        database_dump = dump_database_tables()
        manifest["database_tables"] = sorted(database_dump.keys())
        archive.writestr("database/database.json", json.dumps(database_dump, indent=2, sort_keys=True))
        settings_dump = dump_system_settings()
        manifest["settings_keys"] = sorted(settings_dump.keys())
        archive.writestr("system_settings/app_settings.json", json.dumps(settings_dump, indent=2, sort_keys=True))
        manifest["upload_files"] = add_uploads_to_archive(archive, upload_root)
        archive.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True))
    with zipfile.ZipFile(backup_path, "r") as verifier:
        if verifier.testzip() is not None:
            backup_path.unlink(missing_ok=True)
            raise SystemUpdateError("Backup archive verification failed.")
        if not {"manifest.json", "database/database.json", "system_settings/app_settings.json"}.issubset(set(verifier.namelist())):
            backup_path.unlink(missing_ok=True)
            raise SystemUpdateError("Backup archive is incomplete.")
    return backup_path


def dump_database_tables():
    inspector = inspect(db.engine)
    output = {}
    for table in db.metadata.sorted_tables:
        if not inspector.has_table(table.name):
            continue
        rows = db.session.execute(table.select()).mappings().all()
        output[table.name] = [{column: serialize_value(value) for column, value in row.items()} for row in rows]
    return output


def dump_system_settings():
    return {item.key: item.value for item in AppSetting.query.order_by(AppSetting.key).all()}


def add_uploads_to_archive(archive, upload_root):
    if not upload_root.exists():
        return 0
    count = 0
    skip_dirs = {"system_backups", "system_updates"}
    for path in upload_root.rglob("*"):
        if path.is_dir():
            continue
        relative = path.relative_to(upload_root)
        if relative.parts and relative.parts[0] in skip_dirs:
            continue
        archive.write(path, f"uploads/{relative.as_posix()}")
        count += 1
    return count


def fetch_latest_release_package():
    update_dir = Path(current_app.config["UPLOAD_FOLDER"]).resolve() / "system_updates"
    update_dir.mkdir(parents=True, exist_ok=True)
    try:
        with urlopen_json(GITHUB_API_LATEST) as release:
            if release.get("prerelease") or release.get("draft"):
                raise SystemUpdateError("Latest GitHub release is not stable.")
            label = release.get("tag_name") or release.get("name") or "latest stable release"
            archive_url = release.get("zipball_url") or GITHUB_MAIN_ARCHIVE
    except (urllib.error.HTTPError, urllib.error.URLError, SystemUpdateError):
        label = "main branch archive"
        archive_url = GITHUB_MAIN_ARCHIVE
    target = update_dir / f"astorasoc-{safe_filename(label)}.zip"
    request = urllib.request.Request(archive_url, headers={"User-Agent": "AstoraSOC-Updater"})
    with urllib.request.urlopen(request, timeout=45) as response, open(target, "wb") as handle:
        shutil.copyfileobj(response, handle)
    with zipfile.ZipFile(target, "r") as verifier:
        if verifier.testzip() is not None:
            target.unlink(missing_ok=True)
            raise SystemUpdateError("Downloaded update package failed archive verification.")
    return {"label": label, "path": str(target)}


def urlopen_json(url):
    request = urllib.request.Request(url, headers={"User-Agent": "AstoraSOC-Updater", "Accept": "application/vnd.github+json"})
    response = urllib.request.urlopen(request, timeout=20)

    class JsonContext:
        def __enter__(self_inner):
            with response:
                return json.loads(response.read().decode("utf-8"))

        def __exit__(self_inner, exc_type, exc, tb):
            return False

    return JsonContext()


def apply_git_update():
    project_root = Path(current_app.root_path).resolve().parent
    if not (project_root / ".git").exists():
        raise SystemUpdateError("Automatic source update requires a Git checkout. Use the displayed Docker/manual commands.")
    run_command(["git", "fetch", "--tags", "origin"], project_root)
    run_command(["git", "pull", "--ff-only", "origin", "main"], project_root)
    return "Update successful. Source updated, migrations completed, and health check passed."


def run_database_migrations():
    project_root = Path(current_app.root_path).resolve().parent
    try:
        run_command(["flask", "--app", "run.py", "db", "upgrade"], project_root)
    except SystemUpdateError:
        run_command(["flask", "--app", "run.py", "upgrade-db"], project_root)


def health_check():
    response = current_app.test_client().get("/login")
    if response.status_code >= 500:
        raise SystemUpdateError("Health check failed.")


def run_command(command, cwd):
    completed = subprocess.run(
        command,
        cwd=str(cwd),
        text=True,
        capture_output=True,
        timeout=180,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemUpdateError(f"Command failed: {' '.join(command[:3])}")
    return completed.stdout


def docker_update_commands():
    return [
        "cd /path/to/astorasoc",
        "git pull --ff-only https://github.com/astoralab/astorasoc.git main",
        "docker compose build web",
        "docker compose up -d",
        "docker compose exec web flask --app run.py db upgrade || docker compose exec web flask --app run.py upgrade-db",
        "docker compose ps",
    ]


def running_in_docker():
    return Path("/.dockerenv").exists() or os.environ.get("ASTORASOC_RUNNING_IN_DOCKER", "").lower() == "true"


def serialize_value(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, bytes):
        return value.hex()
    return value


def safe_filename(value):
    cleaned = "".join(char if char.isalnum() or char in ("-", "_", ".") else "-" for char in str(value).strip())
    return cleaned.strip("-")[:80] or "latest"


def safe_error(exc):
    message = str(exc) or exc.__class__.__name__
    for part in SENSITIVE_NAME_PARTS:
        message = message.replace(part, "[redacted]")
        message = message.replace(part.upper(), "[redacted]")
    return message[:240]


def _persist_update_status(result):
    set_setting("system_update_last_status", result.get("status") or "failed")
    set_setting("system_update_last_message", result.get("message") or "")
    set_setting("system_update_last_backup", result.get("backup") or "")
    set_setting("system_update_last_release", result.get("release") or "")
    set_setting("system_update_last_commands", json.dumps(result.get("commands") or []))
    set_setting("system_update_last_at", utcnow().isoformat())
