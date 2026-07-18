import os
import zipfile
import json
import mimetypes
from collections import defaultdict
from io import BytesIO

from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, send_file, send_from_directory, url_for
from flask_login import current_user
from markupsafe import Markup, escape
from sqlalchemy import func

from app import db
from app.decorators import roles_required
from app.models import ChatMessage, ChatReaction, Notification, User, utcnow
from app.security import safe_original_name
from app.utils import audit, decrypt_text, encrypt_text, mark_notifications, notify_roles, random_filename, render_chat_mentions, role_allows, role_config, save_upload, set_setting, setting

chats_bp = Blueprint("chats", __name__)

CHAT_ROLES = ("Admin", "Lead", "Analyst", "Junior Analyst")
DEFAULT_CHAT_EMOJIS = ("👍", "❤️", "😂", "😮", "😢", "🙏", "🔥", "✅")
ALLOWED_CHAT_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif", "webp", "mp3", "wav", "ogg", "mp4", "webm", "mov", "zip"}


@chats_bp.route("/chats", methods=["GET", "POST"])
@roles_required(*CHAT_ROLES)
def chats():
    first_unread = (
        Notification.query.filter_by(user_id=current_user.id, category="chats", read_at=None)
        .order_by(Notification.created_at.asc())
        .first()
    )
    unread_since = first_unread.created_at if first_unread else None
    mark_notifications("chats")
    if request.method == "POST":
        body = request.form.get("body", "").strip()
        file = request.files.get("attachment")
        emoji_tokens = request.form.getlist("emoji_tokens")
        if emoji_tokens:
            body = (body + " " + " ".join(emoji_tokens)).strip()
        edit_message_id = int(request.form.get("edit_message_id") or 0)
        if edit_message_id:
            message = ChatMessage.query.get_or_404(edit_message_id)
            if message.sender_id != current_user.id or message.deleted_at:
                flash("You can only edit your own messages.", "danger")
                return redirect(url_for("chats.chats"))
            if not body:
                flash("Message cannot be empty.", "warning")
                return redirect(url_for("chats.chats"))
            message.body_encrypted = encrypt_text(body)
            audit("chat_message_edited", f"Chat message #{message.id} edited by sender.", current_user.id)
            db.session.commit()
            return redirect(url_for("chats.chats"))
        if not body and not (file and file.filename):
            flash("Message cannot be empty.", "warning")
            return redirect(url_for("chats.chats"))
        message = ChatMessage(sender_id=current_user.id, body_encrypted=encrypt_text(body))
        reply_to_id = int(request.form.get("reply_to_id") or 0)
        if reply_to_id and ChatMessage.query.get(reply_to_id):
            message.reply_to_id = reply_to_id
        if file and file.filename:
            try:
                original, stored, kind = save_chat_zip(file)
            except ValueError:
                flash("Unsupported attachment type.", "danger")
                return redirect(url_for("chats.chats"))
            message.attachment_name = original
            message.attachment_path = stored
            message.attachment_kind = kind
        db.session.add(message)
        notify_roles(CHAT_ROLES, "chats", f"{current_user.full_name} sent a chat message.", url_for("chats.chats"))
        audit("chat_message_sent", "Encrypted chat message sent.", current_user.id)
        db.session.commit()
        return redirect(url_for("chats.chats"))

    db.session.commit()
    context = chat_context(unread_since)
    if request.args.get("partial") == "stream":
        return render_template("chats/_stream.html", **context)
    return render_template("chats.html", **context)


@chats_bp.route("/chats/<int:message_id>/delete", methods=["POST"])
@roles_required(*CHAT_ROLES)
def delete_message(message_id):
    message = ChatMessage.query.get_or_404(message_id)
    if message.sender_id != current_user.id:
        flash("You can only delete your own messages.", "danger")
        return redirect(url_for("chats.chats"))
    message.deleted_at = utcnow()
    audit("chat_message_deleted", f"Chat message #{message.id} deleted by sender.", current_user.id)
    db.session.commit()
    return redirect(url_for("chats.chats"))


@chats_bp.route("/chats/<int:message_id>/react", methods=["POST"])
@roles_required(*CHAT_ROLES)
def react_message(message_id):
    message = ChatMessage.query.get_or_404(message_id)
    if message.deleted_at:
        return jsonify({"ok": False, "error": "deleted"}), 400
    emoji = request.form.get("emoji", "")
    if emoji not in chat_emojis():
        return jsonify({"ok": False, "error": "invalid_emoji"}), 400
    existing = ChatReaction.query.filter_by(message_id=message.id, user_id=current_user.id, emoji=emoji).first()
    reacted = existing is None
    if existing:
        db.session.delete(existing)
    else:
        db.session.add(ChatReaction(message_id=message.id, user_id=current_user.id, emoji=emoji))
    db.session.commit()
    return jsonify({"ok": True, "message_id": message.id, "emoji": emoji, "reacted": reacted, "reactions": reaction_summary([message.id]).get(message.id, [])})


@chats_bp.route("/chats/settings", methods=["GET", "POST"])
@roles_required("Admin")
def chat_settings():
    if request.method == "POST":
        action = request.form.get("action")
        emojis = chat_emojis()
        if action == "add_emoji":
            emoji = (request.form.get("emoji") or "").strip()
            if emoji and emoji not in emojis and len(emoji) <= 12:
                emojis.append(emoji)
                save_chat_emojis(emojis)
                audit("chat_emoji_added", "Chat emoji added.", current_user.id)
                db.session.commit()
                flash("Emoji added.", "success")
            else:
                flash("Emoji already exists or is invalid.", "warning")
        elif action == "delete_emoji":
            emoji = request.form.get("emoji")
            if emoji in emojis and len(emojis) > 1:
                emojis = [item for item in emojis if item != emoji]
                save_chat_emojis(emojis)
                audit("chat_emoji_deleted", "Chat emoji deleted.", current_user.id)
                db.session.commit()
                flash("Emoji deleted.", "success")
        elif action == "upload_emoji":
            file = request.files.get("emoji_file")
            if file and file.filename:
                try:
                    original, stored, _ = save_upload(file, "chat_emojis")
                except ValueError as exc:
                    flash(str(exc), "danger")
                    return redirect(url_for("chats.chat_settings"))
                key = f"file:{stored}:{original[:40]}"
                if key not in emojis:
                    emojis.append(key)
                    save_chat_emojis(emojis)
                    audit("chat_emoji_uploaded", "Chat emoji uploaded.", current_user.id)
                    db.session.commit()
                    flash("Emoji uploaded.", "success")
        elif action == "delete_all":
            ChatReaction.query.delete()
            ChatMessage.query.delete()
            audit("chat_messages_deleted", "Admin deleted all chat messages.", current_user.id)
            db.session.commit()
            flash("All chats deleted.", "success")
        return redirect(url_for("chats.chat_settings"))
    return render_template("chats_settings.html", emojis=chat_emojis(), emoji_html=emoji_html)


@chats_bp.route("/chats/attachments/<path:filename>")
@roles_required(*CHAT_ROLES)
def download_attachment(filename):
    folder = os.path.join(current_app.config["UPLOAD_FOLDER"], "chat_archives")
    return send_from_directory(folder, filename, as_attachment=True)


@chats_bp.route("/chats/attachments/<path:filename>/preview")
@roles_required(*CHAT_ROLES)
def preview_attachment(filename):
    folder = os.path.abspath(os.path.join(current_app.config["UPLOAD_FOLDER"], "chat_archives"))
    path = os.path.abspath(os.path.join(folder, filename))
    if not path.startswith(folder + os.sep):
        return ("Not found", 404)
    with zipfile.ZipFile(path) as archive:
        names = [name for name in archive.namelist() if not name.endswith("/")]
        if not names:
            return ("Not found", 404)
        original = names[0]
        data = archive.read(original)
    mimetype = mimetypes.guess_type(original)[0] or "application/octet-stream"
    return send_file(BytesIO(data), mimetype=mimetype, download_name=original, as_attachment=False)


@chats_bp.route("/chats/emojis/<path:filename>")
@roles_required(*CHAT_ROLES)
def chat_emoji_file(filename):
    folder = os.path.join(current_app.config["UPLOAD_FOLDER"], "chat_emojis")
    return send_from_directory(folder, filename)


def chat_context(unread_since=None):
    items = ChatMessage.query.order_by(ChatMessage.created_at.asc()).limit(200).all()
    users = [
        user
        for user in User.query.filter(User.is_active.is_(True)).order_by(User.full_name).all()
        if role_allows(user.role, *CHAT_ROLES)
    ]
    return {
        "messages": items,
        "users": users,
        "reactions": reaction_summary([message.id for message in items]),
        "emojis": chat_emojis(),
        "emoji_html": emoji_html,
        "decrypt_text": decrypt_text,
        "render_chat_body": lambda text: render_chat_body(text, users),
        "unread_since": unread_since,
        "chat_roles": role_config(),
    }


def save_chat_zip(file):
    original = safe_original_name(file.filename)
    ext = original.rsplit(".", 1)[1].lower() if "." in original else ""
    if ext not in ALLOWED_CHAT_EXTENSIONS:
        raise ValueError("Unsupported attachment type.")
    data = file.read()
    if len(data) > current_app.config.get("MAX_CONTENT_LENGTH", 25 * 1024 * 1024):
        raise ValueError("Attachment is too large.")
    stored = random_filename(f"{original}.zip")
    folder = os.path.join(current_app.config["UPLOAD_FOLDER"], "chat_archives")
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, stored)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(original, data)
    kind = "video" if ext in {"mp4", "webm", "mov"} else "audio" if ext in {"mp3", "wav", "ogg"} else "image" if ext in {"png", "jpg", "jpeg", "gif", "webp"} else "file"
    return original, stored, kind


def reaction_summary(message_ids):
    if not message_ids:
        return {}
    rows = (
        db.session.query(ChatReaction.message_id, ChatReaction.emoji, func.count(ChatReaction.id))
        .filter(ChatReaction.message_id.in_(message_ids))
        .group_by(ChatReaction.message_id, ChatReaction.emoji)
        .all()
    )
    mine = {
        (reaction.message_id, reaction.emoji)
        for reaction in ChatReaction.query.filter(ChatReaction.message_id.in_(message_ids), ChatReaction.user_id == current_user.id).all()
    }
    grouped = defaultdict(list)
    for message_id, emoji, count in rows:
        grouped[message_id].append({"emoji": emoji, "html": str(emoji_html(emoji)), "count": count, "reacted": (message_id, emoji) in mine})
    return grouped


def chat_emojis():
    try:
        raw = setting("chat_emojis", None)
        saved = json.loads(raw) if raw else None
    except json.JSONDecodeError:
        saved = None
    source = saved if isinstance(saved, list) and saved else list(DEFAULT_CHAT_EMOJIS)
    emojis = []
    for emoji in source:
        if emoji and emoji not in emojis:
            emojis.append(emoji)
    return emojis


def save_chat_emojis(emojis):
    set_setting("chat_emojis", json.dumps(emojis, ensure_ascii=False))


def render_chat_body(text, users):
    rendered = render_chat_mentions(text, users)
    for emoji in sorted((item for item in chat_emojis() if item.startswith("file:")), key=len, reverse=True):
        rendered = Markup(str(rendered).replace(str(escape(emoji)), str(emoji_html(emoji))))
    return rendered


def emoji_html(emoji):
    if emoji.startswith("file:"):
        parts = emoji.split(":", 2)
        if len(parts) >= 2:
            return Markup('<img class="custom-emoji" src="') + escape(url_for("chats.chat_emoji_file", filename=parts[1])) + Markup('" alt="emoji">')
    return escape(emoji)
