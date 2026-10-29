"""Server-rendered storage application routes."""

import base64

from flask import Flask, Response, abort, make_response, redirect, render_template, request, session, url_for

from .auth import check_csrf, configure_auth, csrf_token, require_login
from .config import Config, format_ist, format_utc, normalize_ip
from .crypto import IntegrityError, open_record_image, open_record_measured
from .identity import KeyRing
from .images import MAX_IMAGE_BYTES
from .records import RecordDenied, RecordMissing, list_records, read_record, read_record_history, save_record


def _source_ip() -> str:
    """Return the normalized socket peer address used by the shared services."""
    peer = request.remote_addr
    if not peer:
        return "unknown"
    try:
        return normalize_ip(peer)
    except ValueError:
        return "unknown"


def _template_context(**values) -> dict:
    """Supply the storage templates' authenticated identity and CSRF string."""
    return {
        **values,
        "username": session["username"],
        "csrf_token": csrf_token(),
    }


def _error_response(message: str, status: int, *, record_id=None, form=None):
    """Render a generic escaped storage error using the shared form template."""
    return render_template(
        "storage/form.html",
        **_template_context(
            form=form or {"title": "", "body": ""},
            record_id=record_id,
            error=message,
            message=message,
        ),
    ), status


def _record_error(error: Exception, *, record_id=None, form=None):
    if isinstance(error, RecordDenied):
        return _error_response("Record access denied", 403, record_id=record_id, form=form)
    if isinstance(error, RecordMissing):
        return _error_response("Record not found", 404, record_id=record_id, form=form)
    if isinstance(error, IntegrityError):
        return _error_response(
            "Record integrity verification failed", 409, record_id=record_id, form=form,
        )
    raise error


def _submitted_form() -> dict[str, str]:
    return {
        "title": request.form.get("title", ""),
        "body": request.form.get("body", ""),
    }


def _submitted_image() -> tuple[str, bytes | None, str | None]:
    """Read only the bounded upload and preserve the prior text-only request cap."""
    upload = request.files.get("image")
    raw = upload.stream.read(MAX_IMAGE_BYTES + 1) if upload is not None else b""
    if not raw and request.content_length is not None and request.content_length > 65_536:
        abort(413)
    action = request.form.get("image_action") or ("replace" if raw else "keep")
    return action, raw or None, upload.mimetype if raw else None


def _save(config: Config, keys: KeyRing, *, record_id: str | None, form: dict[str, str],
          image_action: str, image_bytes: bytes | None, image_mime: str | None):
    return save_record(
        config,
        keys,
        owner=session["username"],
        record_id=record_id,
        title=form["title"],
        body=form["body"],
        src_ip=_source_ip(),
        session_ref=session["session_ref"],
        image_action=image_action,
        image_bytes=image_bytes,
        image_mime=image_mime,
    )


def _image_response(value):
    """Keep owner image and evidence responses out of browser caches."""
    response = make_response(value)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def _version_image(config: Config, keys: KeyRing, *, record_id: str, version: int,
                   ciphertext: bool):
    try:
        history = read_record_history(
            config, keys, owner=session["username"], record_id=record_id,
            src_ip=_source_ip(), session_ref=session["session_ref"],
        )
        selected = next((row for row, _ in history if row["version"] == version), None)
        if selected is None:
            raise RecordMissing("Record version not found")
        image = open_record_image(keys, selected)
        if image is None:
            raise RecordMissing("Record image not found")
    except (RecordDenied, RecordMissing, IntegrityError) as error:
        return _image_response(_record_error(error, record_id=record_id))
    if ciphertext:
        return _image_response(Response(
            base64.b64encode(selected["image_ciphertext"]).decode("ascii"),
            mimetype="text/plain",
        ))
    mime, raw = image
    return _image_response(Response(raw, mimetype=mime))


def create_storage_app(config: Config, keys: KeyRing) -> Flask:
    """Create the storage website and register its ordinary record routes."""
    app = Flask(__name__, template_folder="templates")
    configure_auth(app, config, keys, required_role="user")
    app.config["MAX_CONTENT_LENGTH"] = MAX_IMAGE_BYTES + 65_536
    app.jinja_env.filters["utc"] = format_utc
    app.jinja_env.filters["ist"] = format_ist
    app.jinja_env.filters["b64"] = lambda value: base64.b64encode(value).decode("ascii")

    @app.after_request
    def _private_record_headers(response):
        if request.endpoint in {"record_image", "record_image_ciphertext"}:
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Content-Type-Options"] = "nosniff"
        elif request.endpoint in {"storage_list", "record_detail", "edit_record"}:
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    @require_login("user")
    def storage_list():
        try:
            records = list_records(
                config,
                keys,
                owner=session["username"],
                src_ip=_source_ip(),
                session_ref=session["session_ref"],
            )
        except IntegrityError as error:
            return _record_error(error)
        return render_template(
            "storage/list.html",
            **_template_context(records=records),
        )

    @app.route("/records/new", methods=["GET", "POST"])
    @require_login("user")
    def new_record():
        if request.method == "GET":
            return render_template(
                "storage/form.html",
                **_template_context(form={"title": "", "body": ""}, record_id=None, error=None),
            )

        check_csrf()
        form = _submitted_form()
        try:
            image_action, image_bytes, image_mime = _submitted_image()
            saved = _save(
                config, keys, record_id=None, form=form, image_action=image_action,
                image_bytes=image_bytes, image_mime=image_mime,
            )
        except ValueError as error:
            return _error_response(str(error), 400, form=form)
        return redirect(url_for("record_detail", record_id=saved["id"]), code=303)

    @app.get("/records/<record_id>")
    @require_login("user")
    def record_detail(record_id: str):
        try:
            history = read_record_history(
                config,
                keys,
                owner=session["username"],
                record_id=record_id,
                src_ip=_source_ip(),
                session_ref=session["session_ref"],
            )
            record, _ = history[0]
            plaintext, _image, read_timings = open_record_measured(keys, record)
        except (RecordDenied, RecordMissing, IntegrityError) as error:
            return _record_error(error, record_id=record_id)
        return render_template(
            "storage/detail.html",
            **_template_context(
                record=record, plaintext=plaintext, verified=True, history=history,
                read_timings=read_timings,
            ),
        )

    @app.get("/records/<record_id>/versions/<int:version>/image")
    @require_login("user")
    def record_image(record_id: str, version: int):
        return _version_image(config, keys, record_id=record_id, version=version, ciphertext=False)

    @app.get("/records/<record_id>/versions/<int:version>/image-ciphertext")
    @require_login("user")
    def record_image_ciphertext(record_id: str, version: int):
        return _version_image(config, keys, record_id=record_id, version=version, ciphertext=True)

    @app.route("/records/<record_id>/edit", methods=["GET", "POST"])
    @require_login("user")
    def edit_record(record_id: str):
        if request.method == "GET":
            try:
                _, plaintext = read_record(
                    config,
                    keys,
                    owner=session["username"],
                    record_id=record_id,
                    src_ip=_source_ip(),
                    session_ref=session["session_ref"],
                )
            except (RecordDenied, RecordMissing, IntegrityError) as error:
                return _record_error(error, record_id=record_id)
            return render_template(
                "storage/form.html",
                **_template_context(form=plaintext, record_id=record_id, error=None),
            )

        check_csrf()
        form = _submitted_form()
        try:
            image_action, image_bytes, image_mime = _submitted_image()
            saved = _save(
                config, keys, record_id=record_id, form=form, image_action=image_action,
                image_bytes=image_bytes, image_mime=image_mime,
            )
        except ValueError as error:
            return _error_response(str(error), 400, record_id=record_id, form=form)
        except (RecordDenied, RecordMissing, IntegrityError) as error:
            return _record_error(error, record_id=record_id, form=form)
        return redirect(url_for("record_detail", record_id=saved["id"]), code=303)

    return app
