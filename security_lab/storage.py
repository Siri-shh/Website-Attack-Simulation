"""Server-rendered storage application routes."""

from flask import Flask, redirect, render_template, request, session, url_for

from .auth import check_csrf, configure_auth, csrf_token, require_login
from .config import Config, format_utc, normalize_ip
from .crypto import IntegrityError
from .identity import KeyRing
from .records import RecordDenied, RecordMissing, list_records, read_record, save_record


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


def _save(config: Config, keys: KeyRing, *, record_id: str | None, form: dict[str, str]):
    return save_record(
        config,
        keys,
        owner=session["username"],
        record_id=record_id,
        title=form["title"],
        body=form["body"],
        src_ip=_source_ip(),
        session_ref=session["session_ref"],
    )


def create_storage_app(config: Config, keys: KeyRing) -> Flask:
    """Create the storage website and register its ordinary record routes."""
    app = Flask(__name__, template_folder="templates")
    configure_auth(app, config, keys, required_role="user")
    app.jinja_env.filters["utc"] = format_utc

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
            saved = _save(config, keys, record_id=None, form=form)
        except ValueError as error:
            return _error_response(str(error), 400, form=form)
        return redirect(url_for("record_detail", record_id=saved["id"]), code=303)

    @app.get("/records/<record_id>")
    @require_login("user")
    def record_detail(record_id: str):
        try:
            record, plaintext = read_record(
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
            "storage/detail.html",
            **_template_context(record=record, plaintext=plaintext, verified=True),
        )

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
            saved = _save(config, keys, record_id=record_id, form=form)
        except ValueError as error:
            return _error_response(str(error), 400, record_id=record_id, form=form)
        except (RecordDenied, RecordMissing, IntegrityError) as error:
            return _record_error(error, record_id=record_id, form=form)
        return redirect(url_for("record_detail", record_id=saved["id"]), code=303)

    return app
