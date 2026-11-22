import datetime as dt
import os
import secrets
from io import BytesIO
from pathlib import Path

from flask import Flask, abort, redirect, render_template, request, send_file, session, url_for

from . import ca, db


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "certforge-dev"),
        DATABASE=str(Path(app.instance_path) / "certforge.db"),
    )
    if test_config is not None:
        app.config.update(test_config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    ca.init_root(Path(app.instance_path) / "ca")
    app.teardown_appcontext(db.close_db)
    app.cli.add_command(db.init_db_command)

    with app.app_context():
        db.init_db()

    @app.get("/")
    def dashboard():
        return render_template("index.html")

    @app.route("/request", methods=["GET", "POST"])
    def submit_request():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(32)
        error = None
        if request.method == "POST":
            if not secrets.compare_digest(session["csrf"].encode(), request.form.get("csrf", "").encode()):
                abort(400)
            mode = request.form.get("mode", "generate")
            key = None
            try:
                if mode == "generate":
                    cn = request.form.get("cn", "").strip()
                    if not cn:
                        raise ValueError("enter a common name")
                    sans = request.form.get("sans", "").replace(",", " ").split()
                    org = request.form.get("org", "").strip() or None
                    key, csr = ca.make_csr(cn, sans, org)
                elif mode == "paste":
                    csr = request.form.get("csr", "").strip().encode("utf-8")
                else:
                    raise ValueError("choose a request mode")
                info = ca.parse_csr(csr)
            except ValueError:
                if mode == "generate":
                    error = "Enter a common name and valid DNS names or IP addresses."
                else:
                    error = "Enter a valid PEM signing request with a common name and a valid signature."
            else:
                conn = db.get_db()
                row = conn.execute(
                    "INSERT INTO requests (cn, sans, csr_pem, key_pem, created_at) VALUES (?, ?, ?, ?, ?)",
                    (info["cn"], ",".join(info["sans"]), csr.decode("utf-8"),
                     key.decode("utf-8") if key else None, dt.datetime.now(dt.timezone.utc).isoformat()),
                )
                conn.commit()
                session["request_id"] = row.lastrowid
                return redirect(url_for("request_done"))
        return render_template("request.html", error=error), 400 if error else 200

    @app.get("/request/done")
    def request_done():
        row = db.get_db().execute(
            "SELECT id, cn, state, key_pem IS NOT NULL AS has_key FROM requests WHERE id = ?",
            (session.get("request_id"),),
        ).fetchone()
        if row is None:
            return redirect(url_for("submit_request"))
        response = app.make_response(render_template("request_done.html", row=row))
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/request/key")
    def download_key():
        if "csrf" not in session or not secrets.compare_digest(
            session["csrf"].encode(), request.form.get("csrf", "").encode()
        ):
            abort(400)
        conn = db.get_db()
        row = conn.execute(
            "SELECT id, key_pem FROM requests WHERE id = ? AND key_pem IS NOT NULL",
            (session.get("request_id"),),
        ).fetchone()
        if row is None:
            abort(404)
        result = conn.execute(
            "UPDATE requests SET key_pem = NULL WHERE id = ? AND key_pem = ?",
            (row["id"], row["key_pem"]),
        )
        conn.commit()
        if result.rowcount != 1:
            abort(404)
        response = send_file(
            BytesIO(row["key_pem"].encode("utf-8")), mimetype="application/octet-stream",
            as_attachment=True, download_name=f"request-{row['id']}.key",
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    return app
