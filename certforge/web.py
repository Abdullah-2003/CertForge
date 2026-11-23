import datetime as dt
import os
import secrets
from io import BytesIO
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from flask import Flask, abort, flash, redirect, render_template, request, send_file, session, url_for

from . import ca, db


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "certforge-dev"),
        DATABASE=str(Path(app.instance_path) / "certforge.db"),
        ADMIN_PASSWORD=os.environ.get("CERTFORGE_ADMIN_PASSWORD", "admin"),
    )
    if test_config is not None:
        app.config.update(test_config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    ca.init_root(Path(app.instance_path) / "ca")
    app.teardown_appcontext(db.close_db)
    app.cli.add_command(db.init_db_command)

    with app.app_context():
        db.init_db()

    @app.before_request
    def check_admin():
        if request.path != "/admin" and not request.path.startswith("/admin/"):
            return
        if request.endpoint != "admin_login" and not session.get("admin"):
            return redirect(url_for("admin_login"))
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(32)
        if request.method == "POST" and not secrets.compare_digest(
            session["csrf"].encode(), request.form.get("csrf", "").encode()
        ):
            abort(400)

    @app.after_request
    def admin_cache(response):
        if request.path == "/admin" or request.path.startswith("/admin/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.route("/admin/login", methods=["GET", "POST"])
    def admin_login():
        if session.get("admin"):
            return redirect(url_for("admin"))
        error = None
        if request.method == "POST":
            if secrets.compare_digest(
                app.config["ADMIN_PASSWORD"].encode(), request.form.get("password", "").encode()
            ):
                session["admin"] = True
                session["csrf"] = secrets.token_hex(32)
                return redirect(url_for("admin"))
            error = "Incorrect password."
        return render_template("admin_login.html", error=error), 401 if error else 200

    @app.post("/admin/logout")
    def admin_logout():
        session.pop("admin", None)
        session["csrf"] = secrets.token_hex(32)
        return redirect(url_for("admin_login"))

    @app.get("/admin")
    def admin():
        conn = db.get_db()
        pending = []
        for row in conn.execute("SELECT id, csr_pem, created_at FROM requests WHERE state = 'pending' ORDER BY id"):
            try:
                info = ca.parse_csr(row["csr_pem"].encode())
            except ValueError:
                info = None
            pending.append({"id": row["id"], "created_at": row["created_at"], "info": info})
        certs = conn.execute("SELECT serial, request_id, cn, not_after FROM certs ORDER BY not_before DESC").fetchall()
        return render_template("admin.html", pending=pending, certs=certs)

    @app.post("/admin/approve/<int:request_id>")
    def approve_request(request_id):
        conn = db.get_db()
        with conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM requests WHERE id = ?", (request_id,)).fetchone()
            if row is None:
                abort(404)
            if row["state"] != "pending":
                abort(409, description="request already processed")
            try:
                pem = ca.sign_csr(Path(app.instance_path) / "ca", row["csr_pem"].encode())
            except ValueError:
                abort(400, description="invalid signing request")
            cert = x509.load_pem_x509_certificate(pem)
            conn.execute(
                "INSERT INTO certs (serial, request_id, cn, issuer, not_before, not_after, pem) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (format(cert.serial_number, "x"), request_id,
                 cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
                 cert.issuer.rfc4514_string(), cert.not_valid_before_utc.isoformat(),
                 cert.not_valid_after_utc.isoformat(), pem.decode()),
            )
            conn.execute("UPDATE requests SET state = 'approved' WHERE id = ?", (request_id,))
        flash(f"Request #{request_id} approved.")
        return redirect(url_for("admin"))

    @app.post("/admin/reject/<int:request_id>")
    def reject_request(request_id):
        conn = db.get_db()
        with conn:
            result = conn.execute("UPDATE requests SET state = 'rejected' WHERE id = ? AND state = 'pending'", (request_id,))
            if result.rowcount != 1:
                if conn.execute("SELECT id FROM requests WHERE id = ?", (request_id,)).fetchone() is None:
                    abort(404)
                abort(409, description="request already processed")
        flash(f"Request #{request_id} rejected.")
        return redirect(url_for("admin"))

    @app.get("/certs/<serial>.pem")
    def download_cert(serial):
        row = db.get_db().execute("SELECT pem FROM certs WHERE serial = ?", (serial,)).fetchone()
        if row is None:
            abort(404)
        return send_file(
            BytesIO(row["pem"].encode()), mimetype="application/x-pem-file",
            as_attachment=True, download_name=f"{serial}.pem",
        )

    @app.get("/root.pem")
    def download_root():
        return send_file(
            Path(app.instance_path) / "ca" / "root.pem", mimetype="application/x-pem-file",
            as_attachment=True, download_name="root.pem",
        )

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
