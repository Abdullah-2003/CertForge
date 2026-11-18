import os
from pathlib import Path

from flask import Flask, render_template

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

    return app
