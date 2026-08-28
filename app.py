"""Leaky Notes — a deliberately INSECURE notes API for BE104.

This app works. It also has real security holes on purpose. You will find and
demonstrate them with your own eyes, then fix the same kinds of holes in your
own Recipe Box API.

DO NOT deploy this or reuse its patterns. It exists to be broken.

Two flaws are planted here:
  1. Passwords are stored in PLAINTEXT (Unit 2 finds this before you learn hashing).
  2. Note editing/deleting has NO ownership check — any logged-in user can change
     anyone's notes (Unit 3 finds this before you enforce ownership).
"""

import sqlite3

from flask import Flask, g, jsonify, request

DATABASE = "leaky.db"

app = Flask(__name__)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    username, password = data.get("username"), data.get("password")
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    db = get_db()
    try:
        # FLAW 1: the password is written straight to the database as plaintext.
        db.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, password),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "username taken"}), 409
    return jsonify({"message": f"registered {username}"}), 201


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username, password = data.get("username"), data.get("password")
    row = get_db().execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    # FLAW 1 (cont.): plaintext comparison, because the stored value is plaintext.
    if row is None or row["password"] != password:
        return jsonify({"error": "bad credentials"}), 401
    # A "token" that is just the user id in the clear. Not how real auth works;
    # good enough to demonstrate the authorization flaw below.
    return jsonify({"token": f"user-{row['id']}"}), 200


def current_user_id():
    token = request.headers.get("Authorization", "")
    if token.startswith("user-"):
        return int(token[len("user-"):])
    return None


@app.post("/notes")
def create_note():
    user_id = current_user_id()
    if user_id is None:
        return jsonify({"error": "log in first"}), 401
    data = request.get_json(silent=True) or {}
    if not data.get("body"):
        return jsonify({"error": "body required"}), 400
    db = get_db()
    cur = db.execute(
        "INSERT INTO notes (owner_id, body) VALUES (?, ?)",
        (user_id, data["body"]),
    )
    db.commit()
    return jsonify({"id": cur.lastrowid, "owner_id": user_id, "body": data["body"]}), 201


@app.get("/notes")
def list_notes():
    rows = get_db().execute("SELECT * FROM notes ORDER BY id").fetchall()
    return jsonify([dict(r) for r in rows])


@app.patch("/notes/<int:note_id>")
def edit_note(note_id):
    user_id = current_user_id()
    if user_id is None:
        return jsonify({"error": "log in first"}), 401
    data = request.get_json(silent=True) or {}
    db = get_db()
    # FLAW 2: authentication is checked, but NOT authorization. We never confirm
    # that note_id belongs to user_id, so any logged-in user can edit any note.
    cur = db.execute(
        "UPDATE notes SET body = ? WHERE id = ?", (data.get("body", ""), note_id)
    )
    db.commit()
    if cur.rowcount == 0:
        return jsonify({"error": "note not found"}), 404
    return jsonify({"id": note_id, "body": data.get("body", "")})


@app.delete("/notes/<int:note_id>")
def delete_note(note_id):
    user_id = current_user_id()
    if user_id is None:
        return jsonify({"error": "log in first"}), 401
    db = get_db()
    # FLAW 2 (cont.): same missing ownership check on delete.
    cur = db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    db.commit()
    if cur.rowcount == 0:
        return jsonify({"error": "note not found"}), 404
    return "", 204


if __name__ == "__main__":
    app.run(debug=True, port=5001)
