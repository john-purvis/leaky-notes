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
from werkzeug.security import check_password_hash, generate_password_hash

DATABASE = "leaky.db"

app = Flask(__name__)

# Turn off automatic alphabetical sorting
app.config["JSON_SORT_KEYS"] = False

# The modern way to disable alphabetical key sorting in Flask 2.3+
app.json.sort_keys = False

def secure_existing_passwords():
    """This function is a utility to help migrate existing plaintext passwords
    in the database to hashed passwords. It should be run once after the
    application is updated to use hashed passwords.

    WARNING: This function will modify the database. Make sure to back up your
    data before running it.
    """
    db = get_db()
    users = db.execute("SELECT id, password FROM users").fetchall()
    for user in users:
        user_id = user["id"]
        plaintext_password = user["password"]
        hashed_password = hash_password(plaintext_password)
        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hashed_password, user_id)
        )
    db.commit()

def test_password_hashing():
    password = "SecretSpiceMix!2024"  # demo only, never use as a real password
    hash1 = generate_password_hash(password)
    hash2 = generate_password_hash(password)

    print("hash1:", hash1)
    print("hash2:", hash2)
    print("hashes_equal:", hash1 == hash2)

    password = "SecretSpiceMix!2024"   # demo only
    wrong    = "SecretSpiceMix!2023"   # close but wrong

    hash1 = generate_password_hash(password)
    print("hash1:", hash1)

    print("correct:", check_password_hash(hash1, password))
    print("wrong:  ", check_password_hash(hash1, wrong))

def hash_password(plaintext: str) -> str:
    if plaintext is None:
        return None
    return generate_password_hash(plaintext)

def verify_password(stored_hash: str, candidate: str) -> bool:
    if stored_hash is None:
        return False
    if candidate is None:
        return False
    return check_password_hash(stored_hash, candidate)

def current_user_id():
    token = request.headers.get("Authorization", "")
    if token.startswith("user-"):
        return int(token[len("user-"):])
    return None

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

@app.get("/")
def api_root():
    # Structure the dictionary with 'message' as the very first key
    response_data = {
        "message": (
            "Welcome to Leaky Notes API! This is a deliberately insecure notes"
            " API for demonstration purposes. Please use it responsibly and do not"
            " deploy it in production."
        ),
        "endpoints": {
            "DELETE /notes/<note_id>": (
                "Delete a note by ID. Requires Authorization header with token."
            ),
            "GET /notes": (
                "List all notes. Requires Authorization header with token."
            ),
            "PATCH /notes/<note_id>": (
                "Edit a note by ID. Requires Authorization header with token."
            ),
            "POST /login": (
                "Log in with 'username' and 'password' to receive a token."
            ),
            "POST /notes": (
                "Create a new note. Requires Authorization header with token."
            ),
            "POST /register": (
                "Register a new user with 'username' and 'password'."
            ),
        },
    }
    return jsonify(response_data)

@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    username, password = data.get("username"), data.get("password")
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    db = get_db()
    try:
        # FIXED: FLAW 1: the password is written straight to the database as plaintext.
        password_hash = hash_password(password)  # This hashes the password before storing it
        # we are continuing to store the plaintext password for demonstration purposes,
        # but in a real application, you should never store plaintext passwords.
        db.execute(
            "INSERT INTO users (username, password, password_hash) VALUES (?, ?, ?)",
            (username, password, password_hash)
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
    if row is None:
        # user does not exist
        return jsonify({"error": "bad credentials"}), 401
    # FIXED: FLAW 1 (cont.): plaintext comparison, because the stored value is plaintext.
    if not verify_password(row["password_hash"], password):
        return jsonify({"error": "bad credentials"}), 401
    # A "token" that is just the user id in the clear. Not how real auth works;
    # good enough to demonstrate the authorization flaw below.
    return jsonify({"token": f"user-{row['id']}"}), 200

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
    note = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if not note:
        return jsonify({"error": "note not found"}), 404
    if note["owner_id"] != user_id:
        return jsonify({"error": "access denied"}), 403
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
    check_note = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if not check_note:
        return jsonify({"error": "note not found"}), 404
    if check_note["owner_id"] != user_id:
        return jsonify({"error": "access denied"}), 403
    cur = db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    db.commit()
    if cur.rowcount == 0:
        return jsonify({"error": "note not found"}), 404
    return "", 204


if __name__ == "__main__":
    app.run(debug=True, port=5000)
