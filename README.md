# Leaky Notes ⚠️

**NOW FIXED...MISSION COMPLETE**

A small notes API that **works but is insecure on purpose**. You will break it,
prove the flaws to yourself, and then fix the same classes of flaw in your own
Recipe Box API.

> Never deploy this or copy its patterns into real code. It exists to be broken.

## Run it

```
python init_db.py
python app.py        # serves on http://127.0.0.1:5001
```

Requires Python 3.10+ and Flask (`pip install -r requirements.txt`).

## Your mission

**Unit 2 — the plaintext password flaw.** Register a user, then open the
database and look at what got stored:

```
curl -X POST http://127.0.0.1:5001/register -H "Content-Type: application/json" \
     -d '{"username":"you","password":"s3cret"}'
sqlite3 leaky.db "SELECT username, password FROM users;"
```

The passwords are sitting there in plaintext. Anyone who reads the database
reads every password. (You fix this in your own project with hashing.)

**Unit 3 — the missing access check.** Log in as one user and edit or delete a
DIFFERENT user's note:

```
# log in as bob -> {"token": "user-2"}
curl -X POST http://127.0.0.1:5001/login -H "Content-Type: application/json" \
     -d '{"username":"bob","password":"hunter2"}'

# bob deletes alice's note (id 1) — and it works. That is the bug.
curl -X DELETE http://127.0.0.1:5001/notes/1 -H "Authorization: user-2"
```

The app checks that you are logged in, but never that the note is yours. (You
fix this in your own project with ownership checks.)

Both flaws are commented in `app.py` as `FLAW 1` and `FLAW 2` — read them after
you have found them yourself.
