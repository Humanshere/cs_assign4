"""
init_db.py
Creates app.db with:
  - users table (for the SQL-injection / auth-bypass demo)
  - comments table (for the stored-XSS demo)
  - accounts table (for the CSRF money-transfer demo)
Run this once before starting the app:  python init_db.py
"""
import sqlite3

conn = sqlite3.connect("app.db")
cur = conn.cursor()

cur.execute("DROP TABLE IF EXISTS users")
cur.execute("""
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0
)
""")
cur.executemany(
    "INSERT INTO users (username, password, is_admin) VALUES (?,?,?)",
    [
        ("admin", "SuperSecret123", 1),
        ("alice", "alicepass", 0),
        ("bob", "bobpass", 0),
    ],
)

cur.execute("DROP TABLE IF EXISTS comments")
cur.execute("""
CREATE TABLE comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author TEXT NOT NULL,
    body TEXT NOT NULL
)
""")
cur.executemany(
    "INSERT INTO comments (author, body) VALUES (?,?)",
    [("alice", "This is a normal comment."), ("bob", "Nice app!")],
)

cur.execute("DROP TABLE IF EXISTS accounts")
cur.execute("""
CREATE TABLE accounts (
    username TEXT PRIMARY KEY,
    balance INTEGER NOT NULL
)
""")
cur.executemany(
    "INSERT INTO accounts (username, balance) VALUES (?,?)",
    [("alice", 1000), ("bob", 1000)],
)

conn.commit()
conn.close()
print("app.db created/reset.")
