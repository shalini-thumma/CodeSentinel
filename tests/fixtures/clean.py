import sqlite3


def find_account(connection: sqlite3.Connection, account_id: int):
    return connection.execute(
        "SELECT id, name FROM accounts WHERE id = ?", (account_id,)
    ).fetchone()