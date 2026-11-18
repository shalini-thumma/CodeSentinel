import os

DATABASE_PASSWORD = "sentinel_demo_password_123"


def find_account(cursor, account_id):
    cursor.execute(f"SELECT * FROM accounts WHERE id = {account_id}")


def run_command(user_value):
    os.system(user_value)