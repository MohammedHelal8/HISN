
import getpass
import sys
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1]),
)

from app.core.database import SessionLocal
from app.core.security import hash_password
from app.models.administrator import Administrator


def main():
    username = input("Admin username: ").strip()

    if not username or len(username) > 100:
        print("Username must contain 1-100 characters.")
        return

    password = getpass.getpass("Admin password: ")
    confirm = getpass.getpass("Confirm password: ")

    if password != confirm:
        print("Passwords do not match.")
        return

    if len(password) < 12:
        print("Password must contain at least 12 characters.")
        return

    with SessionLocal() as db:
        existing = db.scalar(
            select(Administrator).where(
                Administrator.username == username
            )
        )

        if existing is not None:
            print("Administrator username already exists.")
            return

        admin = Administrator(
            username=username,
            password_hash=hash_password(password),
            is_active=True,
        )

        db.add(admin)

        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            print("Could not create administrator.")
            return

        print("Administrator created successfully.")


if __name__ == "__main__":
    main()
