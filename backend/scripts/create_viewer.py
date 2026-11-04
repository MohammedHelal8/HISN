
from getpass import getpass

from sqlalchemy import select

from app.core.database import SessionLocal
from app.core.security import hash_password
from app.models.administrator import Administrator


def main() -> None:
    username = "viewer"

    with SessionLocal() as db:
        existing = db.scalar(
            select(Administrator).where(
                Administrator.username == username
            )
        )

        if existing is not None:
            print("Viewer account already exists.")
            return

        password = getpass("Enter viewer password: ")
        confirmation = getpass("Confirm viewer password: ")

        if password != confirmation:
            print("Passwords do not match.")
            return

        if len(password) < 12:
            print("Password must contain at least 12 characters.")
            return

        user = Administrator(
            username=username,
            password_hash=hash_password(password),
            role="viewer",
            is_active=True,
        )

        db.add(user)
        db.commit()

        print("Viewer account created successfully.")


if __name__ == "__main__":
    main()
