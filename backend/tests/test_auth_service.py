
import pytest

from sqlalchemy import BigInteger, Integer, create_engine
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.core.security import hash_password
from app.models.administrator import Administrator
from app.services.auth_service import authenticate_admin


@compiles(BigInteger, "sqlite")
def compile_big_integer_sqlite(type_, compiler, **kw):
    return "INTEGER"


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(engine)

    with Session(engine) as session:
        yield session

    engine.dispose()


@pytest.fixture
def admin(db):
    administrator = Administrator(
        username="test_admin",
        password_hash=hash_password(
            "Strong-Test-Password-2026!"
        ),
        is_active=True,
    )

    db.add(administrator)
    db.commit()
    db.refresh(administrator)

    return administrator


def test_correct_admin_credentials(db, admin):
    result = authenticate_admin(
        db,
        "test_admin",
        "Strong-Test-Password-2026!",
    )

    assert result is not None
    assert result.admin_id == admin.admin_id


def test_wrong_password(db, admin):
    result = authenticate_admin(
        db,
        "test_admin",
        "Wrong-Password",
    )

    assert result is None


def test_unknown_admin(db):
    result = authenticate_admin(
        db,
        "unknown_admin",
        "Any-Password",
    )

    assert result is None


def test_inactive_admin(db, admin):
    admin.is_active = False
    db.commit()

    result = authenticate_admin(
        db,
        "test_admin",
        "Strong-Test-Password-2026!",
    )

    assert result is None
