
from sqlalchemy import text

from app.core.database import get_db


def test_database_dependency():
    dependency = get_db()

    try:
        db = next(dependency)
        result = db.execute(text("SELECT 1"))
        assert result.scalar_one() == 1
    finally:
        dependency.close()
