"""Importer integration tests: SQLite stands in only for isolated repository logic."""
import app.models
from pathlib import Path
from sqlalchemy import BigInteger, create_engine, select, func
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.core.database import Base
from app.models.threat_indicator import ThreatIndicator
from scripts.import_indicators import import_csv

@compiles(BigInteger, 'sqlite')
def sqlite_bigint(_type, _compiler, **kw):
    return 'INTEGER'

def test_import_deduplicates_and_validates(tmp_path):
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    file = tmp_path / 'feed.csv'
    file.write_text('indicator_type,indicator_value,source_name,confidence_level,expires_at\n'
                    'DOMAIN,bad.example,feed-A,HIGH,\n'
                    'IP,198.51.100.1,feed-A,MEDIUM,\n'
                    'DOMAIN,invalid,feed-A,HIGH,\n')
    assert import_csv(file, factory) == {'created': 2, 'updated': 0, 'invalid': 1}
    assert import_csv(file, factory) == {'created': 0, 'updated': 2, 'invalid': 1}
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(ThreatIndicator)) == 2
    engine.dispose()
