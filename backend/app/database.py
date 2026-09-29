import logging
from typing import Generator, Tuple
from sqlalchemy import create_engine, Engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from app.config import settings

logger = logging.getLogger(__name__)

Base = declarative_base()


def create_active_engine() -> Tuple[Engine, str]:
    """
    Attempts to connect to configured PostgreSQL.
    If PostgreSQL is unreachable or times out, falls back seamlessly to
    a local SQLite database (email_security.db) for frictionless development.
    """
    if settings.DATABASE_URL.startswith("postgresql"):
        try:
            pg_engine = create_engine(
                settings.DATABASE_URL,
                pool_pre_ping=True,
                pool_size=10,
                max_overflow=20,
                connect_args={"connect_timeout": 2},
            )
            with pg_engine.connect():
                logger.info("[✓] Successfully connected to PostgreSQL.")
                return pg_engine, "postgresql"
        except Exception as e:
            logger.warning(
                f"[!] PostgreSQL unreachable at {settings.DATABASE_URL} ({e}). "
                "Engaging local SQLite fallback for seamless development."
            )

    sqlite_url = "sqlite:///./email_security.db"
    sqlite_engine = create_engine(
        sqlite_url,
        connect_args={"check_same_thread": False},
    )
    return sqlite_engine, "sqlite"


engine, db_type = create_active_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> bool:
    """Creates database tables on the active database engine."""
    try:
        Base.metadata.create_all(bind=engine)
        logger.info(f"[✓] Database tables initialized on active engine: {db_type.upper()}.")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize database tables: {e}")
        return False
