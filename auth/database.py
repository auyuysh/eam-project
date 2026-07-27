"""
Centralised Database Connection
================================

Single source of truth for all database connections.

Every module should import ``get_db`` from here instead of creating
its own connection.

Responsibilities
-----------------
- Create and return PostgreSQL connections via psycopg2.
- Connection pooling via psycopg2.pool.
- Centralised configuration from environment variables.
"""

import os
import logging
from contextlib import contextmanager

import psycopg2
import psycopg2.extras
import psycopg2.pool

logger = logging.getLogger("eam.db")

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "eam_db")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}",
)

# ---------------------------------------------------------------------------
# Connection pool (lazy initialised)
# ---------------------------------------------------------------------------

_pool: psycopg2.pool.ThreadedConnectionPool | None = None


class _PoolConnection:
    """Thin proxy that returns the real connection to the pool on ``close()``.

    Every cursor created through this proxy defaults to
    ``psycopg2.extras.RealDictCursor`` so that query results can be
    accessed with ``row['column']`` dict-style syntax.
    """

    __slots__ = ('_conn', '_pool', '_returned')

    def __init__(self, conn, pool):
        self._conn = conn
        self._pool = pool
        self._returned = False

    def close(self):
        if self._returned:
            return
        self._returned = True
        try:
            self._pool.putconn(self._conn)
        except Exception:
            logger.warning("Failed to return connection to pool")

    def cursor(self, name=None, cursor_factory=None, **kwargs):
        """Return a cursor, defaulting to RealDictCursor for dict-style access."""
        if cursor_factory is None:
            cursor_factory = psycopg2.extras.RealDictCursor
        if name is not None:
            return self._conn.cursor(name, cursor_factory=cursor_factory, **kwargs)
        return self._conn.cursor(cursor_factory=cursor_factory, **kwargs)

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def __setattr__(self, name, value):
        if name in ('_conn', '_pool', '_returned'):
            object.__setattr__(self, name, value)
        else:
            setattr(self._conn, name, value)

    def __repr__(self):
        return f"<_PoolConnection closed={self._returned}>"


def _get_pool() -> psycopg2.pool.ThreadedConnectionPool:
    """Return the shared connection pool, creating it on first call."""
    global _pool
    if _pool is None:
        _pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=2,
            maxconn=20,
            dsn=DATABASE_URL,
        )
        logger.info("PostgreSQL connection pool created (%s@%s:%s/%s)", DB_USER, DB_HOST, DB_PORT, DB_NAME)
    return _pool


def get_db():
    """
    Return a new PostgreSQL connection from the pool.

    Returns
    -------
    _PoolConnection
        A wrapper whose ``close()`` method returns the underlying
        connection to the pool instead of truly closing it.
    """
    pool = _get_pool()
    conn = pool.getconn()
    conn.autocommit = False
    return _PoolConnection(conn, pool)


def put_db(conn):
    """Return a connection to the pool."""
    global _pool
    if conn is None:
        return
    if isinstance(conn, _PoolConnection):
        conn.close()
        return
    if _pool is not None:
        try:
            _pool.putconn(conn)
        except Exception:
            logger.warning("Failed to return connection to pool")


def close_all():
    """Shut down the connection pool gracefully."""
    global _pool
    if _pool is not None:
        _pool.closeall()
        _pool = None
        logger.info("PostgreSQL connection pool closed")


# ---------------------------------------------------------------------------
# Convenience cursor helper
# ---------------------------------------------------------------------------

def dict_cursor(conn):
    """Return a RealDictCursor for the given connection."""
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


def plain_cursor(conn):
    """Return a regular cursor for the given connection."""
    return conn.cursor()


# ---------------------------------------------------------------------------
# Legacy alias – other modules import get_db from here
# ---------------------------------------------------------------------------
