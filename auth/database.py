"""
Centralised Database Connection
================================

Single source of truth for all database connections within the
authentication package.

Every authentication module should import ``get_db`` from here
instead of creating its own SQLite connection.

Responsibilities
-----------------
- Create and return SQLite connections.
- Future: connection pooling, read replicas, migration helpers.
"""

import sqlite3

DB_NAME = "devices.db"


def get_db() -> sqlite3.Connection:
    """
    Return a new SQLite connection to the application database.

    Returns
    -------
    sqlite3.Connection
        A connection to the database defined by ``DB_NAME``.

    Notes
    -----
    Each call creates a fresh connection.  Callers are responsible for
    closing the connection when finished (preferably via ``try/finally``).
    """
    return sqlite3.connect(DB_NAME, timeout=10, check_same_thread=False)
