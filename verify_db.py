"""
Database Verification Script
=============================
Verifies that `devices.db` has the correct schema and is the database
the application code is configured to use.

Run with:  python verify_db.py
"""

import sqlite3
import os
import sys


DB_NAME = "devices.db"
import os

print("=" * 60)
print("Database Verification")
print("=" * 60)
print("Current Working Directory:", os.getcwd())
print("Absolute Database Path:", os.path.abspath(DB_NAME))
print()
