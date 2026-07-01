import sqlite3

conn = sqlite3.connect("devices.db")
cursor = conn.cursor()

cursor.execute("SELECT * FROM devices")

for row in cursor.fetchall():
    print(row)

conn.close()