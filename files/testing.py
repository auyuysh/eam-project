import sqlite3

conn = sqlite3.connect("devices.db")
cursor = conn.cursor()

cursor.execute("SELECT * FROM departments")

departments = cursor.fetchall()

for department in departments:
    print(department)

conn.close()