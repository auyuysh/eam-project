import sqlite3
conn = sqlite3.connect("devices.db")
cursor = conn.cursor()
cursor.execute("UPDATE departments SET name = upper(name)")
cursor.execute("UPDATE asset_types SET name = upper(name)")
conn.commit()
conn.close()
print("Done")
exit()