import sqlite3

DB_NAME = "devices.db"

conn = sqlite3.connect(DB_NAME)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

cursor.execute("SELECT id, first_name, last_name, company_name, email, username, created_at FROM users ORDER BY id")
users = cursor.fetchall()
conn.close()

if not users:
    print("No users found in the database.")
else:
    print(f"Total registered users: {len(users)}")
    print()
    for u in users:
        print(f"ID:          {u['id']}")
        print(f"First Name:  {u['first_name']}")
        print(f"Last Name:   {u['last_name']}")
        print(f"Company:     {u['company_name']}")
        print(f"Email:       {u['email']}")
        print(f"Username:    {u['username']}")
        print(f"Created At:  {u['created_at']}")
        print("-" * 40)
