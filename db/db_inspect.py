import sqlite3
from tabulate import tabulate

def inspect_db(db_name="firewall.db"):
    try:
        conn = sqlite3.connect(db_name)
        cur = conn.cursor()

        print(f"\n🔍 Inspecting {db_name} ...\n")

        # List tables
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [t[0] for t in cur.fetchall()]
        if not tables:
            print("⚠️  No tables found in the database.")
            return

        print("📋 Tables found:")
        for t in tables:
            print(f"   - {t}")

        # Preview each table
        for t in tables:
            print(f"\n🧾 Table: {t}")
            cur.execute(f"PRAGMA table_info({t});")
            columns = [col[1] for col in cur.fetchall()]
            print("   Columns:", columns)

            cur.execute(f"SELECT * FROM {t} LIMIT 10;")
            rows = cur.fetchall()
            if rows:
                print(tabulate(rows, headers=columns, tablefmt="fancy_grid"))
            else:
                print("   (No records)")

        conn.close()
    except Exception as e:
        print("❌ Database inspection failed:", str(e))


if __name__ == "__main__":
    inspect_db("firewall.db")
