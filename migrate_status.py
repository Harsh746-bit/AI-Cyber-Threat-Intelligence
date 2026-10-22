
import sqlite3

db = sqlite3.connect("cyber_threats.db")

try:
    columns = db.execute("PRAGMA table_info(incidents)").fetchall()
    names = [column[1] for column in columns]

    if "status" in names:
        print("Status column already exists. No changes needed.")
    else:
        db.execute(
            "ALTER TABLE incidents "
            "ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'OPEN'"
        )
        db.commit()
        print("Migration successful: existing incidents set to OPEN")

finally:
    db.close()
