import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "server/users.sqlite3"

def validarPath(DB):
  if not DB.exists():
    raise FileNotFoundError("Erro: Arquivo não encontrado.")
  else:
    print("DB encontrado.")
    return True

sql = "INSERT OR IGNORE INTO users (name, email, password_hash) VALUES ('Admin', 'admin@admin.com', 'admin123@');"

def query(DB, sql):
  if validarPath(DB):
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()
    cursor.execute(sql)
    conn.commit()
    conn.close()
    print("Query executada com sucesso!")

query(DB, sql)
