import sqlite3

conn = sqlite3.connect('banco.db')
cur = conn.cursor()

# Se quiser recriar do zero (apaga dados) substitua por DROP TABLE... (ver comentário)
cur.execute("""
CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    senha TEXT NOT NULL,
    reset_token TEXT,
    reset_token_expires INTEGER
)
""")

# Caso já exista sem as colunas, adiciona-as (safe)
try:
    cur.execute("ALTER TABLE usuarios ADD COLUMN reset_token TEXT")
except sqlite3.OperationalError:
    pass

try:
    cur.execute("ALTER TABLE usuarios ADD COLUMN reset_token_expires INTEGER")
except sqlite3.OperationalError:
    pass

conn.commit()
conn.close()
print("Banco criado/atualizado com sucesso!")

