import sqlite3

conn = sqlite3.connect('users.db')
c = conn.cursor()

c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        allowed_pages TEXT NOT NULL
    )
''')

# Substitua 'adminpassword' pela senha que você deseja para o administrador
admin_password = 'adminpassword'

c.execute('INSERT INTO users (username, password, allowed_pages) VALUES (?, ?, ?)',
          ('admin', admin_password, 'admin'))

conn.commit()
conn.close()
