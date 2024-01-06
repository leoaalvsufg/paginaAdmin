import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from functools import wraps

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_aleatoria'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Classe de usuário que armazena o ID e as páginas permitidas
class User(UserMixin):
    def __init__(self, id, allowed_pages):
        self.id = id
        self.allowed_pages = allowed_pages

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (user_id,))
    user_data = c.fetchone()
    conn.close()

    if user_data:
        user_id, _, allowed_pages = user_data
        return User(user_id, allowed_pages.split(','))
    return None


# Função para validar login
def validate_login(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
    user = c.fetchone()
    conn.close()

    return user is not None

# Carregar usuários e permissões do arquivo
def load_users():
    users = {}
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users')
    
    for row in c.fetchall():
        username, password, allowed_pages = row
        users[username] = {'password': password, 'allowed_pages': allowed_pages.split(',')}

    conn.close()
    return users

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if validate_login(username, password):
            user = load_user(username)
            login_user(user)
            print(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def home():
    return render_template('home.html', username=current_user.id)

def page_access_required(page_name):
    def decorator(fn):
        @wraps(fn)
        def decorated_function(*args, **kwargs):
            if page_name not in current_user.allowed_pages and 'admin' not in current_user.allowed_pages:
                return render_template('error.html', message='You do not have access to this page.')
            return fn(*args, **kwargs)
        return decorated_function
    return decorator


@app.route('/page1/<secao>/<loja>/<ano>', methods=['GET'])
@login_required
def page1(secao, loja, ano):
    user_permissions = current_user.allowed_pages  # Supondo que isso retorne a lista de permissões

    if has_access(user_permissions, 'page1', secao, loja, ano):
        return 'Page 1 - Accessible by users with permission'




@app.route('/page2')
@login_required
@page_access_required('page2')
def page2():
    return 'Page 2 - Accessible by users with permission'

@app.route('/page3')
@login_required
@page_access_required('page3')
def page3():
    return 'Page 3 - Accessible by users with permission'

@app.route('/admin', methods=['GET', 'POST'])
@login_required
@page_access_required('admin')
def admin():
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()

        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            pages = request.form['pages']

            try:
                c.execute('INSERT INTO users (username, password, allowed_pages) VALUES (?, ?, ?)',
                          (username, password, pages))
                conn.commit()
                flash('Usuário adicionado com sucesso!')
            except sqlite3.IntegrityError:
                flash('Erro: O nome de usuário já existe.')
            except Exception as e:
                flash(f'Erro ao adicionar usuário: {e}')

        # Buscar todos os usuários
        c.execute('SELECT username, allowed_pages FROM users')
        users_list = c.fetchall()

    except Exception as e:
        flash(f'Erro ao buscar usuários: {e}')
        users_list = []
    finally:
        conn.close()

    return render_template('admin.html', users=users_list)



@app.route('/change_password', methods=['POST'])
@login_required
@page_access_required('admin')
def change_password():
    username = request.form['username']
    new_password = request.form['new_password']

    # Alterar a senha do usuário no banco de dados
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('UPDATE users SET password = ? WHERE username = ?', (new_password, username))
    conn.commit()
    conn.close()

    flash('Senha alterada com sucesso!')
    return redirect(url_for('admin'))

@app.route('/delete_user', methods=['POST'])
@login_required
@page_access_required('admin')
def delete_user():
    username = request.form['username']

    # Excluir o usuário do banco de dados
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('DELETE FROM users WHERE username = ?', (username,))
    conn.commit()
    conn.close()

    flash('Usuário excluído com sucesso!')
    return redirect(url_for('admin'))

def has_access(user_permissions, page, secao, loja, ano):
    for perm in user_permissions:
        if 'page1' in perm:
            parts = perm.split(':')
            if len(parts) > 1:
                conditions = parts[1].split(',')
                secao_cond = [cond.split('=')[1] for cond in conditions if 'secao' in cond][0]
                loja_cond = [cond.split('=')[1] for cond in conditions if 'loja' in cond][0]

                secao_allowed = secao_cond == 'todas' or secao in secao_cond.split('|')
                loja_allowed = loja_cond == 'todas' or loja in loja_cond.split('|')
                
                if secao_allowed and loja_allowed:
                    return True
    return False

@app.route('/change_permissions', methods=['POST'])
@login_required
@page_access_required('admin')
def change_permissions():
    username = request.form['username']
    new_permissions = request.form['new_permissions']

    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('UPDATE users SET allowed_pages = ? WHERE username = ?', (new_permissions, username))
        conn.commit()
    except Exception as e:
        flash(f'Erro ao alterar permissões: {e}')
    finally:
        conn.close()

    flash('Permissões alteradas com sucesso!')
    return redirect(url_for('admin'))


if __name__ == '__main__':
    app.run(debug=False, port=8000)
