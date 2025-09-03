from flask import Flask, render_template, request, redirect, session, url_for, flash, abort
import sqlite3, re, uuid, time, os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_aqui'
app.permanent_session_lifetime = timedelta(days=7)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "banco.db")

# ---------------- BANCO ----------------
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    if os.path.exists(DB_PATH):
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.execute("SELECT name FROM sqlite_master LIMIT 1;")
            conn.close()
        except sqlite3.DatabaseError:
            os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
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
    conn.commit()
    conn.close()

init_db()

# ---------------- VALIDAÇÕES ----------------
def validar_email(email):
    return re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", (email or "").strip()) is not None

def validar_senha(senha):
    if (len(senha or "") < 8 or
        not re.search(r"[A-Z]", senha or "") or
        not re.search(r"[0-9]", senha or "") or
        not re.search(r"[@$!%*#?&]", senha or "")):
        return False
    return True

# ---------------- ROTAS ----------------
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    usuario = conn.execute('SELECT id, nome, email FROM usuarios WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    return render_template('index.html', usuario=usuario)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = (request.form.get('email') or "").strip().lower()
        senha = request.form.get('senha') or ""
        lembrar = request.form.get('lembrar') == 'on'

        conn = get_db_connection()
        usuario = conn.execute('SELECT * FROM usuarios WHERE email = ?', (email,)).fetchone()
        conn.close()
        if usuario and check_password_hash(usuario['senha'], senha):
            session.clear()
            session['user_id'] = usuario['id']
            session['user_nome'] = usuario['nome']
            session.permanent = lembrar
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Email ou senha incorretos', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Sessão encerrada com segurança.', 'info')
    return redirect(url_for('login'))

@app.route('/create', methods=['GET', 'POST'])
def create():
    if request.method == 'POST':
        nome = (request.form.get('nome') or "").strip()
        email = (request.form.get('email') or "").strip().lower()
        senha = request.form.get('senha') or ""
        confirmar_senha = request.form.get('confirmar_senha') or ""

        if not validar_email(email):
            flash('Email inválido.', 'danger')
            return render_template('create.html')
        if senha != confirmar_senha:
            flash('As senhas não coincidem', 'danger')
            return render_template('create.html')
        if not validar_senha(senha):
            flash('Senha deve ter 8+ caracteres, 1 maiúscula, 1 número e 1 especial.', 'danger')
            return render_template('create.html')

        hashed = generate_password_hash(senha)
        try:
            conn = get_db_connection()
            conn.execute('INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)', (nome, email, hashed))
            conn.commit()
            conn.close()
            flash('Usuário criado com sucesso! Faça login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email já cadastrado', 'danger')
    return render_template('create.html')

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = (request.form.get('email') or "").strip().lower()
        conn = get_db_connection()
        usuario = conn.execute('SELECT * FROM usuarios WHERE email = ?', (email,)).fetchone()
        if usuario:
            token = str(uuid.uuid4())
            expires = int(time.time()) + 3600
            conn.execute('UPDATE usuarios SET reset_token = ?, reset_token_expires = ? WHERE id = ?', (token, expires, usuario['id']))
            conn.commit()
            reset_link = url_for("reset", token=token, _external=True)
            flash(f"[DEV] Link de redefinição: {reset_link}", "info")
        conn.close()
        flash('Se este email estiver cadastrado, você receberá um link para redefinir a senha.', 'info')
    return render_template('forgot.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset(token):
    now = int(time.time())
    conn = get_db_connection()
    usuario = conn.execute('SELECT * FROM usuarios WHERE reset_token = ?', (token,)).fetchone()
    if not usuario or not usuario['reset_token_expires'] or usuario['reset_token_expires'] < now:
        conn.close()
        flash('Token inválido ou expirado.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        senha = request.form.get('senha') or ""
        confirmar_senha = request.form.get('confirmar_senha') or ""
        if senha != confirmar_senha:
            flash('As senhas não coincidem', 'danger')
            return render_template('reset.html', token=token)
        if not validar_senha(senha):
            flash('Senha não atende aos requisitos de segurança.', 'danger')
            return render_template('reset.html', token=token)
        hashed = generate_password_hash(senha)
        conn.execute('UPDATE usuarios SET senha = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?', (hashed, usuario['id']))
        conn.commit()
        conn.close()
        flash('Senha redefinida com sucesso! Faça login.', 'success')
        return redirect(url_for('login'))
    conn.close()
    return render_template('reset.html', token=token)

@app.route('/account', methods=['GET', 'POST'])
def account():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    conn = get_db_connection()
    usuario = conn.execute('SELECT * FROM usuarios WHERE id = ?', (user_id,)).fetchone()

    if request.method == 'POST':
        nome = (request.form.get('nome') or "").strip()
        email = (request.form.get('email') or "").strip().lower()
        senha = request.form.get('senha') or ""
        confirmar_senha = request.form.get('confirmar_senha') or ""

        if not validar_email(email):
            flash('Email inválido.', 'danger')
            return render_template('account.html', usuario=usuario)

        if senha:
            if senha != confirmar_senha:
                flash('As senhas não coincidem', 'danger')
                return render_template('account.html', usuario=usuario)
            if not validar_senha(senha):
                flash('Senha não atende aos requisitos de segurança.', 'danger')
                return render_template('account.html', usuario=usuario)
            hashed = generate_password_hash(senha)
            query = 'UPDATE usuarios SET nome=?, email=?, senha=? WHERE id=?'
            params = (nome, email, hashed, user_id)
        else:
            query = 'UPDATE usuarios SET nome=?, email=? WHERE id=?'
            params = (nome, email, user_id)

        try:
            conn.execute(query, params)
            conn.commit()
            flash('Conta atualizada com sucesso!', 'success')
        except sqlite3.IntegrityError:
            flash('Este email já está em uso.', 'danger')
        finally:
            conn.close()
        session['user_nome'] = nome
        return redirect(url_for('account'))

    conn.close()
    return render_template('account.html', usuario=usuario)

# ---------------- RUN ----------------
if __name__ == '__main__':
    app.run(debug=True)
