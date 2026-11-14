import os
import subprocess
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import check_password_hash, generate_password_hash
import psycopg2
from psycopg2.extras import DictCursor

app = Flask(__name__)
app.secret_key = 'chave_secreta_didatica'

DB_HOST, DB_NAME, DB_USER, DB_PASS = "localhost", "controle_acesso", "postgres", "Nielkrotieh1@"

def get_db_connection():
    return psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)

def executar_snmp(ip, community, if_index, acao):
    oid = f"1.3.6.1.2.1.2.2.1.7.{if_index}"
    comando = ["java", "-cp", ".:snmp4j-3.8.2.jar", "GerenteSNMP", ip, community, oid, str(acao)]
    print("função foi chamada")
    try:
        resultado = subprocess.run(comando, capture_output=True, text=True)
        print(f"resultado: {' '.join(resultado.stdout.splitlines())}")
        return ("SUCESSO" in resultado.stdout), resultado.stdout
    except Exception as e:
        return False, str(e)

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login = request.form['login']
        senha = request.form['senha']
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)
        cur.execute("SELECT * FROM usuario WHERE login = %s", (login,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user:
            session['user_id'] = user['id_usuario']
            session['perfil'] = user['perfil']
            if user['perfil'] == 'admin':
                return redirect(url_for('admin_painel'))
            return redirect(url_for('painel'))
        flash("Login ou senha inválidos.")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/painel')
def painel():
    if 'user_id' not in session: return redirect(url_for('login'))

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    
    cur.execute('''SELECT s.id_sala, s.identificacao FROM sala s
                   JOIN usuario_sala us ON s.id_sala = us.id_sala
                   WHERE us.id_usuario = %s''', (session['user_id'],))
    salas = cur.fetchall()

    salas_ids = tuple([s['id_sala'] for s in salas]) if salas else (-1,)
    cur.execute('''SELECT c.id_pc, c.nome as pc_nome, c.ip, c.mac, c.acesso_internet, p.id_porta, p.nome as porta_nome, s.identificacao as sala_nome
                   FROM computador c
                   JOIN porta p ON c.id_porta = p.id_porta
                   JOIN sala s ON c.id_sala = s.id_sala
                   WHERE c.id_sala IN %s ORDER BY c.id_pc''', (salas_ids,))
    computadores = cur.fetchall()
    cur.close()
    conn.close()

    return render_template('painel.html', salas=salas, computadores=computadores)

@app.route('/acao_imediata', methods=['POST'])
def acao_imediata():
    print("função acao_imediata foi chamada")
    if 'user_id' not in session: return redirect(url_for('login'))
    print("função acao_imediata passou pela verificação de sessão")
    acao = request.form['acao'] # 'bloquear' ou 'desbloquear'
    alvo_tipo, alvo_id = request.form['alvo_tipo'], request.form['alvo_id']
    valor_snmp = 2 if acao == 'bloquear' else 1
    novo_status_internet = (acao == 'desbloquear')

    print(f"Executando ação imediata: {acao} para alvo_tipo: {alvo_tipo}, alvo_id: {alvo_id}")
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)

    query = '''SELECT c.id_pc, p.if_index, sw.ip, sw.snmp_community_rw, p.id_porta 
               FROM computador c JOIN porta p ON c.id_porta = p.id_porta
               JOIN switch sw ON p.id_switch = sw.id_switch
               WHERE {} AND p.bloqueavel = TRUE'''
    
    filtro = "c.id_pc = %s" if alvo_tipo == 'pc' else "c.id_sala = %s"
    print(f"Executando query com filtro: {filtro} e alvo_id: {alvo_id}")
    cur.execute(query.format(filtro), (alvo_id,))
    alvos = cur.fetchall()
    print(f"Alvos encontrados: {len(alvos)}")

    if not alvos:
        cur.close()
        conn.close()
        flash("Nenhum alvo bloqueável encontrado.", "warning")
        return redirect(url_for('painel'))

    sucessos = 0
    erros = []
    for alvo in alvos:
        sucesso, msg = executar_snmp(alvo['ip'], alvo['snmp_community_rw'], alvo['if_index'], valor_snmp)
        oid = f"1.3.6.1.2.1.2.2.1.7.{alvo['if_index']}"
        cur.execute('''INSERT INTO log_snmp (id_porta, acao, oid, valor, sucesso, mensagem)
                       VALUES (%s, %s, %s, %s, %s, %s)''', (alvo['id_porta'], acao, oid, valor_snmp, sucesso, msg))
        if sucesso:
            sucessos += 1
            cur.execute("UPDATE computador SET acesso_internet = %s, atualizado_em = NOW() WHERE id_pc = %s", 
                        (novo_status_internet, alvo['id_pc']))
        else:
            erros.append(msg.strip() if msg else "Erro desconhecido")
    
    conn.commit()
    cur.close()
    conn.close()

    if erros:
        msg_erro = ", ".join(set(erros))
        if sucessos == 0:
            flash(f"Falha ao executar {acao}: {msg_erro}", "danger")
        else:
            flash(f"Ação concluída parcialmente ({sucessos} sucesso(s), {len(erros)} falha(s)). Erro: {msg_erro}", "warning")
    else:
        flash(f"Ação de {acao} executada com sucesso!", "success")
    return redirect(url_for('painel'))

@app.route('/agendar', methods=['POST'])
def agendar():
    if 'user_id' not in session: return redirect(url_for('login'))

    id_sala, fim_em = request.form['id_sala'], request.form['fim_em']
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute('''INSERT INTO agendamento (id_usuario, id_sala, sala_inteira, fim_em, status)
                   VALUES (%s, %s, TRUE, %s, 'agendado') RETURNING id_agendamento''', 
                (session['user_id'], id_sala, fim_em))
    id_agendamento = cur.fetchone()[0]

    cur.execute('''INSERT INTO agendamento_alvo (id_agendamento, id_pc)
                   SELECT %s, id_pc FROM computador c
                   JOIN porta p ON c.id_porta = p.id_porta 
                   WHERE c.id_sala = %s AND p.bloqueavel = TRUE''', (id_agendamento, id_sala))
    conn.commit()
    cur.close()
    conn.close()
    flash("Bloqueio agendado. O sistema agendador aplicará a restrição automaticamente.", "success")
    return redirect(url_for('painel'))

# ==========================================
#   ADMINISTRAÇÃO (perfil 'admin')
# ==========================================

def requer_admin(f):
    """Decorator: só permite acesso se o usuário logado for admin."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session or session.get('perfil') != 'admin':
            flash('Acesso restrito a administradores.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

# --- DASHBOARD ---
@app.route('/admin')
@requer_admin
def admin_painel():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    cur.execute('SELECT COUNT(*) as n FROM usuario');    t_u  = cur.fetchone()['n']
    cur.execute('SELECT COUNT(*) as n FROM sala');       t_s  = cur.fetchone()['n']
    cur.execute('SELECT COUNT(*) as n FROM switch');     t_sw = cur.fetchone()['n']
    cur.execute('SELECT COUNT(*) as n FROM computador'); t_c  = cur.fetchone()['n']
    cur.close(); conn.close()
    return render_template('admin.html', t_u=t_u, t_s=t_s, t_sw=t_sw, t_c=t_c)

# --- USUÁRIOS ---
@app.route('/admin/usuarios')
@requer_admin
def admin_usuarios():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    cur.execute('SELECT * FROM usuario ORDER BY id_usuario')
    usuarios = cur.fetchall()
    cur.close(); conn.close()
    return render_template('admin_usuarios.html', usuarios=usuarios)

@app.route('/admin/usuarios/adicionar', methods=['POST'])
@requer_admin
def admin_usuario_add():
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('INSERT INTO usuario (login, senha_hash, nome, perfil) VALUES (%s,%s,%s,%s)',
                    (request.form['login'], generate_password_hash(request.form['senha']),
                     request.form['nome'], request.form['perfil']))
        conn.commit()
        flash('Usuário adicionado.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao adicionar: {e}', 'danger')
    cur.close(); conn.close()
    return redirect(url_for('admin_usuarios'))

@app.route('/admin/usuarios/editar/<int:id>', methods=['GET','POST'])
@requer_admin
def admin_usuario_edit(id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    if request.method == 'POST':
        try:
            if request.form.get('senha'):
                cur.execute('UPDATE usuario SET login=%s, senha_hash=%s, nome=%s, perfil=%s WHERE id_usuario=%s',
                            (request.form['login'], generate_password_hash(request.form['senha']),
                             request.form['nome'], request.form['perfil'], id))
            else:
                cur.execute('UPDATE usuario SET login=%s, nome=%s, perfil=%s WHERE id_usuario=%s',
                            (request.form['login'], request.form['nome'], request.form['perfil'], id))
            conn.commit()
            flash('Usuário atualizado.', 'success')
        except Exception as e:
            conn.rollback()
            flash(f'Erro ao atualizar: {e}', 'danger')
        cur.close(); conn.close()
        return redirect(url_for('admin_usuarios'))
    # GET: mostrar formulário de edição
    cur.execute('SELECT * FROM usuario ORDER BY id_usuario')
    usuarios = cur.fetchall()
    cur.execute('SELECT * FROM usuario WHERE id_usuario=%s', (id,))
    editando = cur.fetchone()
    cur.close(); conn.close()
    return render_template('admin_usuarios.html', usuarios=usuarios, editando=editando)

@app.route('/admin/usuarios/excluir/<int:id>', methods=['POST'])
@requer_admin
def admin_usuario_del(id):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('DELETE FROM usuario WHERE id_usuario=%s', (id,))
        conn.commit()
        flash('Usuário excluído.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao excluir: {e}', 'danger')
    cur.close(); conn.close()
    return redirect(url_for('admin_usuarios'))

# --- SALAS ---
@app.route('/admin/salas')
@requer_admin
def admin_salas():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    cur.execute('SELECT * FROM sala ORDER BY id_sala')
    salas = cur.fetchall()
    cur.close(); conn.close()
    return render_template('admin_salas.html', salas=salas)

@app.route('/admin/salas/adicionar', methods=['POST'])
@requer_admin
def admin_sala_add():
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('INSERT INTO sala (identificacao) VALUES (%s)', (request.form['identificacao'],))
        conn.commit()
        flash('Sala adicionada.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao adicionar: {e}', 'danger')
    cur.close(); conn.close()
    return redirect(url_for('admin_salas'))

@app.route('/admin/salas/editar/<int:id>', methods=['GET','POST'])
@requer_admin
def admin_sala_edit(id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    if request.method == 'POST':
        try:
            cur.execute('UPDATE sala SET identificacao=%s WHERE id_sala=%s',
                        (request.form['identificacao'], id))
            conn.commit()
            flash('Sala atualizada.', 'success')
        except Exception as e:
            conn.rollback()
            flash(f'Erro ao atualizar: {e}', 'danger')
        cur.close(); conn.close()
        return redirect(url_for('admin_salas'))
    cur.execute('SELECT * FROM sala ORDER BY id_sala')
    salas = cur.fetchall()
    cur.execute('SELECT * FROM sala WHERE id_sala=%s', (id,))
    editando = cur.fetchone()
    cur.close(); conn.close()
    return render_template('admin_salas.html', salas=salas, editando=editando)

@app.route('/admin/salas/excluir/<int:id>', methods=['POST'])
@requer_admin
def admin_sala_del(id):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('DELETE FROM sala WHERE id_sala=%s', (id,))
        conn.commit()
        flash('Sala excluída.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao excluir: {e}', 'danger')
    cur.close(); conn.close()
    return redirect(url_for('admin_salas'))

# --- SWITCHES ---
@app.route('/admin/switches')
@requer_admin
def admin_switches():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    cur.execute('SELECT * FROM switch ORDER BY id_switch')
    switches = cur.fetchall()
    cur.close(); conn.close()
    return render_template('admin_switches.html', switches=switches)

@app.route('/admin/switches/adicionar', methods=['POST'])
@requer_admin
def admin_switch_add():
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('INSERT INTO switch (ip, descricao, snmp_community_rw) VALUES (%s,%s,%s)',
                    (request.form['ip'], request.form['descricao'], request.form['snmp_community_rw']))
        conn.commit()
        flash('Switch adicionado.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao adicionar: {e}', 'danger')
    cur.close(); conn.close()
    return redirect(url_for('admin_switches'))

@app.route('/admin/switches/editar/<int:id>', methods=['GET','POST'])
@requer_admin
def admin_switch_edit(id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    if request.method == 'POST':
        try:
            cur.execute('UPDATE switch SET ip=%s, descricao=%s, snmp_community_rw=%s WHERE id_switch=%s',
                        (request.form['ip'], request.form['descricao'], request.form['snmp_community_rw'], id))
            conn.commit()
            flash('Switch atualizado.', 'success')
        except Exception as e:
            conn.rollback()
            flash(f'Erro ao atualizar: {e}', 'danger')
        cur.close(); conn.close()
        return redirect(url_for('admin_switches'))
    cur.execute('SELECT * FROM switch ORDER BY id_switch')
    switches = cur.fetchall()
    cur.execute('SELECT * FROM switch WHERE id_switch=%s', (id,))
    editando = cur.fetchone()
    cur.close(); conn.close()
    return render_template('admin_switches.html', switches=switches, editando=editando)

@app.route('/admin/switches/excluir/<int:id>', methods=['POST'])
@requer_admin
def admin_switch_del(id):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('DELETE FROM switch WHERE id_switch=%s', (id,))
        conn.commit()
        flash('Switch excluído.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao excluir: {e}', 'danger')
    cur.close(); conn.close()
    return redirect(url_for('admin_switches'))

# --- PORTAS ---
@app.route('/admin/portas')
@requer_admin
def admin_portas():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    cur.execute('''SELECT p.*, sw.descricao as switch_desc, sw.ip as switch_ip
                   FROM porta p JOIN switch sw ON p.id_switch = sw.id_switch
                   ORDER BY p.id_porta''')
    portas = cur.fetchall()
    cur.execute('SELECT id_switch, ip, descricao FROM switch ORDER BY id_switch')
    switches = cur.fetchall()
    cur.close(); conn.close()
    return render_template('admin_portas.html', portas=portas, switches=switches)

@app.route('/admin/portas/adicionar', methods=['POST'])
@requer_admin
def admin_porta_add():
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('INSERT INTO porta (id_switch, if_index, nome, categoria) VALUES (%s,%s,%s,%s)',
                    (request.form['id_switch'], request.form['if_index'],
                     request.form['nome'], request.form['categoria']))
        conn.commit()
        flash('Porta adicionada.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao adicionar: {e}', 'danger')
    cur.close(); conn.close()
    return redirect(url_for('admin_portas'))

@app.route('/admin/portas/editar/<int:id>', methods=['GET','POST'])
@requer_admin
def admin_porta_edit(id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    if request.method == 'POST':
        try:
            cur.execute('UPDATE porta SET id_switch=%s, if_index=%s, nome=%s, categoria=%s WHERE id_porta=%s',
                        (request.form['id_switch'], request.form['if_index'],
                         request.form['nome'], request.form['categoria'], id))
            conn.commit()
            flash('Porta atualizada.', 'success')
        except Exception as e:
            conn.rollback()
            flash(f'Erro ao atualizar: {e}', 'danger')
        cur.close(); conn.close()
        return redirect(url_for('admin_portas'))
    cur.execute('''SELECT p.*, sw.descricao as switch_desc, sw.ip as switch_ip
                   FROM porta p JOIN switch sw ON p.id_switch = sw.id_switch
                   ORDER BY p.id_porta''')
    portas = cur.fetchall()
    cur.execute('SELECT id_switch, ip, descricao FROM switch ORDER BY id_switch')
    switches = cur.fetchall()
    cur.execute('SELECT * FROM porta WHERE id_porta=%s', (id,))
    editando = cur.fetchone()
    cur.close(); conn.close()
    return render_template('admin_portas.html', portas=portas, switches=switches, editando=editando)

@app.route('/admin/portas/excluir/<int:id>', methods=['POST'])
@requer_admin
def admin_porta_del(id):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('DELETE FROM porta WHERE id_porta=%s', (id,))
        conn.commit()
        flash('Porta excluída.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao excluir: {e}', 'danger')
    cur.close(); conn.close()
    return redirect(url_for('admin_portas'))

# --- COMPUTADORES ---
@app.route('/admin/computadores')
@requer_admin
def admin_computadores():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    cur.execute('''SELECT c.*, s.identificacao as sala_nome, p.nome as porta_nome
                   FROM computador c
                   JOIN sala s ON c.id_sala = s.id_sala
                   JOIN porta p ON c.id_porta = p.id_porta
                   ORDER BY c.id_pc''')
    computadores = cur.fetchall()
    cur.execute('SELECT id_sala, identificacao FROM sala ORDER BY identificacao')
    salas = cur.fetchall()
    cur.execute('''SELECT p.id_porta, p.nome, sw.ip as switch_ip
                   FROM porta p JOIN switch sw ON p.id_switch = sw.id_switch
                   WHERE p.id_porta NOT IN (SELECT id_porta FROM computador)
                   ORDER BY p.id_porta''')
    portas_livres = cur.fetchall()
    cur.close(); conn.close()
    return render_template('admin_computadores.html', computadores=computadores,
                           salas=salas, portas_livres=portas_livres)

@app.route('/admin/computadores/adicionar', methods=['POST'])
@requer_admin
def admin_computador_add():
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('''INSERT INTO computador (id_sala, id_porta, nome, ip, mac)
                       VALUES (%s,%s,%s,%s,%s)''',
                    (request.form['id_sala'], request.form['id_porta'],
                     request.form['nome'], request.form['ip'], request.form['mac']))
        conn.commit()
        flash('Computador adicionado.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao adicionar: {e}', 'danger')
    cur.close(); conn.close()
    return redirect(url_for('admin_computadores'))

@app.route('/admin/computadores/editar/<int:id>', methods=['GET','POST'])
@requer_admin
def admin_computador_edit(id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    if request.method == 'POST':
        try:
            cur.execute('''UPDATE computador SET id_sala=%s, id_porta=%s, nome=%s, ip=%s, mac=%s
                           WHERE id_pc=%s''',
                        (request.form['id_sala'], request.form['id_porta'],
                         request.form['nome'], request.form['ip'], request.form['mac'], id))
            conn.commit()
            flash('Computador atualizado.', 'success')
        except Exception as e:
            conn.rollback()
            flash(f'Erro ao atualizar: {e}', 'danger')
        cur.close(); conn.close()
        return redirect(url_for('admin_computadores'))
    cur.execute('''SELECT c.*, s.identificacao as sala_nome, p.nome as porta_nome
                   FROM computador c JOIN sala s ON c.id_sala = s.id_sala
                   JOIN porta p ON c.id_porta = p.id_porta ORDER BY c.id_pc''')
    computadores = cur.fetchall()
    cur.execute('SELECT id_sala, identificacao FROM sala ORDER BY identificacao')
    salas = cur.fetchall()
    cur.execute('SELECT * FROM computador WHERE id_pc=%s', (id,))
    editando = cur.fetchone()
    # Portas livres + a porta atual do computador sendo editado
    cur.execute('''SELECT p.id_porta, p.nome, sw.ip as switch_ip
                   FROM porta p JOIN switch sw ON p.id_switch = sw.id_switch
                   WHERE p.id_porta NOT IN (SELECT id_porta FROM computador WHERE id_pc != %s)
                   ORDER BY p.id_porta''', (id,))
    portas_livres = cur.fetchall()
    cur.close(); conn.close()
    return render_template('admin_computadores.html', computadores=computadores,
                           salas=salas, portas_livres=portas_livres, editando=editando)

@app.route('/admin/computadores/excluir/<int:id>', methods=['POST'])
@requer_admin
def admin_computador_del(id):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('DELETE FROM computador WHERE id_pc=%s', (id,))
        conn.commit()
        flash('Computador excluído.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao excluir: {e}', 'danger')
    cur.close(); conn.close()
    return redirect(url_for('admin_computadores'))

# --- VÍNCULOS (Usuário↔Sala e Sala↔Switch) ---
@app.route('/admin/vinculos')
@requer_admin
def admin_vinculos():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    # Vínculos usuário ↔ sala
    cur.execute('''SELECT us.id_usuario, us.id_sala, u.nome as usuario_nome, u.login, s.identificacao as sala_nome
                   FROM usuario_sala us
                   JOIN usuario u ON us.id_usuario = u.id_usuario
                   JOIN sala s ON us.id_sala = s.id_sala
                   ORDER BY u.nome, s.identificacao''')
    vinculos_us = cur.fetchall()
    # Vínculos sala ↔ switch
    cur.execute('''SELECT ss.id_sala, ss.id_switch, s.identificacao as sala_nome, sw.ip, sw.descricao as switch_desc
                   FROM sala_switch ss
                   JOIN sala s ON ss.id_sala = s.id_sala
                   JOIN switch sw ON ss.id_switch = sw.id_switch
                   ORDER BY s.identificacao''')
    vinculos_ss = cur.fetchall()
    # Listas para os dropdowns
    cur.execute('SELECT id_usuario, nome, login FROM usuario ORDER BY nome')
    usuarios = cur.fetchall()
    cur.execute('SELECT id_sala, identificacao FROM sala ORDER BY identificacao')
    salas = cur.fetchall()
    cur.execute('SELECT id_switch, ip, descricao FROM switch ORDER BY id_switch')
    switches = cur.fetchall()
    cur.close(); conn.close()
    return render_template('admin_vinculos.html', vinculos_us=vinculos_us, vinculos_ss=vinculos_ss,
                           usuarios=usuarios, salas=salas, switches=switches)

@app.route('/admin/vinculos/usuario_sala/adicionar', methods=['POST'])
@requer_admin
def admin_vinc_us_add():
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('INSERT INTO usuario_sala (id_usuario, id_sala) VALUES (%s,%s)',
                    (request.form['id_usuario'], request.form['id_sala']))
        conn.commit()
        flash('Vínculo usuário → sala adicionado.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Erro: {e}', 'danger')
    cur.close(); conn.close()
    return redirect(url_for('admin_vinculos'))

@app.route('/admin/vinculos/usuario_sala/excluir', methods=['POST'])
@requer_admin
def admin_vinc_us_del():
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('DELETE FROM usuario_sala WHERE id_usuario=%s AND id_sala=%s',
                    (request.form['id_usuario'], request.form['id_sala']))
        conn.commit()
        flash('Vínculo removido.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Erro: {e}', 'danger')
    cur.close(); conn.close()
    return redirect(url_for('admin_vinculos'))

@app.route('/admin/vinculos/sala_switch/adicionar', methods=['POST'])
@requer_admin
def admin_vinc_ss_add():
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('INSERT INTO sala_switch (id_sala, id_switch) VALUES (%s,%s)',
                    (request.form['id_sala'], request.form['id_switch']))
        conn.commit()
        flash('Vínculo sala → switch adicionado.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Erro: {e}', 'danger')
    cur.close(); conn.close()
    return redirect(url_for('admin_vinculos'))

@app.route('/admin/vinculos/sala_switch/excluir', methods=['POST'])
@requer_admin
def admin_vinc_ss_del():
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('DELETE FROM sala_switch WHERE id_sala=%s AND id_switch=%s',
                    (request.form['id_sala'], request.form['id_switch']))
        conn.commit()
        flash('Vínculo removido.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Erro: {e}', 'danger')
    cur.close(); conn.close()
    return redirect(url_for('admin_vinculos'))

# --- LOGS SNMP ---
@app.route('/admin/logs')
@requer_admin
def admin_logs():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    cur.execute('''SELECT l.*, p.nome as porta_nome, sw.ip as switch_ip
                   FROM log_snmp l
                   JOIN porta p ON l.id_porta = p.id_porta
                   JOIN switch sw ON p.id_switch = sw.id_switch
                   ORDER BY l.executado_em DESC LIMIT 100''')
    logs = cur.fetchall()
    cur.close(); conn.close()
    return render_template('admin_logs.html', logs=logs)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
