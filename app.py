import os
import subprocess
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import check_password_hash
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
    try:
        resultado = subprocess.run(comando, capture_output=True, text=True)
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
            return redirect(url_for('painel'))
        flash("Login ou senha inválidos.")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
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
    if 'user_id' not in session: return redirect(url_for('login'))

    acao = request.form['acao'] # 'bloquear' ou 'desbloquear'
    alvo_tipo, alvo_id = request.form['alvo_tipo'], request.form['alvo_id']
    valor_snmp = 2 if acao == 'bloquear' else 1
    novo_status_internet = (acao == 'desbloquear')

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)

    query = '''SELECT c.id_pc, p.if_index, sw.ip, sw.snmp_community_rw, p.id_porta 
               FROM computador c JOIN porta p ON c.id_porta = p.id_porta
               JOIN switch sw ON p.id_switch = sw.id_switch
               WHERE {} AND p.bloqueavel = TRUE'''
    
    filtro = "c.id_pc = %s" if alvo_tipo == 'pc' else "c.id_sala = %s"
    cur.execute(query.format(filtro), (alvo_id,))
    alvos = cur.fetchall()

    for alvo in alvos:
        sucesso, msg = executar_snmp(alvo['ip'], alvo['snmp_community_rw'], alvo['if_index'], valor_snmp)
        oid = f"1.3.6.1.2.1.2.2.1.7.{alvo['if_index']}"
        cur.execute('''INSERT INTO log_snmp (id_porta, acao, oid, valor, sucesso, mensagem)
                       VALUES (%s, %s, %s, %s, %s, %s)''', (alvo['id_porta'], acao, oid, valor_snmp, sucesso, msg))
        if sucesso:
            cur.execute("UPDATE computador SET acesso_internet = %s, atualizado_em = NOW() WHERE id_pc = %s", 
                        (novo_status_internet, alvo['id_pc']))
    
    conn.commit()
    cur.close()
    conn.close()
    flash("Ação executada com sucesso!")
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
    flash("Bloqueio agendado. O sistema agendador aplicará a restrição automaticamente.")
    return redirect(url_for('painel'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
