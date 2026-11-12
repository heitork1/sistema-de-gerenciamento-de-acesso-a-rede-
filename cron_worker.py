import psycopg2
from psycopg2.extras import DictCursor
import subprocess

DB_HOST, DB_NAME, DB_USER, DB_PASS = "localhost", "controle_acesso", "postgres", "postgres"

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

def processar_agendamentos():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)

    # 1. Aplicar bloqueios agendados
    cur.execute("SELECT * FROM agendamento WHERE status = 'agendado' AND inicio_em <= NOW()")
    para_bloquear = cur.fetchall()

    for ag in para_bloquear:
        cur.execute('''SELECT c.id_pc, p.if_index, sw.ip, sw.snmp_community_rw, p.id_porta 
                       FROM agendamento_alvo aa JOIN computador c ON aa.id_pc = c.id_pc
                       JOIN porta p ON c.id_porta = p.id_porta JOIN switch sw ON p.id_switch = sw.id_switch
                       WHERE aa.id_agendamento = %s AND p.bloqueavel = TRUE''', (ag['id_agendamento'],))
        alvos = cur.fetchall()

        for alvo in alvos:
            sucesso, msg = executar_snmp(alvo['ip'], alvo['snmp_community_rw'], alvo['if_index'], 2)
            if sucesso: cur.execute("UPDATE computador SET acesso_internet = FALSE WHERE id_pc = %s", (alvo['id_pc'],))

        cur.execute("UPDATE agendamento SET status = 'ativo' WHERE id_agendamento = %s", (ag['id_agendamento'],))

    # 2. Desfazer bloqueios finalizados
    cur.execute("SELECT * FROM agendamento WHERE status = 'ativo' AND fim_em <= NOW()")
    para_desbloquear = cur.fetchall()

    for ag in para_desbloquear:
        cur.execute('''SELECT c.id_pc, p.if_index, sw.ip, sw.snmp_community_rw, p.id_porta 
                       FROM agendamento_alvo aa JOIN computador c ON aa.id_pc = c.id_pc
                       JOIN porta p ON c.id_porta = p.id_porta JOIN switch sw ON p.id_switch = sw.id_switch
                       WHERE aa.id_agendamento = %s AND p.bloqueavel = TRUE''', (ag['id_agendamento'],))
        alvos = cur.fetchall()

        for alvo in alvos:
            sucesso, msg = executar_snmp(alvo['ip'], alvo['snmp_community_rw'], alvo['if_index'], 1)
            if sucesso: cur.execute("UPDATE computador SET acesso_internet = TRUE WHERE id_pc = %s", (alvo['id_pc'],))

        cur.execute("UPDATE agendamento SET status = 'concluido' WHERE id_agendamento = %s", (ag['id_agendamento'],))

    conn.commit()
    cur.close()
    conn.close()

if __name__ == '__main__':
    processar_agendamentos()
