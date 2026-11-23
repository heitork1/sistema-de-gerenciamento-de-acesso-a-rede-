import psycopg2
from psycopg2.extras import DictCursor
import subprocess

CLASSPATH_SNMP = ".:snmp4j-3.8.2.jar:lib/mibble-parser-2.10.1.jar:lib/mibble-mibs-2.10.1.jar:lib/grammatica-1.6.jar"

DB_HOST, DB_NAME, DB_USER, DB_PASS = "localhost", "controle_acesso", "postgres", "Nielkrotieh1@"

def get_db_connection():
    return psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)

def executar_snmp(ip, community, if_index, acao):
    nome_acao = "bloquear" if acao == 2 else "desbloquear"
    comando = ["java", "-cp", CLASSPATH_SNMP, "GerenteSNMP", ip, community, str(if_index), nome_acao]
    try:
        resultado = subprocess.run(comando, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return ("SUCESSO" in resultado.stdout), resultado.stdout
    except Exception as e:
        return False, str(e)

def processar_agendamentos():
    print("[cron_worker] Conectando ao banco de dados...")
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)

    cur.execute("SELECT * FROM agendamento WHERE status = 'agendado' AND inicio_em <= NOW()")
    para_bloquear = cur.fetchall()
    print(f"[cron_worker] Agendamentos para bloquear encontrados: {len(para_bloquear)}")

    for ag in para_bloquear:
        cur.execute('''SELECT c.id_pc, c.nome as pc_nome, p.if_index, sw.ip, sw.snmp_community_rw, p.id_porta
                       FROM agendamento_alvo aa JOIN computador c ON aa.id_pc = c.id_pc
                       JOIN porta p ON c.id_porta = p.id_porta JOIN switch sw ON p.id_switch = sw.id_switch
                       WHERE aa.id_agendamento = %s AND p.bloqueavel = TRUE''', (ag['id_agendamento'],))
        alvos = cur.fetchall()
        print(f"[cron_worker] Agendamento #{ag['id_agendamento']}: {len(alvos)} alvo(s) bloqueável(is)")

        for alvo in alvos:
            print(f"[cron_worker] Bloqueando PC {alvo['pc_nome']} (porta {alvo['if_index']} no switch {alvo['ip']})...")
            sucesso, msg = executar_snmp(alvo['ip'], alvo['snmp_community_rw'], alvo['if_index'], 2)
            print(f"[cron_worker] Resultado SNMP: {'SUCESSO' if sucesso else 'FALHA'} ({msg.strip() if msg else ''})")
            oid = f"1.3.6.1.2.1.2.2.1.7.{alvo['if_index']}"
            cur.execute('''INSERT INTO log_snmp (id_agendamento, id_porta, acao, oid, valor, sucesso, mensagem)
                           VALUES (%s, %s, 'bloquear', %s, 2, %s, %s)''',
                        (ag['id_agendamento'], alvo['id_porta'], oid, sucesso, msg))
            if sucesso:
                cur.execute("UPDATE computador SET acesso_internet = FALSE, atualizado_em = NOW() WHERE id_pc = %s", (alvo['id_pc'],))

        cur.execute("UPDATE agendamento SET status = 'ativo' WHERE id_agendamento = %s", (ag['id_agendamento'],))
        print(f"[cron_worker] Agendamento #{ag['id_agendamento']} mudou para status 'ativo'")

    cur.execute("SELECT * FROM agendamento WHERE status = 'ativo' AND fim_em <= NOW()")
    para_desbloquear = cur.fetchall()
    print(f"[cron_worker] Agendamentos expirados para desbloquear: {len(para_desbloquear)}")

    for ag in para_desbloquear:
        cur.execute('''SELECT c.id_pc, c.nome as pc_nome, p.if_index, sw.ip, sw.snmp_community_rw, p.id_porta
                       FROM agendamento_alvo aa JOIN computador c ON aa.id_pc = c.id_pc
                       JOIN porta p ON c.id_porta = p.id_porta JOIN switch sw ON p.id_switch = sw.id_switch
                       WHERE aa.id_agendamento = %s AND p.bloqueavel = TRUE''', (ag['id_agendamento'],))
        alvos = cur.fetchall()
        print(f"[cron_worker] Agendamento #{ag['id_agendamento']}: {len(alvos)} alvo(s) para desbloquear")

        for alvo in alvos:
            print(f"[cron_worker] Desbloqueando PC {alvo['pc_nome']} (porta {alvo['if_index']} no switch {alvo['ip']})...")
            sucesso, msg = executar_snmp(alvo['ip'], alvo['snmp_community_rw'], alvo['if_index'], 1)
            print(f"[cron_worker] Resultado SNMP: {'SUCESSO' if sucesso else 'FALHA'} ({msg.strip() if msg else ''})")
            oid = f"1.3.6.1.2.1.2.2.1.7.{alvo['if_index']}"
            cur.execute('''INSERT INTO log_snmp (id_agendamento, id_porta, acao, oid, valor, sucesso, mensagem)
                           VALUES (%s, %s, 'desbloquear', %s, 1, %s, %s)''',
                        (ag['id_agendamento'], alvo['id_porta'], oid, sucesso, msg))
            if sucesso:
                cur.execute("UPDATE computador SET acesso_internet = TRUE, atualizado_em = NOW() WHERE id_pc = %s", (alvo['id_pc'],))

        cur.execute("UPDATE agendamento SET status = 'concluido' WHERE id_agendamento = %s", (ag['id_agendamento'],))
        print(f"[cron_worker] Agendamento #{ag['id_agendamento']} mudou para status 'concluido'")

    conn.commit()
    cur.close()
    conn.close()
    print("[cron_worker] Processamento finalizado com sucesso.")

if __name__ == '__main__':
    processar_agendamentos()
