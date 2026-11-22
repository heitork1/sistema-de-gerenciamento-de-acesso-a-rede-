# Controle de Acesso SNMP

Este projeto implementa um sistema de controle de acesso à Internet em laboratórios via protocolo SNMP, composto por uma interface web em Flask, um gerente SNMP em Java (SNMP4J) e um agendador em Python para o Crontab.

## Arquivos Necessários na Pasta Raiz

Além dos arquivos incluídos neste pacote (`app.py`, `cron_worker.py`, `GerenteSNMP.java`, `seed.sql` e a pasta `templates/`), adicione à pasta raiz:
- `schema_controle_acesso.sql` (script SQL de criação das tabelas do banco)
- `snmp4j-3.8.2.jar` (biblioteca compilada do SNMP4J)

## Passo a Passo de Implementação e Execução

### 1. Preparar o Banco de Dados
1. Instale o PostgreSQL e crie o banco de dados `controle_acesso`.
2. Restaure o arquivo base:
   ```bash
   psql -U postgres -d controle_acesso -f schema_controle_acesso.sql
   ```
3. Aplique os dados iniciais:
   ```bash
   psql -U postgres -d controle_acesso -f seed.sql
   ```

### 2. Compilar o Gerente SNMP (Java) e o tradudor da MIB
Assegure-se de que o JDK está instalado e o arquivo `snmp4j-3.8.2.jar` está na pasta do projeto:
```bash
javac -cp ".:snmp4j-3.8.2.jar:lib/mibble-parser-2.10.1.jar:lib/mibble-mibs-2.10.1.jar:lib/grammatica-1.6.jar" GerenteSNMP.java TraducaoMib.java```

### 3. Inicializar a Aplicação Web (Flask)
Instale as dependências Python necessárias e inicie o servidor:
```bash
pip install Flask psycopg2-binary Werkzeug
python3 app.py
```
Acesse `http://localhost:5000` via navegador. O usuário criado pelo `seed.sql` é `prof` e a senha é `123`.

### 4. Agendamento Automático via Crontab (Linux)
1. Abra o editor de tarefas cron:
   ```bash
   crontab -e
   ```
2. Adicione a seguinte linha (ajustando o diretório para o caminho real da sua pasta):
   ```bash
   * * * * * cd /caminho/do/projeto && python3 cron_worker.py >> /var/log/cron_snmp.log 2>&1
   ```

   https://docs.google.com/document/d/1dv82vO9ohveva5hoBajQraVbUtGw1RhiEHVJOidgoL8/edit?usp=sharing
   https://docs.google.com/document/d/1ynLLMjny2tN3oJUgVZbzZNll7wvIogUc-Td7zplE1JU/edit?usp=sharing
