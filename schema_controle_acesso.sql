CREATE TYPE categoria_porta AS ENUM ('aluno','professor','uplink','datacenter');
CREATE TYPE acao_tipo       AS ENUM ('bloquear','desbloquear');
CREATE TYPE status_agend    AS ENUM ('agendado','ativo','concluido','cancelado','erro');
CREATE TYPE perfil_usuario  AS ENUM ('professor','admin');

CREATE TABLE sala (
  id_sala SERIAL PRIMARY KEY,
  identificacao TEXT NOT NULL UNIQUE
);

CREATE TABLE switch (
  id_switch SERIAL PRIMARY KEY,
  ip INET NOT NULL UNIQUE,
  descricao TEXT,
  snmp_community_rw TEXT NOT NULL
);

CREATE TABLE sala_switch (
  id_sala   INT REFERENCES sala(id_sala)     ON DELETE CASCADE,
  id_switch INT REFERENCES switch(id_switch) ON DELETE CASCADE,
  PRIMARY KEY (id_sala, id_switch)
);
CREATE TABLE porta (
  id_porta SERIAL PRIMARY KEY,
  id_switch INT NOT NULL REFERENCES switch(id_switch) ON DELETE CASCADE,
  if_index INT NOT NULL,
  nome TEXT,
  categoria categoria_porta NOT NULL DEFAULT 'aluno',
  id_switch_destino INT REFERENCES switch(id_switch),
  bloqueavel BOOLEAN GENERATED ALWAYS AS (categoria = 'aluno') STORED,
  UNIQUE (id_switch, if_index)
);
CREATE TABLE computador (
  id_pc SERIAL PRIMARY KEY,
  id_sala  INT NOT NULL REFERENCES sala(id_sala),
  id_porta INT NOT NULL UNIQUE REFERENCES porta(id_porta),
  nome TEXT NOT NULL,
  ip  INET NOT NULL,
  mac MACADDR NOT NULL UNIQUE,
  acesso_internet BOOLEAN NOT NULL DEFAULT TRUE,
  atualizado_em TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE usuario (
  id_usuario SERIAL PRIMARY KEY,
  login TEXT NOT NULL UNIQUE,
  senha_hash TEXT NOT NULL,
  nome TEXT,
  perfil perfil_usuario NOT NULL DEFAULT 'professor'
);

CREATE TABLE usuario_sala (
  id_usuario INT REFERENCES usuario(id_usuario) ON DELETE CASCADE,
  id_sala    INT REFERENCES sala(id_sala)       ON DELETE CASCADE,
  PRIMARY KEY (id_usuario, id_sala)
);
CREATE TABLE agendamento (
  id_agendamento SERIAL PRIMARY KEY,
  id_usuario INT NOT NULL REFERENCES usuario(id_usuario),
  id_sala    INT NOT NULL REFERENCES sala(id_sala),
  sala_inteira BOOLEAN NOT NULL DEFAULT FALSE,
  inicio_em TIMESTAMPTZ NOT NULL DEFAULT now(),
  fim_em    TIMESTAMPTZ NOT NULL,
  status status_agend NOT NULL DEFAULT 'agendado',
  criado_em TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (fim_em > inicio_em)
);

CREATE TABLE agendamento_alvo (
  id_agendamento INT REFERENCES agendamento(id_agendamento) ON DELETE CASCADE,
  id_pc INT REFERENCES computador(id_pc) ON DELETE CASCADE,
  PRIMARY KEY (id_agendamento, id_pc) 
);

CREATE TABLE log_snmp (
  id_log BIGSERIAL PRIMARY KEY,
  id_agendamento INT REFERENCES agendamento(id_agendamento) ON DELETE SET NULL,
  id_porta INT NOT NULL REFERENCES porta(id_porta) ON DELETE CASCADE,
  acao acao_tipo NOT NULL,
  oid TEXT NOT NULL,
  valor SMALLINT NOT NULL,
  sucesso BOOLEAN NOT NULL,
  mensagem TEXT,
  executado_em TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ON agendamento (status, inicio_em);
CREATE INDEX ON computador (id_sala);

CREATE FUNCTION fn_checa_alvo() RETURNS trigger AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM computador c JOIN porta p USING (id_porta)
                 WHERE c.id_pc = NEW.id_pc AND p.bloqueavel) THEN
    RAISE EXCEPTION 'PC % está em porta protegida', NEW.id_pc;
  END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE TRIGGER trg_checa_alvo BEFORE INSERT ON agendamento_alvo
  FOR EACH ROW EXECUTE FUNCTION fn_checa_alvo();
