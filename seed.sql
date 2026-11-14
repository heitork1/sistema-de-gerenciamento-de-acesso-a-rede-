-- Insere o usuário Professor (senha: 123)
INSERT INTO usuario (login, senha_hash, nome, perfil) 
VALUES ('prof', 'scrypt:32768:8:1$E6x6G8vjQ5Z$e0b0213d2f974eb050cfd58a5e0dfa2e6f47df4e650fc30a473f3c4c9256e6d1', 'Professor', 'professor') ON CONFLICT DO NOTHING;

-- Insere o usuário Admin (senha: admin123)
INSERT INTO usuario (login, senha_hash, nome, perfil) 
VALUES ('admin', 'scrypt:32768:8:1$yefkGLs81gJC8OSd$877b67a6fd5f47250d30b1d6251e2e042e21f78a115a2cca031d4ac47b256ce206d59a1dbd044677563033f6f98bc322778a408bff07d791a4ab3e59c2cb010f', 'Administrador', 'admin') ON CONFLICT DO NOTHING;

INSERT INTO sala (identificacao) VALUES ('F203') ON CONFLICT DO NOTHING;
INSERT INTO usuario_sala (id_usuario, id_sala) VALUES (1, 1) ON CONFLICT DO NOTHING;

-- Insere o Switch 
INSERT INTO switch (ip, descricao, snmp_community_rw) VALUES ('127.0.0.1', 'Switch F203 Principal', 'public') ON CONFLICT DO NOTHING;
INSERT INTO sala_switch (id_sala, id_switch) VALUES (1, 1) ON CONFLICT DO NOTHING;

-- Portas (A porta Fa0/1 do professor é protegida)
INSERT INTO porta (id_switch, if_index, nome, categoria) VALUES (1, 1, 'Fa0/1', 'professor') ON CONFLICT DO NOTHING;
INSERT INTO porta (id_switch, if_index, nome, categoria) VALUES (1, 2, 'Fa0/2', 'aluno') ON CONFLICT DO NOTHING;
INSERT INTO porta (id_switch, if_index, nome, categoria) VALUES (1, 3, 'Fa0/3', 'aluno') ON CONFLICT DO NOTHING;
INSERT INTO porta (id_switch, if_index, nome, categoria) VALUES (1, 24, 'Gi0/1', 'uplink') ON CONFLICT DO NOTHING;

-- Computadores
INSERT INTO computador (id_sala, id_porta, nome, ip, mac, acesso_internet) 
VALUES (1, 1, 'PC-Prof', '192.168.1.10', '00:11:22:33:44:55', true) ON CONFLICT DO NOTHING;

INSERT INTO computador (id_sala, id_porta, nome, ip, mac, acesso_internet) 
VALUES (1, 2, 'PC-Aluno-01', '192.168.1.11', 'AA:BB:CC:DD:EE:01', true) ON CONFLICT DO NOTHING;

INSERT INTO computador (id_sala, id_porta, nome, ip, mac, acesso_internet) 
VALUES (1, 3, 'PC-Aluno-02', '192.168.1.12', 'AA:BB:CC:DD:EE:02', true) ON CONFLICT DO NOTHING;
