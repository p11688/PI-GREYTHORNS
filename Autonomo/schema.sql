-- Esquema do banco da ferramenta de verificação GreyThorns (MySQL 8)
-- Executar com: mysql -u root -p greythorns < schema.sql

CREATE TABLE IF NOT EXISTS usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    senha_hash VARCHAR(255) NOT NULL,
    contato_cifrado TEXT NULL,
    criado_em DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS execucoes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT NOT NULL,
    dominio VARCHAR(253) NOT NULL,
    observacoes_cifradas TEXT NULL,
    executado_em DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS resultados (
    id INT AUTO_INCREMENT PRIMARY KEY,
    execucao_id INT NOT NULL,
    verificacao VARCHAR(80) NOT NULL,
    status VARCHAR(10) NOT NULL CHECK (status IN ('ok', 'atencao', 'falha', 'erro')),
    gravidade VARCHAR(10) NOT NULL CHECK (gravidade IN ('info', 'baixa', 'media', 'alta')),
    detalhe VARCHAR(500) NULL,
    FOREIGN KEY (execucao_id) REFERENCES execucoes (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS logs_acesso (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT NULL,
    username_tentado VARCHAR(50) NULL,
    acao VARCHAR(30) NOT NULL,
    sucesso TINYINT(1) NOT NULL,
    criado_em DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
