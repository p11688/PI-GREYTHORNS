-- Usuários de banco com privilégios mínimos (executar como root do MySQL).
-- As senhas abaixo são provisórias e devem ser substituídas na implantação.
-- A aplicação só precisa ler e inserir: não recebe UPDATE, DELETE nem DROP.

CREATE DATABASE IF NOT EXISTS greythorns CHARACTER SET utf8mb4;

CREATE USER IF NOT EXISTS 'gt_app'@'localhost' IDENTIFIED BY 'senha_app_provisoria';
GRANT SELECT, INSERT ON greythorns.* TO 'gt_app'@'localhost';

-- Usuário só para backup (somente leitura)
CREATE USER IF NOT EXISTS 'gt_backup'@'localhost' IDENTIFIED BY 'senha_backup_provisoria';
GRANT SELECT, LOCK TABLES ON greythorns.* TO 'gt_backup'@'localhost';

FLUSH PRIVILEGES;
