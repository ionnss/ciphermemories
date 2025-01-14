// Package db gerencia a conexão e operações com o banco de dados PostgreSQL.
//
// Fornece:
//   - Conexão com o banco de dados
//   - Execução de migrações
//   - Gerenciamento de transações
package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/lib/pq" // Driver PostgreSQL
)

// DB é a conexão global com o banco de dados
var DB *sql.DB

// Connect inicializa e retorna uma conexão com o banco de dados.
//
// Utiliza variáveis de ambiente para configuração:
//   - DB_HOST: host do banco
//   - DB_PORT: porta
//   - DB_USER: usuário
//   - DB_PASSWORD: senha
//   - DB_NAME: nome do banco
//
// Retorna:
//   - error: erro se a conexão falhar
func Connect() error {
	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
	)

	// Tenta conectar ao banco de dados
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("erro ao conectar ao banco: %v", err)
	}

	// Verifica se a conexão está funcionando
	if err = db.Ping(); err != nil {
		return fmt.Errorf("erro ao pingar o banco: %v", err)
	}

	// Atribui a conexão à variável global
	DB = db

	return nil
}

// ExecuteMigrations executa os scripts de migração e cria as tabelas no banco
//
// Recebe:
//   - conn: conexão com o banco de dados
//
// Retorna:
//   - error: erro se a migração falhar
func ExecuteMigrations(conn *sql.DB) error {
	migrationFiles := []string{
		"db/001.users_table.sql",
		"db/002.memories_table.sql",
		"db/migrations/003.memories_manager.sql",
		//...
	}

	for _, file := range migrationFiles {
		content, err := os.ReadFile(file)
		if err != nil {
			log.Fatalf("Erro ao ler o arquivo de migração %s: %v", file, err)
		}

		// Inicia uma transação
		tx, err := conn.Begin()
		if err != nil {
			log.Fatalf("Erro ao iniciar transação para %s: %v", file, err)
		}

		_, err = tx.Exec(string(content))
		if err != nil {
			tx.Rollback()
			log.Fatalf("Erro ao executar o script de migração %s: %v", file, err)
		}

		if err = tx.Commit(); err != nil {
			log.Fatalf("Erro ao commitar migração %s: %v", file, err)
		}

		log.Printf("Migração executada com sucesso: %s", file)
	}

	return nil
}
