package main

import (
	"fmt"
	"log"
	"net/http"

	"ciphermemories/db"
	"ciphermemories/routes"

	"github.com/gorilla/mux"
)

func main() {
	fmt.Println("Hello, Memory!")

	// Conectar ao banco de dados
	conn, err := db.Connect()
	if err != nil {
		log.Fatal("Erro ao conectar ao banco de dados:", err)
	}
	defer conn.Close()

	// Executar migrações
	err = db.ExecuteMigrations(conn)
	if err != nil {
		log.Fatal("Erro ao executar migrações:", err)
	}

	// Configurar rotas
	r := mux.NewRouter()
	routes.ConfigureRoutes(r)

	// Iniciar servidor
	log.Println("Servidor iniciado na porta 8080 em https://localhost")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatal("Erro ao iniciar servidor:", err)
	}
}
