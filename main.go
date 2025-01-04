package main

import (
	"fmt"
	"log"
	"net/http"

	"ciphermemories/routes"

	"github.com/gorilla/mux"
)

func main() {
	fmt.Println("Hello, Memory!")

	// Executar migrações

	// Configurar rotas
	r := mux.NewRouter()
	routes.ConfigureRoutes(r)

	// Iniciar servidor
	log.Println("Servidor iniciado na porta 8080 em https://localhost")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatal("Erro ao iniciar servidor:", err)
	}
}
