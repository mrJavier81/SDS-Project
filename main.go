/*
'prac' es una base para el desarrollo de prácticas en clase con Go.

se puede compilar con "go build" en el directorio donde resida main.go

versión: 1.0

curso: 			**rellenar**
asignatura: 	**antes de**
estudiantes: 	**entregar**
*/
package main

import (
	"log"
	"os"
	"time"

	"prac/pkg/backup"
	"prac/pkg/client"
	"prac/pkg/server"
	"prac/pkg/ui"
)

func main() {

	// Creamos un logger con prefijo 'main' para identificar
	// los mensajes en la consola.
	log := log.New(os.Stdout, "[main] ", log.LstdFlags)

	// Canal para sincronizar el inicio de los servidores
	serverReady := make(chan bool, 2)

	// Inicia servidor en goroutine.
	log.Println("Iniciando servidor...")
	go func() {
		// Esperar a que termine la barra de progreso
		<-serverReady
		if err := server.Run(); err != nil {
			log.Fatalf("Error del servidor: %v\n", err)
		}
	}()

	// Iniciar servidor de respaldo en una goroutine
	go func() {
		// Esperar a que termine la barra de progreso
		<-serverReady
		backupServer, err := backup.NewBackupServer("data/backup.db")
		if err != nil {
			log.Fatalf("Error al iniciar el servidor de respaldo: %v\n", err)
		}
		backupServer.Start()
	}()

	// Esperamos un tiempo prudencial a que arranque el servidor.
	const totalSteps = 20
	for i := 1; i <= totalSteps; i++ {
		ui.PrintProgressBar(i, totalSteps, 30)
		time.Sleep(100 * time.Millisecond)
	}

	// Señalar que la barra de progreso ha terminado
	serverReady <- true
	serverReady <- true

	// Dar tiempo a que se inicie el servidor antes del cliente
	time.Sleep(1 * time.Second)

	// Inicia cliente.
	log.Println("Iniciando cliente...")
	client.Run()
}
