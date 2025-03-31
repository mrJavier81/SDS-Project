package server

import (
	"fmt"
	"sync"
	"time"
)

// Poll representa una encuesta con una pregunta, opciones y votos.
type Poll struct {
	ID           string          // Identificador único para la encuesta
	Question     string          // La pregunta de la encuesta
	Options      map[string]int  // Opciones y sus conteos de votos
	mu           sync.Mutex      // Mutex para manejar el acceso concurrente
	fechaInicio  string          // Fecha de inicio de la encuesta
	fechaFin     string          // Fecha de fin de la encuesta
	creador      string          // Usuario que creó la encuesta
	estado       string          // Estado de la encuesta (abierta/cerrada)
	participants map[string]bool // Registro de usuarios que han participado
}

// NewPoll crea una nueva encuesta con la pregunta y opciones dadas.
func NewPoll(id, question string, options []string, duracionHoras int, creador string) *Poll {
	pollOptions := make(map[string]int)
	for _, option := range options {
		pollOptions[option] = 0
	}

	pollEndDate := time.Now().Add(time.Duration(duracionHoras) * time.Hour).Format("2006-01-02 15:04:05")
	fechaInicio := time.Now().Format("2006-01-02 15:04:05")
	return &Poll{
		ID:           id,
		Question:     question,
		Options:      pollOptions,
		fechaInicio:  fechaInicio,
		fechaFin:     pollEndDate,
		creador:      creador,
		estado:       "abierta",
		participants: make(map[string]bool),
	}
}

// AddParticipant agrega un usuario al registro de participantes.
func (p *Poll) AddParticipant(user string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.participants[user] {
		return fmt.Errorf("el usuario '%s' ya ha participado", user)
	}

	p.participants[user] = true
	return nil
}

// HasParticipated verifica si un usuario ya ha participado.
func (p *Poll) HasParticipated(user string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.participants[user]
}

// Vote permite a un usuario votar por una opción.
func (p *Poll) Vote(option string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.Options[option]; !exists {
		return fmt.Errorf("la opción '%s' no existe", option)
	}
	p.Options[option]++
	return nil
}

// Results devuelve los resultados actuales de la encuesta.
func (p *Poll) Results() map[string]int {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Devuelve una copia de los resultados para evitar condiciones de carrera
	results := make(map[string]int)
	for option, votes := range p.Options {
		results[option] = votes
	}
	return results
}
