package server

import (
	"fmt"
	"sync"
)

// Poll representa una encuesta con una pregunta, opciones y votos.
type Poll struct {
	ID       string         // Identificador único para la encuesta
	Question string         // La pregunta de la encuesta
	Options  map[string]int // Opciones y sus conteos de votos
	mu       sync.Mutex     // Mutex para manejar el acceso concurrente
}

// NewPoll crea una nueva encuesta con la pregunta y opciones dadas.
func NewPoll(id, question string, options []string) *Poll {
	pollOptions := make(map[string]int)
	for _, option := range options {
		pollOptions[option] = 0
	}
	return &Poll{
		ID:       id,
		Question: question,
		Options:  pollOptions,
	}
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
