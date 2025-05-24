package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Poll representa una encuesta con una pregunta, opciones y votos.
type Poll struct {
	ID          string          // Identificador único para la encuesta
	Question    string          // La pregunta de la encuesta
	Options     map[string]int  // Opciones y sus conteos de votos
	FechaInicio string          // Fecha de inicio de la encuesta
	FechaFin    string          // Fecha de fin de la encuesta
	Creador     string          // Usuario que creó la encuesta
	Estado      string          // Estado de la encuesta (abierta/cerrada)
	VoteHashes  map[string]bool // Registro de usuarios que han participado
}

// NewPoll crea una nueva encuesta con la pregunta y opciones dadas.
func NewPoll(id, question string, options []string, duracionHoras int, creador string) *Poll {
	pollOptions := make(map[string]int)
	for _, option := range options {
		pollOptions[option] = 0
	}

	pollEndDate := time.Now().Add(time.Duration(duracionHoras) * time.Hour).Format("2006-01-02 15:04:05")
	fechaInicio := time.Now().Format("2006-01-02 15:04:05")
	fmt.Printf("Creando poll con fecha limite %s y fecha de inicio %s\n", pollEndDate, fechaInicio)
	return &Poll{
		ID:          id,
		Question:    question,
		Options:     pollOptions,
		FechaInicio: fechaInicio,
		FechaFin:    pollEndDate,
		Creador:     creador,
		Estado:      "abierta",
		VoteHashes:  make(map[string]bool),
	}
}

// Funciones para generar el hash de voto

func GenerateVoteHash(username, pollID string, salt []byte) string {

	data := username + pollID + string(salt)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// Comprueba si el hash del usuario ya está registrado
func (p *Poll) HasVoted(voteHash string) bool {
	return p.VoteHashes[voteHash]
}

// Registra el hash de voto
func (p *Poll) RegisterVoteHash(voteHash string) {
	p.VoteHashes[voteHash] = true
}

// Vote permite a un usuario votar por una opción.
func (p *Poll) Vote(option string) error {

	if _, exists := p.Options[option]; !exists {
		return fmt.Errorf("la opción '%s' no existe", option)
	}
	p.Options[option]++
	return nil
}

// Results devuelve los resultados actuales de la encuesta.
func (p *Poll) Results() map[string]int {

	// Devuelve una copia de los resultados para evitar condiciones de carrera
	results := make(map[string]int)
	for option, votes := range p.Options {
		results[option] = votes
	}
	return results
}

func (p *Poll) ToJSON() ([]byte, error) {

	data, err := json.Marshal(p)
	if err != nil {
		fmt.Println("Error al convertir la encuesta a JSON:", err)
		return nil, err
	}
	fmt.Println("Encuesta en formato JSON:", string(data))
	return data, nil
}
