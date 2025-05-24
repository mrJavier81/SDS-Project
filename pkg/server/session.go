// package server contiene la lógica del servidor
package server

import (
	"encoding/json"
	"time"
)

// SessionInfo almacena información sobre la sesión de un usuario
type SessionInfo struct {
	Token      string    `json:"token"`
	ExpiresAt  time.Time `json:"expiresAt"`
	LastAccess time.Time `json:"lastAccess"`
}

// FailedLoginAttempt almacena información sobre intentos fallidos de inicio de sesión
type FailedLoginAttempt struct {
	Count       int       `json:"count"`
	LastAttempt time.Time `json:"lastAttempt"`
	Locked      bool      `json:"locked"`
	LockUntil   time.Time `json:"lockUntil"`
}

// IsLocked verifica si la cuenta está bloqueada
func (f *FailedLoginAttempt) IsLocked() bool {
	if f.Locked && time.Now().Before(f.LockUntil) {
		return true
	}
	// Si el tiempo de bloqueo ha pasado, desbloqueamos la cuenta
	if f.Locked && time.Now().After(f.LockUntil) {
		f.Locked = false
		return false
	}
	return false
}

// RegisterAttempt registra un intento fallido de inicio de sesión
func (f *FailedLoginAttempt) RegisterAttempt() {
	f.Count++
	f.LastAttempt = time.Now()

	// Si hay 5 o más intentos fallidos, bloqueamos la cuenta por 15 minutos
	if f.Count >= 5 {
		f.Locked = true
		f.LockUntil = time.Now().Add(15 * time.Minute)
	}
}

// Reset restablece el contador de intentos fallidos
func (f *FailedLoginAttempt) Reset() {
	f.Count = 0
	f.Locked = false
}

// IsExpired verifica si un token ha expirado
func (s *SessionInfo) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// UpdateLastAccess actualiza la marca de tiempo del último acceso
func (s *SessionInfo) UpdateLastAccess() {
	s.LastAccess = time.Now()
}

// ToJSON serializa la información de sesión a JSON
func (s *SessionInfo) ToJSON() ([]byte, error) {
	return json.Marshal(s)
}

// FromJSON deserializa la información de sesión desde JSON
func (s *SessionInfo) FromJSON(data []byte) error {
	return json.Unmarshal(data, s)
}
