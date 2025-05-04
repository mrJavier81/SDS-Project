// El paquete server contiene el código del servidor.
// Interactúa con el cliente mediante una API JSON/HTTP
package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"prac/pkg/api"
	"prac/pkg/store"

	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"

	"strconv"

	"golang.org/x/crypto/bcrypt"
)

// server encapsula el estado de nuestro servidor
type server struct {
	db    store.Store      // base de datos
	log   *log.Logger      // logger para mensajes de error e información
	polls map[string]*Poll // polls es un mapa que contiene las encuestas activas
	//tokenCounter int64       // contador para generar tokens
	nextPollID int64 // ID para la próxima encuesta
}

// Run inicia la base de datos y arranca el servidor HTTP.
func Run() error {
	// Abrimos la base de datos usando el motor bbolt
	db, err := store.NewStore("bbolt", "data/server.db")
	if err != nil {
		return fmt.Errorf("error abriendo base de datos: %v", err)
	}

	// Creamos nuestro servidor con su logger con prefijo 'srv'
	srv := &server{
		db:    db,
		log:   log.New(os.Stdout, "[srv] ", log.LstdFlags),
		polls: make(map[string]*Poll),
	}

	// Inicializamos la lista de superadmins (esto es solo un ejemplo)
	superadmins := []string{"Mirri", "Saulet", "Fabix"}
	for _, superadmin := range superadmins {
		if err := srv.db.Put("superadmin", []byte(superadmin), []byte("true")); err != nil {
			return fmt.Errorf("error inicializando lista de superadmins: %v", err)
		}
	}

	// Al crear un nuevo rol, añadidlo a esta lista
	rolesValidos := []string{"superadmin", "admin", "user"}
	for _, role := range rolesValidos {
		if err := srv.db.Put("roles", []byte(role), []byte("")); err != nil {
			return fmt.Errorf("error inicializando roles: %v", err)
		}
	}

	// Al terminar, cerramos la base de datos
	defer srv.db.Close()

	// Construimos un mux y asociamos /api a nuestro apiHandler,
	mux := http.NewServeMux()
	mux.Handle("/api", http.HandlerFunc(srv.apiHandler))

	// Iniciamos el servidor HTTP.
	err = http.ListenAndServe(":8080", mux)

	return err
}

// apiHandler descodifica la solicitud JSON, la despacha
// a la función correspondiente y devuelve la respuesta JSON.
func (s *server) apiHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}

	// Decodificamos la solicitud en una estructura api.Request
	var req api.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Error en el formato JSON", http.StatusBadRequest)
		return
	}

	// Despacho según la acción solicitada
	var res api.Response
	switch req.Action {
	case api.ActionRegister:
		res = s.registerUser(req)
	case api.ActionLogin:
		res = s.loginUser(req)
	case api.ActionFetchData:
		res = s.fetchData(req)
	case api.ActionUpdateData:
		res = s.updateData(req)
	case api.ActionLogout:
		res = s.logoutUser(req)
	case api.ActionManageUsers: // New case for managing users
		res = s.manageUsers(req)
	case api.ActionFetchPolls:
		res = s.listPolls()
	case api.ActionCreatePoll:
		res = s.createPoll(req)
	case api.ActionVote:
		res = s.vote(req)

	default:
		res = api.Response{Success: false, Message: "Acción desconocida"}
	}

	// Enviamos la respuesta en formato JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// /////////////////////////////////////////////////////////////
// //// FUNCIONES RELACIONADAS CON LAS ENCUESTAS (POLLS) ///////
// /////////////////////////////////////////////////////////////
func (s *server) managePolls(req api.Request) api.Response {
	// Solo los administradores pueden gestionar encuestas
	if req.Role != "admin" && req.Role != "superadmin" {
		return api.Response{Success: false, Message: "Acceso denegado"}
	}

	switch req.Data {
	case "list":
		return s.listPolls()
	case "delete":
		return s.deletePoll(req)
	case "create":
		return s.createPoll(req)
	default:
		return api.Response{Success: false, Message: "Acción no válida"}
	}
}

func (s *server) createPoll(req api.Request) api.Response {
	// Crear una nueva encuesta
	if req.Question == "" || len(req.Options) == 0 {
		return api.Response{Success: false, Message: "Faltan datos para crear la encuesta"}
	}
	duracionHoras, err := strconv.Atoi(req.Data) // Duración de la encuesta en horas
	if err != nil {
		return api.Response{Success: false, Message: "Duración inválida"}
	}
	creador := req.Username // Usuario que crea la encuesta

	poll := NewPoll(req.PollID, req.Question, req.Options, duracionHoras, creador)
	if poll == nil {
		return api.Response{Success: false, Message: "Error al crear la encuesta"}
	}

	s.polls[req.PollID] = poll

	return api.Response{Success: true, Message: "Encuesta creada", Data: poll.Question}
}

func (s *server) deletePoll(req api.Request) api.Response {
	// Eliminar encuesta por ID
	if len(s.polls) == 0 {
		return api.Response{Success: false, Message: "No hay encuestas activas"}
	}

	// Aquí se eliminaría la encuesta por ID (no implementado)
	return api.Response{Success: true, Message: "Encuesta eliminada"}
}

func (s *server) listPolls() api.Response {
	// Listar encuestas activas
	if len(s.polls) == 0 {
		return api.Response{Success: false, Message: "No hay encuestas activas"}
	}

	pollList := "\n"
	for id, poll := range s.polls {

		pollList += fmt.Sprintf("ID: %s, Pregunta: %s, Opciones: %v, Creador: %s\n", id, poll.Question, poll.Options, poll.Creador)
	}
	return api.Response{Success: true, Message: "Encuestas listadas", Data: pollList}
}

func (s *server) vote(req api.Request) api.Response {
	// Votar en una encuesta
	if req.PollID == "" || req.Option == "" {
		return api.Response{Success: false, Message: "Faltan datos para votar"}
	}

	poll, exists := s.polls[req.PollID]
	if !exists {
		return api.Response{Success: false, Message: "Encuesta no encontrada"}
	}

	if err := poll.Vote(req.Option); err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}

	return api.Response{Success: true, Message: "Voto registrado"}
}

// manageUsers permite a los administradores listar, eliminar y modificar roles de usuarios.
// Solo los administradores pueden acceder a esta función.
func (s *server) manageUsers(req api.Request) api.Response {
	if req.Role != "admin" && req.Role != "superadmin" {
		return api.Response{Success: false, Message: "Acceso denegado"}
	}

	switch req.Data {
	case "list":
		// List all users
		keys, err := s.db.ListKeys("auth")
		if err != nil {
			return api.Response{Success: false, Message: "Error al listar usuarios"}
		}

		users := []string{}
		for _, key := range keys {
			role, err := s.db.Get("roles", key)
			if err != nil {
				role = []byte("unknown") // Default to "unknown" if role is not found
			}
			users = append(users, fmt.Sprintf("%s (%s)", string(key), string(role)))
		}
		return api.Response{Success: true, Message: "Usuarios listados", Data: strings.Join(users, "\n")}

	case "delete":
		// Delete a user
		if req.Username == "" {
			return api.Response{Success: false, Message: "Falta el nombre de usuario"}
		}
		if err := s.db.Delete("auth", []byte(req.Username)); err != nil {
			return api.Response{Success: false, Message: "Error al eliminar usuario"}
		}
		if err := s.db.Delete("roles", []byte(req.Username)); err != nil {
			return api.Response{Success: false, Message: "Error al eliminar rol del usuario"}
		}
		if err := s.db.Delete("userdata", []byte(req.Username)); err != nil {
			return api.Response{Success: false, Message: "Error al eliminar datos del usuario"}
		}
		return api.Response{Success: true, Message: "Usuario eliminado"}

	case "modify":
		// Modify a user's role
		if req.Username == "" || req.NewRole == "" {
			return api.Response{Success: false, Message: "Faltan datos para modificar usuario"}
		}

		// Check if the user exists
		exists, error := s.userExists(req.Username)
		if error != nil {
			return api.Response{Success: false, Message: "Error al verificar usuario"}
		}
		if !exists {
			return api.Response{Success: false, Message: "El usuario no existe"}
		}

		// Check if the new role is valid
		_, err := s.db.Get("roles", []byte(req.NewRole))
		if err != nil {
			return api.Response{Success: false, Message: "Rol no válido"}
		}
		// Update the user's role
		if err := s.db.Put("roles", []byte(req.Username), []byte(req.NewRole)); err != nil {
			return api.Response{Success: false, Message: "Error al modificar rol del usuario"}
		}
		return api.Response{Success: true, Message: "Rol del usuario modificado"}
	}

	return api.Response{Success: false, Message: "Acción no válida"}
}

// generateToken crea un token seguro usando valores aleatorios y SHA-256
func (s *server) generateToken() string {
	// Generar 32 bytes aleatorios
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		s.log.Println("Error generando token:", err)
		return "" // En caso de error, devolvería un token vacío (puedes manejarlo mejor)
	}

	// Aplicar SHA-256
	hash := sha256.Sum256(randomBytes)

	// Convertir el hash en string hexadecimal
	token := hex.EncodeToString(hash[:])

	print("Token generado: ", token, "\n")

	return token
}

// registerUser registra un nuevo usuario, si no existe.
// - Guardamos la contraseña en el namespace 'auth'
// - Creamos entrada vacía en 'userdata' para el usuario
func (s *server) registerUser(req api.Request) api.Response {
	// Validación básica
	if req.Username == "" || req.Password == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	// Verificamos si ya existe el usuario
	exists, err := s.userExists(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "Error al verificar usuario"}
	}
	if exists {
		return api.Response{Success: false, Message: "El usuario ya existe"}
	}

	// Determinar el rol del usuario
	role := "user" // Por defecto, el rol es "user"
	adminCheck, err := s.db.Get("superadmin", []byte(req.Username))
	if err == nil && string(adminCheck) == "true" {
		role = "superadmin" // Si el usuario está en la lista de admins, asignar el rol "admin"
	}

	// Hash the password using bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return api.Response{Success: false, Message: "Error al hashear la contraseña"}
	}

	// Guardamos el usuario con su hash en la base de datos
	if err := s.db.Put("auth", []byte(req.Username), hashedPassword); err != nil {
		return api.Response{Success: false, Message: "Error al guardar credenciales"}
	}

	// Guardamos el rol del usuario en la base de datos
	if err := s.db.Put("roles", []byte(req.Username), []byte(role)); err != nil {
		return api.Response{Success: false, Message: "Error al guardar rol del usuario"}
	}

	// Creamos una entrada vacía para los datos en 'userdata'
	if err := s.db.Put("userdata", []byte(req.Username), []byte("")); err != nil {
		return api.Response{Success: false, Message: "Error al inicializar datos de usuario"}
	}

	return api.Response{Success: true, Message: "Usuario registrado"}
}

// loginUser maneja el inicio de sesión de un usuario
func (s *server) loginUser(req api.Request) api.Response {
	if req.Username == "" || req.Password == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	// Recogemos la contraseña hasheada guardada en 'auth'
	hashedPassword, err := s.db.Get("auth", []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Usuario no encontrado"}
	}

	// Comparamos la contraseña ingresada con el hash almacenado
	if !verifyPassword(string(hashedPassword), req.Password) {
		return api.Response{Success: false, Message: "Credenciales inválidas"}
	}

	// Generamos un nuevo token de sesión y lo guardamos
	token := s.generateToken()
	if err := s.db.Put("sessions", []byte(req.Username), []byte(token)); err != nil {
		return api.Response{Success: false, Message: "Error al crear sesión"}
	}

	// Obtenemos el rol del usuario desde la base de datos
	role, err := s.db.Get("roles", []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener rol del usuario"}
	}

	return api.Response{
		Success: true,
		Message: "Login exitoso",
		Token:   token,
		Data:    string(role), // Incluimos el rol en el campo Data
	}
}

// fetchData verifica el token y retorna el contenido del namespace 'userdata'.
func (s *server) fetchData(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Obtenemos los datos asociados al usuario desde 'userdata'
	rawData, err := s.db.Get("userdata", []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener datos del usuario"}
	}

	return api.Response{
		Success: true,
		Message: "Datos privados de " + req.Username,
		Data:    string(rawData),
	}
}

// updateData cambia el contenido de 'userdata' (los "datos" del usuario)
// después de validar el token.
func (s *server) updateData(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Escribimos el nuevo dato en 'userdata'
	if err := s.db.Put("userdata", []byte(req.Username), []byte(req.Data)); err != nil {
		return api.Response{Success: false, Message: "Error al actualizar datos del usuario"}
	}

	return api.Response{Success: true, Message: "Datos de usuario actualizados"}
}

// logoutUser borra la sesión en 'sessions', invalidando el token.
func (s *server) logoutUser(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Borramos la entrada en 'sessions'
	if err := s.db.Delete("sessions", []byte(req.Username)); err != nil {
		return api.Response{Success: false, Message: "Error al cerrar sesión"}
	}

	return api.Response{Success: true, Message: "Sesión cerrada correctamente"}
}

// userExists comprueba si existe un usuario con la clave 'username'
// en 'auth'. Si no se encuentra, retorna false.
func (s *server) userExists(username string) (bool, error) {
	_, err := s.db.Get("auth", []byte(username))
	if err != nil {
		// Si no existe namespace o la clave:
		if strings.Contains(err.Error(), "bucket no encontrado: auth") {
			return false, nil
		}
		if err.Error() == "clave no encontrada: "+username {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// isTokenValid comprueba que el token almacenado en 'sessions'
// coincida con el token proporcionado.
func (s *server) isTokenValid(username, token string) bool {
	storedToken, err := s.db.Get("sessions", []byte(username))
	if err != nil {
		return false
	}
	return string(storedToken) == token
}

func verifyPassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}
