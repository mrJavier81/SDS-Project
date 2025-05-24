// El paquete server contiene el código del servidor.
// Interactúa con el cliente mediante una API JSON/HTTP
package server

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"

	"prac/pkg/api"
	"prac/pkg/store"
)

// server encapsula el estado de nuestro servidor
type server struct {
	db    store.Store      // base de datos
	log   *log.Logger      // logger para mensajes de error e información
	polls map[string]*Poll // polls es un mapa que contiene las encuestas activas
	//tokenCounter int64       // contador para generar tokens
	nextPollID int64 // ID para la próxima encuesta
}

// initBucket intenta inicializar un bucket realizando una operación simple
func initBucket(db store.Store, bucketName string) error {
	// Intentamos escribir un valor vacío con una clave temporal
	// Esto debería crear el bucket si no existe
	err := db.Put(bucketName, []byte("__init__"), []byte(""))
	if err != nil {
		return fmt.Errorf("error inicializando bucket %s: %v", bucketName, err)
	}

	// Opcionalmente, podemos eliminar esta clave temporal
	// Ya que solo la usamos para forzar la creación del bucket
	// err = db.Delete(bucketName, []byte("__init__"))

	return nil
}

// Run inicia la base de datos y arranca el servidor HTTPS.
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

	// Inicializamos todos los buckets necesarios
	bucketsNecesarios := []string{
		"auth",       // Credenciales de usuarios
		"roles",      // Roles de usuarios
		"sessions",   // Tokens de sesión
		"superadmin", // Lista de superadmins
		"messages",   // Mensajes entre usuarios
		"polls",      // Encuestas (si las usas)
		"pKeys",      // Claves públicas de usuarios
	}

	for _, bucket := range bucketsNecesarios {
		if err := initBucket(srv.db, bucket); err != nil {
			return err
		}
	}

	// Crear el bucket "polls" si no existe para que no falle si se intenta acceder a las polls

	// Cargar las encuestas desde la base de datos al mapa en memoria
	if err := srv.loadPolls(); err != nil {
		return fmt.Errorf("error al cargar encuestas desde la base de datos: %v", err)
	}

	idActual, _ := db.Get("config", []byte("nextPollID"))

	fmt.Printf("nextPollID antes de inicializar: %s", idActual)

	// Inicializamos la nextPollID a 1 si no existe, si existe no se cambia nada (se supone)
	if idActual == nil || string(idActual) == "" {

		err = db.Put("config", []byte("nextPollID"), []byte("1"))
		if err != nil && !strings.Contains(err.Error(), "bucket no encontrado") {
			return fmt.Errorf("error al crear el bucket config: %v", err)
		}
	}

	idActual, _ = db.Get("config", []byte("nextPollID"))

	fmt.Printf("nextPollID despues de inicializar: %s", idActual)

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

	// Construimos un mux y asociamos /api a nuestro apiHandler
	mux := http.NewServeMux()
	mux.Handle("/api", http.HandlerFunc(srv.apiHandler))

	// Configuración de HTTPS
	certFile := "cert.pem" // Ruta al certificado SSL
	keyFile := "key.pem"   // Ruta a la clave privada

	// Iniciamos el servidor HTTPS
	fmt.Println("Servidor HTTPS iniciado en https://localhost:8443")
	err = http.ListenAndServeTLS(":8443", certFile, keyFile, mux)
	if err != nil {
		return fmt.Errorf("error iniciando servidor HTTPS: %v", err)
	}

	return nil
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
		if req.Data == "past" { // Filtrar votaciones según si están pasadas o no
			res = s.listPolls("past", req.Username)

		} else if req.Data == "participate" { // Filtrar votaciones según si el usuario ha participado o no
			res = s.listPolls("participate", req.Username)

		} else {
			res = s.listPolls("", req.Username)
		}
	case api.ActionCreatePoll:
		res = s.createPoll(req)
	case api.ActionVote:
		res = s.vote(req)
	case api.ActionGetPollByID:
		res = s.getPollByID(req.PollID)
	case api.ActionFetchMessages:
		res = s.fetchMessages(req)
	case api.ActionCheckUser:
		res = s.checkUser(req)
	case api.ActionSendMessage:
		res = s.storeMessage(req.Dest, req.Data, req.Username)
	case api.ActionFetchLogs:
		res = s.fetchLogs(req)
	case api.ActionGetPublicKey:
		res = s.getPublicKey(req)
	case api.ActionSavePublicKey:
		res = s.savePublicKey(req)

	case api.ActionSavePrivateKey:
		res = s.savePrivateKey(req)

	case api.ActionFetchPrivateKey:
		res = s.fetchPrivateKey(req)

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

// Cargar las encuestas desde la base de datos al mapa en memoria
// Esta función se llama al iniciar el servidor y carga todas las encuestas
func (s *server) loadPolls() error {
	// Obtener todas las claves en el namespace "polls"
	keys, err := s.db.ListKeys("polls")
	if err != nil {
		return fmt.Errorf("error al listar encuestas: %v", err)
	}

	// Recorrer las claves y cargar cada encuesta
	for _, key := range keys {
		// Obtener los datos de la encuesta desde la base de datos

		// Ignorar la clave "__init__" que se usa para inicializar el bucket
		if string(key) == "__init__" {
			continue
		}
		data, err := s.db.Get("polls", key)
		if err != nil {
			return fmt.Errorf("error al obtener encuesta con ID %s: %v", string(key), err)
		}

		// Deserializar los datos en una estructura Poll
		var poll Poll
		if err := json.Unmarshal(data, &poll); err != nil {
			return fmt.Errorf("error al deserializar encuesta con ID %s: %v", string(key), err)
		}

		// Añadir la encuesta al mapa en memoria
		s.polls[string(key)] = &poll
	}

	return nil
}

// Obtenemos el ID de la próxima encuesta desde la base de datos, y si no existe, lo inicializamos a 1
func (s *server) initializeNextPollID() error {
	// Intentar obtener el ID de la próxima encuesta desde la base de datos
	data, err := s.db.Get("config", []byte("nextPollID"))
	if err != nil {

		fmt.Printf("Inicializando nextPollID: %s", data)
		// Si no existe la clave, inicializar el ID a 1
		if strings.Contains(err.Error(), "clave no encontrada") {
			s.nextPollID = 1
			// Guardar el valor inicial en la base de datos
			return s.saveNextPollID()
		}
		return fmt.Errorf("error al obtener nextPollID: %v", err)
	}
	fmt.Printf("NextpollID inicializado a %v", s.nextPollID)

	// Convertir el valor recuperado a int64
	nextPollID, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		return fmt.Errorf("error al parsear nextPollID: %v", err)
	}

	// Asignar el valor al campo nextPollID del servidor
	s.nextPollID = nextPollID
	return nil
}

// Esta funcion se encarga de cargar el ID de la próxima encuesta desde la base de datos
func (s *server) saveNextPollID() error {
	// Convertimos el valor de nextPollID a string
	nextPollIDStr := strconv.FormatInt(s.nextPollID, 10)

	fmt.Printf("Guardando nextPollID: %s", nextPollIDStr)

	// Guardamos el valor en la base de datos bajo el namespace "config" con la clave "nextPollID"
	if err := s.db.Put("config", []byte("nextPollID"), []byte(nextPollIDStr)); err != nil {
		return fmt.Errorf("error al guardar nextPollID en la base de datos: %v", err)
	}

	return nil
}

/*func (s *server) managePolls(req api.Request) api.Response {
	// Solo los administradores pueden gestionar encuestas
	if req.Role != "admin" && req.Role != "superadmin" {
		return api.Response{Success: false, Message: "Acceso denegado"}
	}

	switch req.Data {
	case "list":
		return s.listPolls("")
	case "delete":
		return s.deletePoll(req)
	case "create":
		return s.createPoll(req)
	default:
		return api.Response{Success: false, Message: "Acción no válida"}
	}
}*/

func (s *server) createPoll(req api.Request) api.Response {
	// Crear una nueva encuesta
	if req.Question == "" || len(req.Options) == 0 {
		return api.Response{Success: false, Message: "Faltan datos para crear la encuesta"}
	}
	duracionHoras, err := strconv.Atoi(req.Data) // Duración de la encuesta en horas
	if err != nil {
		return api.Response{Success: false, Message: "Duración inválida"}
	}
	creador := req.Creador // Usuario que crea la encuesta

	// Generar un ID único para la encuesta

	pollID := strconv.FormatInt(s.nextPollID, 10)
	s.nextPollID++ // Incrementar el ID para la próxima encuesta

	fmt.Printf("nextPollID: %d\n", s.nextPollID)
	// Guardar el nuevo ID de encuesta en la base de datos
	if err := s.saveNextPollID(); err != nil {
		return api.Response{Success: false, Message: "Error al guardar el siguiente ID de encuesta"}
	}

	// Crear la encuesta
	poll := NewPoll(pollID, req.Question, req.Options, duracionHoras, creador)
	if poll == nil {
		s.logMessage(fmt.Sprintf("Error al crear la encuesta: %s", req.Question))
		return api.Response{Success: false, Message: "Error al crear la encuesta"}
	}

	s.polls[pollID] = poll

	pollData, err := poll.ToJSON()

	fmt.Printf("Poll data: %s\n", pollData)

	s.db.Put("polls", []byte(pollID), []byte(pollData))

	s.logMessage(fmt.Sprintf("Encuesta creada exitosamente: %s por %s", req.Question, req.Creador))
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

// listPolls lista las encuestas activas o pasadas según el filtro
func (s *server) listPolls(filtro string, user string) api.Response {
	// Listar encuestas activas
	if len(s.polls) == 0 {
		return api.Response{Success: false, Message: "No hay encuestas activas"}
	}

	pollList := "\n"
	pollsListadas := 0
	for _, poll := range s.polls {

		if poll.ID == "__init__" {
			fmt.Println("Poll ID es __init__, continuando...")
			continue
		}

		if filtro == "past" {
			fechaFin, err := time.Parse("2006-01-02 15:04:05", poll.FechaFin)
			if err != nil {
				continue
			}

			if fechaFin.After(time.Now()) {
				continue
			}
		} else if filtro == "participate" {
			if !poll.HasParticipated(user) {
				continue
			}
		}
		// Aquí se podría agregar más lógica para filtrar por estado o creador

		pollList += fmt.Sprintf("ID: %s, Estado: %s Pregunta: %s, Opciones: %v, Creador: %s, Fecha limite: %s, Participantes: %v, \n",
			poll.ID, poll.Estado, poll.Question, poll.Options, poll.Creador, poll.FechaFin, poll.Participants)
		pollsListadas++
	}

	if pollList == "\n" {
		return api.Response{Success: false, Message: "No hay encuestas que coincidan con el filtro"}
	}

	return api.Response{Success: true, Message: "Encuestas listadas", Data: pollList, Cantidad: pollsListadas}
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
		s.logMessage(fmt.Sprintf("Error al registrar voto en la encuesta %s: %v", req.PollID, err))
		return api.Response{Success: false, Message: err.Error()}
	}
	pollData, err := json.Marshal(poll)
	if err != nil {
		return api.Response{Success: false, Message: "Error al serializar la encuesta actualizada"}
	}
	if err := s.db.Put("polls", []byte(poll.ID), pollData); err != nil {
		return api.Response{Success: false, Message: "Error al guardar la encuesta actualizada"}
	}

	s.logMessage(fmt.Sprintf("Voto registrado en la encuesta %s por %s", req.PollID, req.Username))
	return api.Response{Success: true, Message: "Voto registrado"}
}

func (s *server) getPollByID(pollID string) api.Response {
	// Verificar si la encuesta existe en el mapa en memoria
	poll, exists := s.polls[pollID]
	if !exists {
		return api.Response{Success: false, Message: "Encuesta no encontrada"}
	}

	// Serializar la encuesta a JSON para enviarla al cliente
	pollData, err := json.Marshal(poll)
	if err != nil {
		return api.Response{Success: false, Message: "Error al serializar la encuesta"}
	}

	return api.Response{Success: true, Message: "Encuesta encontrada", Data: string(pollData)}
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

func (s *server) getPublicKey(req api.Request) api.Response {
	// Obtener la clave pública del usuario
	if req.Username == "" {
		return api.Response{Success: false, Message: "Falta el nombre de usuario"}
	}

	publicKey, err := s.db.Get("pKeys", []byte(req.Dest))

	if err != nil {
		if strings.Contains(err.Error(), "clave no encontrada") {
			return api.Response{Success: false, Message: "Clave pública no encontrada"}
		}
		return api.Response{Success: false, Message: "Error al obtener clave pública"}
	}

	return api.Response{Success: true, Message: "Clave pública obtenida", Data: string(publicKey)}
}

func (s *server) savePublicKey(req api.Request) api.Response {
	// Guardar la clave pública del usuario
	if req.Username == "" || req.Data == "" {

		return api.Response{Success: false, Message: "Faltan datos para guardar clave pública"}
	}

	fmt.Println("Guardando clave pública para el usuario:", req.Username)
	if err := s.db.Put("pKeys", []byte(req.Username), []byte(req.Data)); err != nil {
		fmt.Print("Error al guardar clave pública database:", err, "\n")
		return api.Response{Success: false, Message: "Error al guardar clave pública"}
	}

	fmt.Print("Clave pública guardada: ", req.Data, "\n")

	return api.Response{Success: true, Message: "Clave pública guardada"}
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
		s.logMessage("Intento de registro fallido: faltan credenciales")
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	// Verificamos si ya existe el usuario
	exists, err := s.userExists(req.Username)
	if err != nil {
		s.logMessage(fmt.Sprintf("Error al verificar usuario %s: %v", req.Username, err))
		return api.Response{Success: false, Message: "Error al verificar usuario"}
	}
	if exists {
		s.logMessage(fmt.Sprintf("Intento de registro fallido: usuario %s ya existe", req.Username))
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

	s.logMessage(fmt.Sprintf("Usuario registrado exitosamente: %s", req.Username))
	return api.Response{Success: true, Message: "Usuario registrado"}
}

// maneja el inicio de sesión de un usuario
func (s *server) loginUser(req api.Request) api.Response {
	if req.Username == "" || req.Password == "" {
		s.logMessage("Intento de inicio de sesión fallido: faltan credenciales")
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	// Recogemos la contraseña hasheada guardada en 'auth'
	hashedPassword, err := s.db.Get("auth", []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Usuario no encontrado"}
	}

	// Comparamos la contraseña ingresada con el hash almacenado
	if !verifyPassword(string(hashedPassword), req.Password) {
		s.logMessage(fmt.Sprintf("Intento de inicio de sesión fallido: credenciales inválidas para %s", req.Username))
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

	s.logMessage(fmt.Sprintf("Inicio de sesión exitoso: %s", req.Username))
	return api.Response{
		Success: true,
		Message: "Login exitoso",
		Token:   token,
		Data:    string(role), // Incluimos el rol en el campo Data
	}
}

func (s *server) fetchMessages(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Obtener los mensajes en formato JSON desde la base de datos
	messagesJSON, err := s.db.Get("messages", []byte(req.Username))
	if err != nil {
		// Si no hay mensajes, devolver lista vacía en formato JSON
		return api.Response{
			Success: true,
			Message: "No hay mensajes",
			Data:    "[]",
		}
	}

	// Validar que el JSON sea decodificable
	var messages []map[string]string
	if err := json.Unmarshal(messagesJSON, &messages); err != nil {
		return api.Response{Success: false, Message: "Error al decodificar mensajes: " + err.Error()}
	}

	// Reconvertimos a JSON válido (opcional, pero más seguro)
	data, err := json.Marshal(messages)
	if err != nil {
		return api.Response{Success: false, Message: "Error al reserializar mensajes"}
	}

	return api.Response{
		Success: true,
		Message: "Mensajes obtenidos",
		Data:    string(data),
	}
}

func (s *server) storeMessage(username string, message string, sender string) api.Response {
	// Obtener los mensajes existentes
	messagesJSON, err := s.db.Get("messages", []byte(username))
	if err != nil {
		// Si no hay mensajes previos, inicializamos un slice vacío
		if strings.Contains(err.Error(), "clave no encontrada") {
			messagesJSON = []byte("[]") // Inicializamos con un JSON vacío
		} else {
			return api.Response{Success: false, Message: "Error al obtener mensajes: " + err.Error()}
		}
	}

	// Decodificar los mensajes existentes
	var messages []map[string]string
	if err := json.Unmarshal(messagesJSON, &messages); err != nil {
		return api.Response{Success: false, Message: "Error al decodificar mensajes: " + err.Error()}
	}

	// Agregar el nuevo mensaje con el remitente
	newMessage := map[string]string{
		"Sender":  sender,  // Cambiado a mayúsculas
		"Message": message, // Cambiado a mayúsculas
	}
	messages = append(messages, newMessage)

	// Codificar los mensajes actualizados a JSON
	messagesJSON, err = json.Marshal(messages)
	if err != nil {
		return api.Response{Success: false, Message: "Error al codificar mensajes: " + err.Error()}
	}

	// Guardar los mensajes actualizados en la base de datos
	if err := s.db.Put("messages", []byte(username), messagesJSON); err != nil {
		return api.Response{Success: false, Message: "Error al guardar mensajes: " + err.Error()}
	}

	return api.Response{
		Success: true,
		Message: "Mensaje enviado correctamente",
		Data:    fmt.Sprintf("Enviado a %s", username),
	}
}

func (s *server) checkUser(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Verificamos si el usuario existe
	exists, err := s.userExists(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "Error al verificar usuario"}
	}
	if !exists {
		return api.Response{Success: false, Message: "El usuario no existe"}
	}

	dest, err := s.userExists(req.Dest)
	if err != nil {
		return api.Response{Success: false, Message: "Error al verificar usuario destino"}
	}
	if !dest {
		return api.Response{Success: false, Message: "El usuario destino no existe"}
	}

	return api.Response{
		Success: true,
		Message: "Usuario verificado",
		Data:    "El usuario existe y el destino también",
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

	// Derivamos la clave de cifrado a partir del nombre de usuario
	key := deriveKey(req.Username)

	if rawData == nil {
		return api.Response{Success: false, Message: "No hay datos para el usuario"}
	}
	// Verificamos si los datos están vacíos
	if string(rawData) == "" {
		return api.Response{Success: false, Message: "No hay datos para el usuario"}
	}

	// Desciframos los datos antes de devolverlos
	decryptedData, err := decryptHTTPS(rawData, key)
	if err != nil {
		fmt.Println("Error al descifrar datos:", err)
		s.logMessage(fmt.Sprintf("Error al descifrar datos del usuario %s: %v", req.Username, err))
		return api.Response{Success: false, Message: "Error al descifrar datos del usuario"}
	}

	return api.Response{
		Success: true,
		Message: "Datos privados de " + req.Username,
		Data:    string(decryptedData),
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

	// Derivamos la clave de cifrado a partir del nombre de usuario
	key := deriveKey(req.Username)

	// Ciframos los datos del usuario antes de guardarlos
	encryptedData, err := encryptHTTPS([]byte(req.Data), key)
	if err != nil {
		s.logMessage(fmt.Sprintf("Error al cifrar datos del usuario %s: %v", req.Username, err))
		return api.Response{Success: false, Message: "Error al cifrar datos del usuario"}
	}

	// Guardamos los datos cifrados en la base de datos
	if err := s.db.Put("userdata", []byte(req.Username), encryptedData); err != nil {
		s.logMessage(fmt.Sprintf("Error al actualizar datos del usuario %s: %v", req.Username, err))
		return api.Response{Success: false, Message: "Error al actualizar datos del usuario"}
	}

	s.logMessage(fmt.Sprintf("Datos del usuario %s actualizados exitosamente", req.Username))
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
		s.logMessage(fmt.Sprintf("Error al cerrar sesión para el usuario %s: %v", req.Username, err))
		return api.Response{Success: false, Message: "Error al cerrar sesión"}
	}

	s.logMessage(fmt.Sprintf("Sesión cerrada exitosamente para el usuario %s", req.Username))
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

var encryptionSalt = []byte("saltsalt") // Debe tener 8 bytes mínimo. Idealmente fija o por usuario.

func deriveKey(passphrase string) []byte {
	return argon2.IDKey([]byte(passphrase), encryptionSalt, 1, 64*1024, 4, 32)
}

func encrypt(plaintext string, passphrase string) (string, error) {
	key := deriveKey(passphrase)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(ciphertextBase64 string, passphrase string) (string, error) {
	key := deriveKey(passphrase)

	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// encryptHTTPS cifra los datos utilizando AES-GCM y devuelve el ciphertext con el nonce adjunto.
func encryptHTTPS(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creando el cifrador AES: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error creando el modo GCM: %v", err)
	}

	nonce := make([]byte, aesGCM.NonceSize()) // Generar un nonce aleatorio
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("error generando nonce: %v", err)
	}

	// Cifrar los datos y adjuntar el nonce al principio del ciphertext
	ciphertext := aesGCM.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decryptHTTPS descifra los datos utilizando AES-GCM y devuelve el plaintext.
func decryptHTTPS(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creando el cifrador AES: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error creando el modo GCM: %v", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext demasiado corto")
	}

	// Separar el nonce del ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Descifrar los datos
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("error descifrando datos: %v", err)
	}

	return plaintext, nil
}

// sendLogToBackupServer envía un log al servidor de respaldo.
func sendLogToBackupServer(logMessage string) {
	conn, err := net.Dial("tcp", "localhost:9000") // Conectar al servidor de respaldo
	if err != nil {
		fmt.Println("Error al conectar con el servidor de respaldo:", err)
		return
	}
	defer conn.Close()

	_, err = conn.Write([]byte(logMessage + "\n"))
	if err != nil {
		fmt.Println("Error al enviar log al servidor de respaldo:", err)
	}
}

// Modificar el logger para enviar logs al servidor de respaldo.
func (s *server) logMessage(message string) {
	s.log.Println(message)
	sendLogToBackupServer(message)
}

func (s *server) fetchLogs(req api.Request) api.Response {
	// Solo los superadministradores pueden ver los logs
	if req.Role != "superadmin" {
		return api.Response{Success: false, Message: "Acceso denegado"}
	}

	// Conectar al servidor de respaldo para obtener los logs
	conn, err := net.Dial("tcp", "localhost:9000")
	if err != nil {
		return api.Response{Success: false, Message: "Error al conectar con el servidor de respaldo: " + err.Error()}
	}
	defer conn.Close()

	// Solicitar los logs al servidor de respaldo
	fmt.Fprintln(conn, "FETCH_LOGS")

	// Leer la respuesta del servidor de respaldo
	scanner := bufio.NewScanner(conn)
	var logs []string
	for scanner.Scan() {
		logs = append(logs, scanner.Text())
	}

	if len(logs) == 0 {
		return api.Response{Success: false, Message: "No hay logs disponibles"}
	}

	return api.Response{
		Success: true,
		Message: "Logs obtenidos correctamente",
		Data:    strings.Join(logs, "\n"),
	}
}

func (s *server) savePrivateKey(req api.Request) api.Response {
	// Guardar la clave privada del usuario
	if req.Username == "" || req.Data == "" {
		return api.Response{Success: false, Message: "Faltan datos para guardar clave privada"}
	}

	fmt.Println("Guardando clave privada para el usuario:", req.Username)
	if err := s.db.Put("privateKeys", []byte(req.Username), []byte(req.Data)); err != nil {
		fmt.Print("Error al guardar clave privada database:", err, "\n")
		return api.Response{Success: false, Message: "Error al guardar clave privada"}
	}

	fmt.Print("Clave privada guardada: ", req.Data, "\n")

	return api.Response{Success: true, Message: "Clave privada guardada"}
}

func (s *server) fetchPrivateKey(req api.Request) api.Response {
	// Obtener la clave privada del usuario
	if req.Username == "" {
		return api.Response{Success: false, Message: "Falta el nombre de usuario"}
	}

	privateKey, err := s.db.Get("privateKeys", []byte(req.Username))

	if err != nil {
		if strings.Contains(err.Error(), "clave no encontrada") {
			return api.Response{Success: false, Message: "Clave privada no encontrada"}
		}
		return api.Response{Success: false, Message: "Error al obtener clave privada"}
	}

	return api.Response{Success: true, Message: "Clave privada obtenida", Data: string(privateKey)}
}
