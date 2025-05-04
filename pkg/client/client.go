// El paquete client contiene la lógica de interacción con el usuario
// así como de comunicación con el servidor.
package client

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"prac/pkg/api"
	"prac/pkg/ui"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/scrypt"
)

// client estructura interna no exportada que controla
// el estado de la sesión (usuario, token) y logger.
type client struct {
	log         *log.Logger
	currentUser string
	authToken   string
	userRole    string
	kData       string
}

// Run es la única función exportada de este paquete.
// Crea un client interno y ejecuta el bucle principal.
func Run() {
	// Creamos un logger con prefijo 'cli' para identificar
	// los mensajes en la consola.
	c := &client{
		log: log.New(os.Stdout, "[cli] ", log.LstdFlags),
	}
	c.runLoop()
}

// runLoop maneja la lógica del menú principal.
// Si NO hay usuario logueado, se muestran ciertas opciones;
// si SÍ hay usuario logueado, se muestran otras.
func (c *client) runLoop() {
	for {
		ui.ClearScreen()

		// Construimos un título que muestre el usuario logueado, si lo hubiera.
		var title string
		if c.currentUser == "" {
			title = "Menú"
		} else {
			title = fmt.Sprintf("Menú (%s)", c.currentUser)
		}

		// Generamos las opciones dinámicamente, según si hay un login activo.
		var options []string
		if c.currentUser == "" {
			// Usuario NO logueado: Registro, Login, Salir
			options = []string{
				"Registrar usuario",
				"Iniciar sesión",
				"Salir",
			}
		} else {
			// Usuario logueado: Ver datos, Actualizar datos, Logout, Salir
			options = []string{
				"Ver votaciones",
				"Ver datos",
				"Actualizar datos",
				"Cerrar sesión",
			}

			if c.userRole == "admin" || c.userRole == "superadmin" {
				options = append(options, "Administrar votaciones")
			}

			if c.userRole == "superadmin" {
				options = append(options, "Administrar usuarios")
			}

			options = append(options, "Salir")
		}

		// Mostramos el menú y obtenemos la elección del usuario.
		choice := ui.PrintMenu(title, options)

		// Hay que mapear la opción elegida según si está logueado o no.
		if c.currentUser == "" {
			// Caso NO logueado
			switch choice {
			case 1:
				c.registerUser()
			case 2:
				c.loginUser()
			case 3:
				// Opción Salir
				c.log.Println("Saliendo del cliente...")
				return
			}
		} else {
			// Caso logueado
			switch choice {
			case 1:
				c.verVotaciones()
			case 2:
				c.fetchData()
			case 3:
				c.updateData()
			case 4:
				c.logoutUser()
			case 5:
				if c.userRole == "superadmin" {
					c.administrarUsuarios()
				} else { // Si no es admin, la opcion de salir se mostrará como la cuarta
					c.log.Println("Saliendo del cliente...")
					return
				}
			case 6:
				if c.userRole == "admin" || c.userRole == "superadmin" {
					c.administrarVotaciones()
				} else {
					fmt.Println("No tienes permisos para administrar votaciones.")
				}

			case 7:
				// Opción Salir
				c.log.Println("Saliendo del cliente...")
				return
			}
		}

		// Pausa para que el usuario vea resultados.
		ui.Pause("Pulsa [Enter] para continuar...")
	}
}

func (c *client) administrarVotaciones() {
	ui.ClearScreen()
	fmt.Println("** Administrar votaciones **")

	options := []string{
		"Crear votación",
		"Modificar votación",
		"Eliminar votación",
		"Ver resultados de votación",
		"Volver al menú principal",
	}

	choice := ui.PrintMenu("Opciones de administración", options)
	switch choice {
	case 1:
		// Crear votación
		question := ui.ReadInput("Pregunta de la votación")
		options := strings.Split(ui.ReadInput("Opciones de la votación (separadas por comas)"), ",")
		duration := ui.ReadInput("Duración de la votación (en horas)")
		res := c.sendRequest(api.Request{
			Action:   api.ActionCreatePoll,
			Role:     c.userRole,
			Question: question,
			Options:  options,
			Data:     duration,
		})
		fmt.Println("Resultado:", res.Message)
	case 2:
		// Modificar votación
		pollID := ui.ReadInput("ID de la votación a modificar")
		newQuestion := ui.ReadInput("Nueva pregunta de la votación")
		newOptions := strings.Split(ui.ReadInput("Nuevas opciones de la votación (separadas por comas)"), ",")

		res := c.sendRequest(api.Request{
			Action:   api.ActionModifyPoll,
			Role:     c.userRole,
			PollID:   pollID,
			Question: newQuestion,
			Options:  newOptions,
		})
		fmt.Println("Resultado:", res.Message)
	case 3:
		// Eliminar votación
		pollID := ui.ReadInput("ID de la votación a eliminar")
		res := c.sendRequest(api.Request{
			Action: api.ActionDeletePoll,
			Role:   c.userRole,
			PollID: pollID,
		})
		fmt.Println("Resultado:", res.Message)
	case 4:
		// Ver resultados de votación
		pollID := ui.ReadInput("ID de la votación a ver resultados")
		res := c.sendRequest(api.Request{
			Action: api.ActionFetchPolls,
			Role:   c.userRole,
			PollID: pollID,
		})
		if res.Success {
			fmt.Println("Resultados de la votación:")
			fmt.Println(res.Data)
		} else {
			fmt.Println("Error:", res.Message)
		}
	case 5:
		// Volver al menú principal
		return
	}
}

func (c *client) verVotaciones() {
	ui.ClearScreen()
	fmt.Println("** Ver votaciones **")

	options := []string{
		"Ver votaciones activas",
		"Ver votaciones en las que participas",
		"Ver votaciones pasadas",
		"Volver al menú principal",
	}

	choice := ui.PrintMenu("Opciones de votación", options)
	switch choice {
	case 1:
		// Ver votaciones activas
		res := c.sendRequest(api.Request{
			Action: api.ActionFetchPolls,
			Role:   c.userRole,
		})
		if res.Success {
			fmt.Println("Votaciones activas:")
			fmt.Println(res.Data)
		} else {
			fmt.Println("Error:", res.Message)
		}
	case 2:
		// Ver votaciones en las que participas
		res := c.sendRequest(api.Request{
			Action: api.ActionFetchPolls,
			Role:   c.userRole,
		})
		if res.Success {
			fmt.Println("Votaciones en las que participas:")
			fmt.Println(res.Data)
		} else {
			fmt.Println("Error:", res.Message)
		}
	case 3:
		// Ver votaciones pasadas
		res := c.sendRequest(api.Request{
			Action: api.ActionFetchPolls,
			Role:   c.userRole,
		})
		if res.Success {
			fmt.Println("Votaciones pasadas:")
			fmt.Println(res.Data)
		} else {
			fmt.Println("Error:", res.Message)
		}
	case 4:
		// Volver al menú principal
		return
	}

	ui.Pause("Pulsa [Enter] para continuar...")
	c.verVotaciones()
}

func (c *client) administrarUsuarios() {
	ui.ClearScreen()
	fmt.Println("** Administrar usuarios **")

	options := []string{
		"Listar usuarios",
		"Modificar usuario",
		"Eliminar usuario",
		"Volver al menú principal",
	}

	choice := ui.PrintMenu("Opciones de administración", options)

	switch choice {
	case 1:
		// List users
		res := c.sendRequest(api.Request{
			Action: api.ActionManageUsers,
			Role:   c.userRole,
			Data:   "list",
		})
		if res.Success {
			fmt.Println("Usuarios registrados:")
			fmt.Println(res.Data)
		} else {
			fmt.Println("Error:", res.Message)
		}

	case 2:
		// Modify user role
		username := ui.ReadInput("Nombre del usuario a modificar")
		newRole := ui.ReadInput("Nuevo rol (user/admin)")
		res := c.sendRequest(api.Request{
			Action:   api.ActionManageUsers,
			Role:     c.userRole,
			Data:     "modify",
			Username: username,
			NewRole:  newRole,
		})
		fmt.Println("Resultado:", res.Message)

	case 3:
		// Delete user
		username := ui.ReadInput("Nombre del usuario a eliminar")
		res := c.sendRequest(api.Request{
			Action:   api.ActionManageUsers,
			Role:     c.userRole,
			Data:     "delete",
			Username: username,
		})
		fmt.Println("Resultado:", res.Message)

	case 4:
		// Return to main menu
		return
	}

	ui.Pause("Pulsa [Enter] para continuar...")
	c.administrarUsuarios()

}

// registerUser pide credenciales y las envía al servidor para un registro.
// Si el registro es exitoso, se intenta el login automático.
func (c *client) registerUser() {
	ui.ClearScreen()
	fmt.Println("** Registro de usuario **")

	username := ui.ReadInput("Nombre de usuario")
	password := ui.ReadInput("Contraseña")

	// Hash de la contraseña
	kKey, kData := hashPassword(password)

	// Guardamos kData para uso futuro
	c.kData = kData

	// Enviamos la acción al servidor
	res := c.sendRequest(api.Request{
		Action:   api.ActionRegister,
		Username: username,
		Password: kKey, // Enviamos el hash determinista de la primera mitad
	})

	// Mostramos resultado
	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si fue exitoso, probamos loguear automáticamente.
	if res.Success {
		c.log.Println("Registro exitoso; intentando login automático...")

		loginRes := c.sendRequest(api.Request{
			Action:   api.ActionLogin,
			Username: username,
			Password: kKey, // Enviamos el hash determinista de la primera mitad
		})

		// Log the response for debugging
		c.log.Printf("Respuesta de login automático: %+v\n", loginRes)

		if loginRes.Success {
			c.currentUser = username
			c.authToken = loginRes.Token
			c.userRole = loginRes.Data
			fmt.Printf("Login automático como %v exitoso. Token guardado.\n", c.userRole)
		} else {
			fmt.Println("No se ha podido hacer login automático:", loginRes.Message)
		}
	}
}

// loginUser pide credenciales y realiza un login en el servidor.
// loginUser pide credenciales y realiza un login en el servidor.
func (c *client) loginUser() {
	ui.ClearScreen()
	fmt.Println("** Inicio de sesión **")

	username := ui.ReadInput("Nombre de usuario")
	password := ui.ReadInput("Contraseña")

	// Hash de la contraseña
	kKey, kData := hashPassword(password)

	// Guardamos kData para uso futuro (añadir esta línea)
	c.kData = kData

	res := c.sendRequest(api.Request{
		Action:   api.ActionLogin,
		Username: username,
		Password: kKey,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si login fue exitoso, guardamos currentUser y el token.
	if res.Success {
		c.currentUser = username
		c.authToken = res.Token
		c.userRole = res.Data
		fmt.Printf("Sesión iniciada como %v. Token guardado.\n", c.userRole)
	}
}

// fetchData obtiene la data cifrada del servidor y la descifra.
func (c *client) fetchData() {
	ui.ClearScreen()
	fmt.Println("** Obtener datos del usuario **")

	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return
	}

	// Hacemos la request con ActionFetchData
	res := c.sendRequest(api.Request{
		Action:   api.ActionFetchData,
		Username: c.currentUser,
		Token:    c.authToken,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	if res.Success {
		fmt.Println("Tus datos:", res.Data)

		// Decode the hex string
		payload, err := hex.DecodeString(res.Data)
		if err != nil {
			fmt.Println("Error al decodificar los datos:", err)
			return
		}

		if len(payload) < 12 {
			fmt.Println("Datos inválidos: falta el nonce")
			return
		}

		// Extraer nonce y ciphertext
		nonce := payload[:12]
		encryptedData := payload[12:]

		// Descifrar
		descifrado, err := decryptData(c, nonce, encryptedData)
		if err != nil {
			fmt.Println("Error al descifrar los datos:", err)
			return
		}
		fmt.Println("Descifrado:", descifrado)
	}
}

// updateData pide nuevo texto y lo envía al servidor con ActionUpdateData.
func (c *client) updateData() {
	ui.ClearScreen()
	fmt.Println("** Actualizar datos del usuario **")

	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return
	}

	// Leemos la nueva Data
	newData := ui.ReadInput("Introduce el contenido que desees almacenar")

	// Ciframos newData con kData de usuario
	nonce, encryptedData, err := encryptData(c, newData)
	if err != nil {
		fmt.Println("Error al cifrar los datos:", err)
		return
	}

	// Concatenamos nonce + encryptedData
	finalPayload := append(nonce, encryptedData...)

	// Encode the full payload to hex
	encodedData := hex.EncodeToString(finalPayload)

	// Enviamos la solicitud de actualización
	res := c.sendRequest(api.Request{
		Action:   api.ActionUpdateData,
		Username: c.currentUser,
		Token:    c.authToken,
		Data:     encodedData,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
}

// logoutUser llama a la acción logout en el servidor, y si es exitosa,
// borra la sesión local (currentUser/authToken).
func (c *client) logoutUser() {
	ui.ClearScreen()
	fmt.Println("** Cerrar sesión **")

	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado.")
		return
	}

	// Llamamos al servidor con la acción ActionLogout
	res := c.sendRequest(api.Request{
		Action:   api.ActionLogout,
		Username: c.currentUser,
		Token:    c.authToken,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si fue exitoso, limpiamos la sesión local.
	if res.Success {
		c.currentUser = ""
		c.authToken = ""
	}
}

// sendRequest envía un POST JSON a la URL del servidor y
// devuelve la respuesta decodificada. Se usa para todas las acciones.
func (c *client) sendRequest(req api.Request) api.Response {
	jsonData, _ := json.Marshal(req)
	resp, err := http.Post("http://localhost:8080/api", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Error al contactar con el servidor:", err)
		return api.Response{Success: false, Message: "Error de conexión"}
	}
	defer resp.Body.Close()

	// Leemos el body de respuesta y lo desempaquetamos en un api.Response
	body, _ := io.ReadAll(resp.Body)
	var res api.Response
	_ = json.Unmarshal(body, &res)
	return res
}

// HashPassword hashea la contraseña completa con SHA-256
func hashPassword(password string) (string, string) {
	hash := sha256.Sum256([]byte(password))

	hashedPassword := hex.EncodeToString(hash[:])

	// Dividimos la contraseña en dos partes
	mid := len(hashedPassword) / 2
	kKey := hashedPassword[:mid]  // Primera mitad (se almacena en el servidor)
	kData := hashedPassword[mid:] // Segunda mitad (se usa en el cliente)

	return kKey, kData
}

// Derivamos una clave AES-256 de kData
func deriveKey(c *client) []byte {
	salt := []byte(c.currentUser) // Usamos el nombre de usuario como salt
	key, err := scrypt.Key([]byte(c.kData), salt, 32768, 8, 1, 32)
	if err != nil {
		fmt.Println("Error al derivar la clave:", err)
		return nil
	}
	return key
}

// Cifrar datos con AES-256 GCM
func encryptData(c *client, data string) ([]byte, []byte, error) {
	key := deriveKey(c)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, 12) // GCM estándar usa 12 bytes de nonce
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	// Cifrado con GCM, incluye el tag de autenticación
	cipherText := aesGCM.Seal(nil, nonce, []byte(data), nil)

	return nonce, cipherText, nil
}

func decryptData(c *client, nonce, cipherText []byte) (string, error) {
	// Verificar que cipherText no sea nil o vacío
	if len(cipherText) == 0 {
		return "", nil
	}

	// Verificar que nonce tenga la longitud correcta (12 bytes para AES-GCM)
	if len(nonce) != 12 {
		return "", fmt.Errorf("invalid nonce length: got %d, expected 12", len(nonce))
	}

	key := deriveKey(c)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plainText, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}
