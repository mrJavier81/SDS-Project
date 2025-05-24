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
	"crypto/ed25519"

	"golang.org/x/crypto/nacl/box"

	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"

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
	privateKey  *rsa.PrivateKey //Descomentar si generar la clave cada vez es muy lento
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
		title := "Menú"
		if c.currentUser != "" {
			title = fmt.Sprintf("Menú (%s) — rol: %s", c.currentUser, c.userRole)
		}

		var options []string

		if c.currentUser == "" {
			// no autenticado
			options = []string{
				"Registrar usuario",
				"Iniciar sesión",
				"Salir",
			}
		} else {
			// autenticado: menú por rol
			switch c.userRole {
			case "superadmin":
				options = []string{
					"Ver votaciones",
					"Ver datos",
					"Actualizar datos",
					"Enviar mensaje",
					"Administrar votaciones",
					"Administrar usuarios",
					"Ver logs del sistema",
					"Cerrar sesión",
					"Salir",
				}
			case "admin":
				options = []string{
					"Ver votaciones",
					"Ver datos",
					"Actualizar datos",
					"Enviar mensaje",
					"Administrar votaciones",
					"Cerrar sesión",
					"Salir",
				}
			default: // "user"
				options = []string{
					"Ver votaciones",
					"Ver datos",
					"Actualizar datos",
					"Enviar mensaje",
					"Cerrar sesión",
					"Salir",
				}
			}
		}

		choice := ui.PrintMenu(title, options)

		// DESPACHAMOS según el rol y la elección
		if c.currentUser == "" {
			switch choice {
			case 1:
				c.registerUser()
			case 2:
				c.loginUser()
			case 3:
				c.log.Println("Saliendo del cliente…")
				return
			}
		} else {
			// usuario autenticado
			idx := 0
			// estas acciones van en todos los roles
			switch choice {
			case idx + 1:
				c.verVotaciones()
				idx++
			case idx + 2:
				c.fetchData()
				idx++
			case idx + 3:
				c.updateData()
				idx++
			case idx + 4:
				c.sendMessage()
				idx++
			default:
				// los siguientes dependen del rol
				switch c.userRole {
				case "superadmin":
					// índices 5,6,7,8,9
					switch choice {
					case 5:
						c.administrarVotaciones()
					case 6:
						c.administrarUsuarios()
					case 7:
						c.verLogs() // nueva función desde menú principal
					case 8:
						c.logoutUser()
					case 9:
						c.log.Println("Saliendo…")
						return
					}
				case "admin":
					// índices 5,6,7
					switch choice {
					case 5:
						c.administrarVotaciones()
					case 6:
						c.logoutUser()
					case 7:
						c.log.Println("Saliendo…")
						return
					}
				default: // user
					// índices 5,6
					switch choice {
					case 5:
						c.logoutUser()
					case 6:
						c.log.Println("Saliendo…")
						return
					}
				}
			}
		}

		ui.Pause("Pulsa [Enter] para continuar…")
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
		rawOptions := strings.Split(ui.ReadInput("Opciones de la votación (separadas por comas)"), ",")

		// Eliminar opciones vacías y duplicadas
		optionSet := make(map[string]struct{})
		var options []string
		for _, opt := range rawOptions {
			opt = strings.TrimSpace(opt)
			if opt == "" {
				continue
			}
			if _, exists := optionSet[opt]; !exists {
				optionSet[opt] = struct{}{}
				options = append(options, opt)
			}
		}

		if len(options) <= 1 {
			fmt.Println("Debes introducir al menos una opción válida y no repetida.")
			return
		}

		duration := ui.ReadInput("Duración de la votación (en horas)")
		creador := c.currentUser
		res := c.sendRequest(api.Request{
			Action:   api.ActionCreatePoll,
			Role:     c.userRole,
			Question: question,
			Options:  options,
			Data:     duration,
			Creador:  creador,
		})
		fmt.Println("Resultado:", res.Message)
	case 2:
		// Modificar votación
		pollID := ui.ReadInput("ID de la votación a modificar")
		newQuestion := ui.ReadInput("Nueva pregunta de la votación")
		rawOptions := strings.Split(ui.ReadInput("Nuevas opciones de la votación (separadas por comas)"), ",")

		// Eliminar opciones vacías y duplicadas
		optionSet := make(map[string]struct{})
		var newOptions []string
		for _, opt := range rawOptions {
			opt = strings.TrimSpace(opt)
			if opt == "" {
				continue
			}
			if _, exists := optionSet[opt]; !exists {
				optionSet[opt] = struct{}{}
				newOptions = append(newOptions, opt)
			}
		}

		if len(newOptions) == 0 {
			fmt.Println("Debes introducir al menos una opción válida y no repetida.")
			return
		}

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
		c.verVotacionesActivas()
	case 2:
		// Ver votaciones en las que participas
		res := c.sendRequest(api.Request{
			Action: api.ActionFetchPolls,
			Role:   c.userRole,
			Data:   "participated",
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
			Data:   "past",
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

func (c *client) verVotacionesActivas() {

	ui.ClearScreen()
	fmt.Println("** Ver votaciones activas **")

	// Enviar solicitud al servidor para obtener las votaciones activas
	res := c.sendRequest(api.Request{
		Action: api.ActionFetchPolls,
		Role:   c.userRole,
	})

	if res.Success {
		fmt.Println("Votaciones activas:")
		fmt.Println(res.Data)

	} else {
		fmt.Println("Error al obtener votaciones:", res.Message)
	}
	input := ui.ReadInput("Selecciona una votación o pulsa [Enter] para volver al menú principal")

	if input == "" {
		return
	}

	res = c.sendRequest(api.Request{
		Action: api.ActionGetPollByID,
		PollID: input,
	})

	if res.Success {
		var poll struct {
			ID           string          `json:"ID"`
			Question     string          `json:"Question"`
			Options      map[string]int  `json:"Options"`
			FechaInicio  string          `json:"FechaInicio"`
			FechaFin     string          `json:"FechaFin"`
			Creador      string          `json:"Creador"`
			Estado       string          `json:"Estado"`
			Participants map[string]bool `json:"Participants"`
		}
		err := json.Unmarshal([]byte(res.Data), &poll)
		if err != nil {
			fmt.Println("Error al procesar la encuesta:", err)
			return
		}
		fmt.Println("------ Detalles de la votación ------")
		fmt.Printf("ID: %s\n", poll.ID)
		fmt.Printf("Pregunta: %s\n", poll.Question)
		fmt.Printf("Opciones:\n")
		for opt, votos := range poll.Options {
			fmt.Printf("  - %s: %d votos\n", opt, votos)
		}
		fmt.Printf("Creador: %s\n", poll.Creador)
		fmt.Printf("Estado: %s\n", poll.Estado)
		fmt.Printf("Fecha de inicio: %s\n", poll.FechaInicio)
		fmt.Printf("Fecha de fin: %s\n", poll.FechaFin)
		fmt.Printf("Participantes: %d\n", len(poll.Participants))
		fmt.Println("-------------------------------------")
		if ui.ReadInput("¿Quieres votar? (s/n)") == "s" {
			// Votar
			option := ui.ReadInput("Selecciona una opción para votar")
			res := c.sendRequest(api.Request{
				Action: api.ActionVote,
				PollID: poll.ID,
				Option: option,
			})
			if res.Success {
				fmt.Println("Voto registrado con éxito.")
			} else {
				fmt.Println("Error al registrar el voto:", res.Message)
			}
		}

	} else {
		fmt.Println("Error al obtener detalles de la votación:", res.Message)
	}

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

func (c *client) verLogs() {
	ui.ClearScreen()
	fmt.Println("** Logs del sistema **")

	// Enviar solicitud al servidor para obtener los logs
	res := c.sendRequest(api.Request{
		Action: api.ActionFetchLogs,
		Role:   c.userRole,
	})

	if res.Success {
		fmt.Println("Logs del sistema:")
		fmt.Println(res.Data)
	} else {
		fmt.Println("Error al obtener logs:", res.Message)
	}
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

	res := c.sendRequest(api.Request{
		Action:   api.ActionRegister,
		Username: username,
		Password: kKey,
	})

	// Mostrar resultado
	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si fue exitoso, guardar la clave privada cifrada en el servidor o localmente
	// Almacenar clave privada cifrada y clave pública
	if res.Success {
		privateKey, err := generateRSAKeyPair()
		if err != nil {
			fmt.Println("Error al generar clave:", err)
			return
		}

		privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

		c.currentUser = username

		// Cifrado binario real
		nonce, encryptedPrivateKey, err := encryptData(c, privateKeyBytes)
		if err != nil {
			fmt.Println("Error al cifrar clave privada:", err)
			return
		}

		finalPayload := append(nonce, encryptedPrivateKey...)
		encodedData := hex.EncodeToString(finalPayload)

		res = c.sendRequest(api.Request{
			Action:   api.ActionSavePrivateKey,
			Username: username,
			Token:    c.authToken,
			Data:     encodedData,
		})

		if res.Success {
			fmt.Println("Clave privada guardada con éxito.")
		} else {
			fmt.Println("Error al guardar la clave privada:", res.Message)
		}

		// Serializar y enviar clave pública
		publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			fmt.Println("Error al serializar la clave pública:", err)
			return
		}

		publicKeyHex := hex.EncodeToString(publicKeyBytes)
		res = c.sendRequest(api.Request{
			Action:   api.ActionSavePublicKey,
			Username: username,
			Token:    c.authToken,
			Data:     publicKeyHex,
		})

		if res.Success {
			fmt.Println("Clave pública guardada con éxito.")
			res = c.sendRequest(api.Request{
				Action:   api.ActionLogin,
				Username: username,
				Password: kKey,
			})
			if res.Success {
				c.currentUser = username
				c.authToken = res.Token
				c.userRole = res.Data
				fmt.Println("Inicio de sesión automático exitoso.")
			}
		} else {
			fmt.Println("Error al guardar la clave pública:", res.Message)
		}
	}
}

// loginUser pide credenciales y realiza un login en el servidor.
func (c *client) loginUser() {
	ui.ClearScreen()
	fmt.Println("** Inicio de sesión **")

	username := ui.ReadInput("Nombre de usuario")
	password := ui.ReadInput("Contraseña")

	// Hash de la contraseña
	kKey, kData := hashPassword(password)

	// Guardamos kData para uso futuro
	c.kData = kData

	// Enviar la solicitud de inicio de sesión al servidor
	res := c.sendRequest(api.Request{
		Action:   api.ActionLogin,
		Username: username,
		Password: kKey,
	})

	if res.Success {
		c.currentUser = username
		c.authToken = res.Token
		c.userRole = res.Data

		// Recuperar la clave privada cifrada del servidor
		// Recuperar clave privada cifrada
		res := c.sendRequest(api.Request{
			Action:   api.ActionFetchPrivateKey,
			Username: username,
			Token:    c.authToken,
		})

		if res.Success {
			encryptedPrivateKey, err := hex.DecodeString(res.Data)
			if err != nil {
				fmt.Println("Error al decodificar la clave:", err)
				return
			}
			if len(encryptedPrivateKey) < 12 {
				fmt.Println("Error: datos inválidos, nonce insuficiente.")
				return
			}

			nonce := encryptedPrivateKey[:12]
			cipherText := encryptedPrivateKey[12:]

			// Descifrado binario real
			decryptedBytes, err := decryptData(c, nonce, cipherText)
			if err != nil {
				fmt.Println("Error al descifrar la clave privada:", err)
				return
			}

			privateKey, err := x509.ParsePKCS1PrivateKey(decryptedBytes)
			if err != nil {
				fmt.Println("Error al reconstruir la clave privada:", err)
				return
			}

			c.privateKey = privateKey

			fmt.Println("Clave privada cargada con éxito.")
		} else {
			fmt.Println("Error al recuperar clave privada:", res.Message)
		}

		// Recuperar mensajes del servidor
		res = c.sendRequest(api.Request{
			Action:   api.ActionFetchMessages,
			Username: c.currentUser,
			Token:    c.authToken,
		})

		if res.Success {
			fmt.Println("Mensajes recibidos:")

			// Supongamos que los mensajes vienen en formato JSON con los campos "Sender" y "Message"
			var messages []struct {
				Sender  string `json:"Sender"`  // Clave pública del remitente (hexadecimal)
				Message string `json:"Message"` // Mensaje cifrado (hexadecimal)
			}

			// Decodificar los mensajes recibidos
			err := json.Unmarshal([]byte(res.Data), &messages)
			if err != nil {
				fmt.Println("Error al procesar los mensajes:", err)
				return
			}

			// Procesar y descifrar cada mensaje
			for _, msg := range messages {
				fmt.Printf("\nMensaje recibido de: %s\n", msg.Sender)
				encryptedMessage, err := hex.DecodeString(msg.Message)
				if err != nil {
					fmt.Println("Error al decodificar el mensaje cifrado:", err)
					continue
				}

				// Descifrar el mensaje con la clave privada del cliente
				decryptedMessage, err := decryptMessageWithPrivateKey(c, encryptedMessage)
				if err != nil {
					fmt.Println("Error al descifrar el mensaje:", err)
					continue
				}

				// Mostrar el mensaje descifrado
				fmt.Printf("Mensaje descifrado: %s\n", decryptedMessage)
			}
		} else {
			fmt.Println("Error al recuperar mensajes:", res.Message)
		}
	} else {
		fmt.Println("Error al iniciar sesión:", res.Message)
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

		fmt.Println("Tus datos descodificados:", payload)

		if len(payload) < 12 {
			fmt.Println("Datos inválidos: falta el nonce")
			return
		}

		// Extraer nonce y ciphertext
		nonce := payload[:12]
		encryptedData := payload[12:]

		if len(encryptedData) == 0 {
			fmt.Println("No tienes datos almacenados.")
			return
		}

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
	nonce, encryptedData, err := encryptData(c, []byte(newData))
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
		print(c.currentUser, " ", c.authToken)
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

	// Cargar los certificados
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		fmt.Println("Error al cargar los certificados:", err)
		return api.Response{Success: false, Message: "Error al cargar certificados"}
	}

	// Crear un pool de certificados raíz
	caCertPool := x509.NewCertPool()

	// Si estás usando un certificado autofirmado, puedes cargarlo aquí
	caCert, err := os.ReadFile("cert.pem")
	if err != nil {
		fmt.Println("Error al leer el certificado raíz:", err)
		return api.Response{Success: false, Message: "Error al leer certificado raíz"}
	}
	caCertPool.AppendCertsFromPEM(caCert)

	// Configurar el cliente HTTP con los certificados
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{cert},
				RootCAs:            caCertPool,
				InsecureSkipVerify: false, // Asegúrate de validar el certificado del servidor
			},
		},
	}

	// Realizar la solicitud POST
	resp, err := client.Post("https://localhost:8443/api", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Error al contactar con el servidor:", err)
		return api.Response{Success: false, Message: "Error de conexión"}
	}
	defer resp.Body.Close()

	// Leer el cuerpo de la respuesta y desempaquetarlo en un api.Response
	body, _ := io.ReadAll(resp.Body)
	var res api.Response
	_ = json.Unmarshal(body, &res)
	return res
}

func (c *client) sendMessage() {
	fmt.Println("** Enviar mensaje **")
	print(c.currentUser, " ", c.authToken)
	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return
	}

	// Introducir nombre de usuario destinatario
	destinatario := ui.ReadInput("Nombre de usuario del destinatario")

	// Comprobar si el destinatario es válido
	if destinatario == "" {
		fmt.Println("Nombre de usuario inválido.")
		return
	}

	// Verificar si el destinatario existe
	res := c.sendRequest(api.Request{
		Action:   api.ActionCheckUser,
		Username: c.currentUser,
		Token:    c.authToken,
		Dest:     destinatario,
	})

	if !res.Success {
		fmt.Println("El usuario no existe.")
		return
	}

	// Obtener la clave pública del destinatario
	res = c.sendRequest(api.Request{
		Action:   api.ActionGetPublicKey,
		Username: c.currentUser,
		Token:    c.authToken,
		Dest:     destinatario,
	})

	if !res.Success {
		fmt.Println("Error al obtener la clave pública del destinatario:", res.Message)
		return
	}

	// Convertir la clave pública del destinatario de hexadecimal a *rsa.PublicKey
	publicKeyReceptor, err := stringToRSAPublicKey(res.Data)

	if err != nil {
		fmt.Println("Error al convertir la clave pública:", err)
		return
	}

	// Leer el mensaje a enviar
	message := ui.ReadInput("Introduce el mensaje")

	// Cifrar el mensaje con la clave pública del destinatario
	encryptedMessage, err := encryptMessageWithPublicKey(publicKeyReceptor, message)
	if err != nil {
		fmt.Println("Error al cifrar el mensaje:", err)
		return
	}

	encryptedMessageHex := hex.EncodeToString(encryptedMessage)

	// Enviar el mensaje cifrado al servidor
	res = c.sendRequest(api.Request{
		Action:   api.ActionSendMessage,
		Username: c.currentUser,
		Token:    c.authToken,
		Dest:     destinatario,
		Data:     encryptedMessageHex,
	})

	// Mostrar el resultado
	if res.Success {
		fmt.Printf("Mensaje enviado con éxito a %v\n", destinatario)
	} else {
		fmt.Println("Error al enviar el mensaje:", res.Message)
	}
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
func encryptData(c *client, data []byte) ([]byte, []byte, error) {
	key := deriveKey(c)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, 12) // GCM usa 12 bytes de nonce
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	cipherText := aesGCM.Seal(nil, nonce, data, nil)
	return nonce, cipherText, nil
}

// Descifrar datos con AES-256 GCM
func decryptData(c *client, nonce, cipherText []byte) ([]byte, error) {
	if len(cipherText) == 0 {
		return nil, nil
	}
	if len(nonce) != 12 {
		return nil, fmt.Errorf("invalid nonce length: got %d, expected 12", len(nonce))
	}

	key := deriveKey(c)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plainText, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

// Esta función genera la clave privada del cliente a partir de una semilla
// obtenida a partir de su contraseña y con salt del nombre
func generatePrivateKeyFromPassword(c *client) ed25519.PrivateKey {
	seed, err := scrypt.Key([]byte(c.kData), []byte(c.currentUser), 32768, 8, 1, 32)
	if err != nil {
		fmt.Errorf("Error al derivar la semilla: %v", err)
	}

	// Generamos la clave privada mediante el algoritmo ed25519 a partir de la semilla generada
	privateKey := ed25519.NewKeyFromSeed(seed)

	// Guardamos la clave privada en el cliente

	return privateKey
}

/*publicKey := privateKey.Public().(ed25519.PublicKey)

c.sendRequest(api.Request{
	Action:   api.ActionSavePublicKey,
	Username: c.currentUser,
	Token:    c.authToken,
	Data:     hex.EncodeToString(publicKey),
})
*/ //Esto es el fragmento para que se guarde la clave publica en el servidor usalo donde te salga de los huitos

// En vez de generar
func getKeyPairFromPassword(c *client) (*[32]byte, *[32]byte) {
	// Derivamos la semilla a partir de kData y el nombre de usuario
	seed, err := scrypt.Key([]byte(c.kData), []byte(c.currentUser), 32768, 8, 1, 32)
	if err != nil {
		log.Fatal("Error al derivar la semilla:", err)
	}

	// Declaramos la semilla con longitud fija de 32 bytes,
	// que es necesario para la clave pública y privada de ed25519

	publicKey, privateKey, _ := box.GenerateKey(bytes.NewReader(seed))

	return publicKey, privateKey
}

// Enviamos la clave pública al servidor
func sendPublicKeyToServer(c *client) {
	publicKey, _ := getKeyPairFromPassword(c)
	if publicKey == nil {
		fmt.Println("Error al obtener la clave pública.")
		return
	}

	pKeySend := hex.EncodeToString(publicKey[:])

	fmt.Printf("Clave pública generada: %s\n", pKeySend)

	res := c.sendRequest(api.Request{
		Action:   api.ActionSavePublicKey,
		Username: c.currentUser,
		Token:    c.authToken,
		Data:     pKeySend,
	})

	if !res.Success {
		fmt.Println("Error al enviar la clave pública:", res.Message)
		return
	}
	// Si la respuesta es exitosa, mostramos un mensaje
	// de confirmación
	// y guardamos la clave pública en el cliente

	fmt.Println("Clave pública enviada al servidor.")
}

func stringToPublicKey(hexString string) (*[32]byte, error) {
	// Decode the hex string to bytes
	publicKeyBytes, err := hex.DecodeString(hexString)
	if err != nil {
		return nil, fmt.Errorf("error al decodificar clave pública: %v", err)
	}

	// Ensure the public key is the correct length
	if len(publicKeyBytes) != 32 {
		return nil, fmt.Errorf("clave pública inválida: longitud incorrecta")
	}

	// Convert the bytes to a [32]byte array
	var publicKey [32]byte
	copy(publicKey[:], publicKeyBytes)

	return &publicKey, nil
}

func generateRSAKeyPair() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048) // 2048 bits es un tamaño seguro
	if err != nil {
		return nil, fmt.Errorf("error al generar el par de claves RSA: %v", err)
	}
	return privateKey, nil
}

func encryptMessageWithPublicKey(publicKey *rsa.PublicKey, message string) ([]byte, error) {
	encryptedMessage, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, []byte(message), nil)
	if err != nil {
		return nil, fmt.Errorf("error al cifrar el mensaje: %v", err)
	}
	return encryptedMessage, nil
}

func decryptMessageWithPrivateKey(c *client, encryptedMessage []byte) (string, error) {
	decryptedMessage, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, c.privateKey, encryptedMessage, nil)

	if err != nil {
		return "", fmt.Errorf("error al descifrar el mensaje: %v", err)
	}
	return string(decryptedMessage), nil
}

func stringToRSAPublicKey(hexString string) (*rsa.PublicKey, error) {
	// Decodificar la clave pública de hexadecimal a bytes
	publicKeyBytes, err := hex.DecodeString(hexString)
	if err != nil {
		return nil, fmt.Errorf("error al decodificar clave pública: %v", err)
	}

	// Reconstruir la clave pública desde los bytes
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error al reconstruir la clave pública: %v", err)
	}

	// Asegurarse de que sea del tipo *rsa.PublicKey
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("la clave pública no es de tipo RSA")
	}

	return rsaPublicKey, nil
}
