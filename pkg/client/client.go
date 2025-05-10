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
	//privKey     ed25519.PrivateKey   //Descomentar si generar la clave cada vez es muy lento
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
			// Usuario logueado: Ver votaciones, Ver datos, etc.
			options = []string{
				"Ver votaciones",
				"Ver datos",
				"Actualizar datos",
				"Enviar mensaje",
				"Cerrar sesión",
				"Administrar usuarios",
				"Administrar votaciones",
				"Salir",
			}
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
				c.sendMessage()
			case 5:
				c.logoutUser()
			case 6:
				c.administrarUsuarios()
			case 7:
				c.administrarVotaciones()
			case 8:
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
		"Ver logs del sistema", // Nueva opción para ver los logs
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
		// Ver logs del sistema
		c.verLogs()
	case 5:
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

			// Generar y enviar la clave pública al servidor
			sendPublicKeyToServer(c)

		} else {
			fmt.Println("No se ha podido hacer login automático:", loginRes.Message)
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

	// Enviamos la solicitud de inicio de sesión al servidor
	res := c.sendRequest(api.Request{
		Action:   api.ActionLogin,
		Username: username,
		Password: kKey,
	})

	// Mostramos el resultado de la solicitud
	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si el inicio de sesión fue exitoso
	if res.Success {
		c.currentUser = username
		c.authToken = res.Token
		c.userRole = res.Data
		fmt.Printf("Sesión iniciada como %v. Token guardado.\n", c.userRole)

		//privateKey := generatePrivateKeyFromPassword(c)
	}

	res = c.sendRequest(api.Request{
		Action:   api.ActionFetchMessages,
		Username: c.currentUser,
		Token:    c.authToken,
	})
	if res.Success {
		fmt.Println("Mensajes recibidos:")

		for _, message := range res.Messages {
			// Decodificar el mensaje de hexadecimal a bytes

			fmt.Println("Mensaje recibido:", message)
			// Convertir el mensaje a json
			messageData, err := hex.DecodeString(message)

			if err != nil {
				fmt.Println("Error al decodificar el mensaje:", err)
				continue
			}

			fmt.Println("Mensaje decodificado:", string(messageData))

			// Hecho mediante vibe coding

			encryptedMessage := messageData
			if err != nil {
				fmt.Println("Error al decodificar el mensaje:", err)
				continue
			}

			// Separar el nonce y el mensaje cifrado
			if len(encryptedMessage) < 24 {
				fmt.Println("Mensaje cifrado inválido: falta el nonce")
				continue
			}
			var nonce [24]byte
			copy(nonce[:], encryptedMessage[:24])
			cipherText := encryptedMessage[24:]

			// Descifrar el mensaje
			_, privateKey := getKeyPairFromPassword(c)

			publicRemitenteKey := 
			decryptedMessage, ok := box.Open(nil, cipherText, &nonce, nil, privateKey)
			if !ok {
				fmt.Println("Error al descifrar el mensaje")
				continue
			}

			// Mostrar el mensaje descifrado
			fmt.Println("Mensaje descifrado: Usuario " /*messageData["sender"],*/, string(decryptedMessage))
		}
	} else {
		fmt.Println("Error al recibir mensajes:", res.Message)
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

	// Aqui vas a encriptar el mensaje con la clave publica del destinatario
	// y luego enviarlo al servidor

	res := c.sendRequest(api.Request{
		Action:   api.ActionCheckUser,
		Username: c.currentUser,
		Token:    c.authToken,
		Dest:     destinatario,
	})

	if res.Success {
		fmt.Println("El usuario es válido.")
	} else {
		fmt.Println("El usuario no existe.")
		return
	}

	message := ui.ReadInput("Introduce el mensaje")

	res = c.sendRequest(api.Request{
		Action:   api.ActionGetPublicKey,
		Username: c.currentUser,
		Token:    c.authToken,
	})

	// Clave pública del destinatario
	publicKeyReceptor, err := stringToPublicKey(res.Data)

	if err != nil {
		fmt.Println("Error al convertir la clave pública:", err)
		return
	}

	_, privateKey := getKeyPairFromPassword(c)

	var nonce [24]byte

	if _, err := rand.Read(nonce[:]); err != nil {
		fmt.Printf("Error al generar nonce: %v", err)
		return
	}
	// Cifrar el mensaje con la clave pública del destinatario
	encryptedMessage := box.Seal(nil, []byte(message), &nonce, publicKeyReceptor, privateKey)

	// Convertir el mensaje cifrado a una cadena hexadecimal para enviarlo
	encryptedMessageHex := hex.EncodeToString(encryptedMessage)

	res = c.sendRequest(api.Request{
		Action:   api.ActionSendMessage,
		Username: c.currentUser,
		Token:    c.authToken,
		Dest:     destinatario,
		Data:     encryptedMessageHex,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
	if res.Success {
		fmt.Println("Mensaje enviado a", destinatario)
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
