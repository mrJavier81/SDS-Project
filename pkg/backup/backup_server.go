package backup

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"prac/pkg/store"
)

type BackupServer struct {
	db              store.Store
	log             *log.Logger
	encryptionKey   []byte
	encryptionReady chan struct{}
}

func NewBackupServer(dbPath string) (*BackupServer, error) {
	db, err := store.NewStore("bbolt", dbPath)
	if (err != nil) {
		return nil, fmt.Errorf("error al abrir la base de datos de respaldo: %v", err)
	}

	// Inicializar el bucket 'logs'
	if err := db.Put("logs", []byte("__init__"), []byte("")); err != nil {
		return nil, fmt.Errorf("error al inicializar el bucket 'logs': %v", err)
	}

	bs := &BackupServer{
		db:              db, 
		log:             log.New(os.Stdout, "[backup] ", log.LstdFlags),
		encryptionReady: make(chan struct{}),
	}
	
	return bs, nil
}

// SetEncryptionKey establece la clave de cifrado para el servidor de backup
func (bs *BackupServer) SetEncryptionKey(key []byte) {
	bs.encryptionKey = key
	// Señalar que la clave está lista
	close(bs.encryptionReady)
}

func (bs *BackupServer) Start() {
	listener, err := net.Listen("tcp", ":9000")
	if err != nil {
		bs.log.Printf("Error al iniciar el servidor de respaldo: %v", err)
		return
	}
	defer listener.Close()

	bs.log.Println("Servidor de respaldo escuchando en el puerto 9000...")
	go bs.startPeriodicBackup()

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error al aceptar conexión:", err)
			continue
		}
		go bs.handleConnection(conn)
	}
}

func (bs *BackupServer) handleConnection(conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		command := scanner.Text()

		if command == "FETCH_LOGS" {
			// Enviar todos los logs al cliente
			keys, err := bs.db.ListKeys("logs")
			if err != nil {
				fmt.Fprintln(conn, "Error al obtener logs:", err)
				return
			}

			for _, key := range keys {
				value, _ := bs.db.Get("logs", key)
				// Enviar el log tal como está almacenado, manteniendo el prefijo ENCRYPTED: si existe
				fmt.Fprintln(conn, fmt.Sprintf("%s: %s", string(key), string(value)))
			}
			return
		}

		// Si no es un comando, se asume que es un log
		logMessage := command
				// Verificar si es un log cifrado (tiene prefijo ENCRYPTED:)
		originalMessage := logMessage
		if strings.HasPrefix(logMessage, "ENCRYPTED:") {
			// Preservamos el mensaje completo tal cual para almacenamiento
			originalMessage = logMessage
		}
		
		// Almacenar el log manteniendo el prefijo ENCRYPTED: si existe
		err := bs.db.Put("logs", []byte(time.Now().Format(time.RFC3339Nano)), []byte(originalMessage))
		if err != nil {
			fmt.Println("Error al guardar log:", err)
		}
	}
}

func (bs *BackupServer) startPeriodicBackup() {
	for {
		time.Sleep(24 * time.Hour) // Realizar backup cada 24 horas
		err := bs.performBackup()
		if err != nil {
			fmt.Println("Error al realizar backup:", err)
		} else {
			fmt.Println("Backup realizado con éxito.")
		}
	}
}

func (bs *BackupServer) performBackup() error {
	// Ruta del archivo de la base de datos principal
	sourceFile := "data/server.db"
	// Nombre del archivo de backup con marca de tiempo
	backupFile := fmt.Sprintf("backup_%s.db", time.Now().Format("20060102_150405"))

	// Leer el contenido del archivo fuente
	input, err := os.ReadFile(sourceFile)
	if err != nil {
		return fmt.Errorf("error al leer el archivo fuente (%s): %v", sourceFile, err)
	}

	// Si la clave de cifrado está disponible, cifrar el backup
	if bs.encryptionKey != nil {
		bs.log.Println("Cifrando archivo de backup...")
		input, err = encryptData(input, bs.encryptionKey)
		if err != nil {
			return fmt.Errorf("error al cifrar el backup: %v", err)
		}
		// Cambiar el nombre del archivo para indicar que está cifrado
		backupFile = fmt.Sprintf("encrypted_backup_%s.db", time.Now().Format("20060102_150405"))
	} else {
		bs.log.Println("ADVERTENCIA: Realizando backup sin cifrado - clave no disponible")
	}

	// Escribir el contenido en el archivo de backup
	err = os.WriteFile(backupFile, input, 0600)
	if err != nil {
		return fmt.Errorf("error al crear archivo de backup (%s): %v", backupFile, err)
	}

	fmt.Printf("Backup realizado: %s\n", backupFile)
	return nil
}

// encryptData cifra los datos utilizando AES-GCM y devuelve el ciphertext con el nonce adjunto.
func encryptData(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decryptData descifra los datos utilizando AES-GCM, asumiendo que el nonce está adjunto.
func decryptData(encryptedData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	return aesGCM.Open(nil, nonce, ciphertext, nil)
}
