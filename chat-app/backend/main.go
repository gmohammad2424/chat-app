package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	"github.com/supabase-community/supabase-go"
)

var (
	supabaseClient *supabase.Client
	encryptionKey  []byte
	upgrader       = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true // Adjust for production
		},
	}
	clients = make(map[*websocket.Conn]Client)
)

type Client struct {
	Conn      *websocket.Conn
	UserID    string
	ReceiverID string
	ChatID    string
}

type Message struct {
	Type      string    `json:"type"`
	Sender    string    `json:"sender"`
	Receiver  string    `json:"receiver"`
	Content   string    `json:"content,omitempty"`
	FileURL   string    `json:"file_url,omitempty"`
	FileType  string    `json:"file_type,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

type SignalMessage struct {
	Type      string      `json:"type"`
	Sender    string      `json:"sender"`
	Receiver  string      `json:"receiver"`
	Signal    interface{} `json:"signal"`
	Timestamp time.Time   `json:"timestamp"`
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	supabaseURL := os.Getenv("SUPABASE_URL")
	supabaseKey := os.Getenv("SUPABASE_ANON_KEY")
	jwtSecret := os.Getenv("JWT_SECRET")
	encKey := os.Getenv("ENCRYPTION_KEY")

	var err error
	encryptionKey, err = base64.StdEncoding.DecodeString(encKey)
	if err != nil {
		log.Fatalf("Invalid encryption key: %v", err)
	}
	if len(encryptionKey) != 32 {
		log.Fatal("Encryption key must be 32 bytes")
	}

	supabaseClient, err = supabase.NewClient(supabaseURL, supabaseKey, nil)
	if err != nil {
		log.Fatalf("Failed to initialize Supabase client: %v", err)
	}

	http.HandleFunc("/ws", handleWebSocket)
	http.HandleFunc("/upload", handleFileUpload)
	http.HandleFunc("/messages", handleGetMessages)

	log.Println("Server starting on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	receiverID := r.URL.Query().Get("receiver_id")
	chatID := r.URL.Query().Get("chat_id")

	if token == "" {
		http.Error(w, "Missing token", http.StatusUnauthorized)
		return
	}

	userID, err := verifyToken(token)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	if receiverID == "" || !isValidUUID(receiverID) {
		http.Error(w, "Invalid receiver_id", http.StatusBadRequest)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		http.Error(w, "WebSocket upgrade failed", http.StatusInternalServerError)
		return
	}

	client := Client{
		Conn:      conn,
		UserID:    userID,
		ReceiverID: receiverID,
		ChatID:    chatID,
	}
	clients[conn] = client

	defer func() {
		delete(clients, conn)
		conn.Close()
	}()

	if chatID == "" {
		chatID, err = getOrCreateChat(userID, receiverID)
		if err != nil {
			sendError(conn, fmt.Sprintf("Failed to create chat: %v", err))
			return
		}
		client.ChatID = chatID
		sendChatID(conn, chatID)
	}

	go handlePingPong(conn)

	for {
		var msg Message
		err := conn.ReadJSON(&msg)
		if err != nil {
			log.Printf("Read error: %v", err)
			break
		}
		msg.Timestamp = time.Now()

		if msg.Type == "pong" {
			continue
		}

		if msg.Type == "call_signal" {
			var signalMsg SignalMessage
			if err := json.Unmarshal([]byte(msg.Content), &signalMsg); err != nil {
				sendError(conn, fmt.Sprintf("Invalid signal message: %v", err))
				continue
			}
			signalMsg.Sender = userID
			signalMsg.Receiver = receiverID
			signalMsg.Timestamp = time.Now()
			broadcastSignal(signalMsg)
			continue
		}

		msg.Sender = userID
		msg.Receiver = receiverID

		if msg.Type == "text" {
			encryptedContent, err := encrypt(msg.Content)
			if err != nil {
				sendError(conn, fmt.Sprintf("Encryption failed: %v", err))
				continue
			}
			_, err = supabaseClient.From("messages").Insert(map[string]interface{}{
				"chat_id":   client.ChatID,
				"sender":    userID,
				"receiver":  receiverID,
				"type":      "text",
				"content":   encryptedContent,
				"timestamp": msg.Timestamp,
			}).Execute()
			if err != nil {
				sendError(conn, fmt.Sprintf("Failed to save message: %v", err))
				continue
			}
			msg.Content, _ = decrypt(encryptedContent)
		} else if msg.Type == "file" {
			encryptedFileURL, err := encrypt(msg.FileURL)
			if err != nil {
				sendError(conn, fmt.Sprintf("Encryption failed: %v", err))
				continue
			}
			_, err = supabaseClient.From("messages").Insert(map[string]interface{}{
				"chat_id":   client.ChatID,
				"sender":    userID,
				"receiver":  receiverID,
				"type":      "file",
				"file_url":  encryptedFileURL,
				"file_type": msg.FileType,
				"timestamp": msg.Timestamp,
			}).Execute()
			if err != nil {
				sendError(conn, fmt.Sprintf("Failed to save file message: %v", err))
				continue
			}
			msg.FileURL, _ = decrypt(encryptedFileURL)
		}

		broadcastMessage(msg, client.ChatID)
	}
}

func handleFileUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := r.Header.Get("Authorization")
	if strings.HasPrefix(token, "Bearer ") {
		token = strings.TrimPrefix(token, "Bearer ")
	} else {
		http.Error(w, "Missing token", http.StatusUnauthorized)
		return
	}

	userID, err := verifyToken(token)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	err = r.ParseMultipartForm(10 << 20) // 10MB
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse form: %v", err), http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get file: %v", err), http.StatusBadRequest)
		return
	}
	defer file.Close()

	fileExt := filepath.Ext(handler.Filename)
	fileName := fmt.Sprintf("%s%s", generateUUID(), fileExt)
	filePath := fmt.Sprintf("uploads/%s", fileName)

	fileBytes, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read file: %v", err), http.StatusInternalServerError)
		return
	}

	_, err = supabaseClient.Storage.From("files").Upload(filePath, fileBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to upload file: %v", err), http.StatusInternalServerError)
		return
	}

	fileURL := fmt.Sprintf("%s/storage/v1/object/public/files/%s", os.Getenv("SUPABASE_URL"), filePath)
	response := map[string]string{
		"file_url":  fileURL,
		"file_type": handler.Header.Get("Content-Type"),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleGetMessages(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if strings.HasPrefix(token, "Bearer ") {
		token = strings.TrimPrefix(token, "Bearer ")
	} else {
		http.Error(w, "Missing token", http.StatusUnauthorized)
		return
	}

	userID, err := verifyToken(token)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	chatID := r.URL.Query().Get("chat_id")
	if chatID == "" || !isValidUUID(chatID) {
		http.Error(w, "Invalid chat_id", http.StatusBadRequest)
		return
	}

	var messages []map[string]interface{}
	_, err = supabaseClient.From("messages").Select("*").Eq("chat_id", chatID).ExecuteTo(&messages)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch messages: %v", err), http.StatusInternalServerError)
		return
	}

	var decryptedMessages []map[string]interface{}
	for _, msg := range messages {
		decryptedMsg := make(map[string]interface{})
		for k, v := range msg {
			if k == "content" && v != nil {
				if str, ok := v.(string); ok {
					decrypted, _ := decrypt(str)
					decryptedMsg[k] = decrypted
				} else {
					decryptedMsg[k] = v
				}
			} else if k == "file_url" && v != nil {
				if str, ok := v.(string); ok {
					decrypted, _ := decrypt(str)
					decryptedMsg[k] = decrypted
				} else {
					decryptedMsg[k] = v
				}
			} else {
				decryptedMsg[k] = v
			}
		}
		decryptedMessages = append(decryptedMessages, decryptedMsg)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(decryptedMessages)
}

func verifyToken(token string) (string, error) {
	// Simplified; use JWT library in production
	userID, err := supabaseClient.Auth.User(context.Background(), token)
	if err != nil {
		return "", err
	}
	return userID.ID, nil
}

func getOrCreateChat(userID, receiverID string) (string, error) {
	var chats []map[string]interface{}
	_, err := supabaseClient.From("chats").Select("id").In("participant1", []string{userID, receiverID}).In("participant2", []string{userID, receiverID}).ExecuteTo(&chats)
	if err != nil {
		return "", err
	}

	if len(chats) > 0 {
		return chats[0]["id"].(string), nil
	}

	chatID := generateUUID()
	_, err = supabaseClient.From("chats").Insert(map[string]interface{}{
		"id":           chatID,
		"participant1": userID,
		"participant2": receiverID,
		"created_at":   time.Now(),
	}).Execute()
	if err != nil {
		return "", err
	}
	return chatID, nil
}

func broadcastMessage(msg Message, chatID string) {
	for conn, client := range clients {
		if client.ChatID == chatID && (client.UserID == msg.Sender || client.UserID == msg.Receiver) {
			err := conn.WriteJSON(msg)
			if err != nil {
				log.Printf("Write error: %v", err)
				conn.Close()
				delete(clients, conn)
			}
		}
	}
}

func broadcastSignal(signalMsg SignalMessage) {
	for conn, client := range clients {
		if client.UserID == signalMsg.Receiver {
			err := conn.WriteJSON(signalMsg)
			if err != nil {
				log.Printf("Write error: %v", err)
				conn.Close()
				delete(clients, conn)
			}
		}
	}
}

func sendError(conn *websocket.Conn, message string) {
	conn.WriteJSON(map[string]string{"type": "error", "error": message})
}

func sendChatID(conn *websocket.Conn, chatID string) {
	conn.WriteJSON(map[string]string{"type": "chat_id", "chat_id": chatID})
}

func handlePingPong(conn *websocket.Conn) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			err := conn.WriteJSON(map[string]string{"type": "ping", "timestamp": time.Now().String()})
			if err != nil {
				log.Printf("Ping error: %v", err)
				return
			}
		}
	}
}

func encrypt(plainText string) (string, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	plainBytes := []byte(plainText)
	cipherText := make([]byte, aes.BlockSize+len(plainBytes))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainBytes)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func decrypt(cipherText string) (string, error) {
	cipherBytes, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	if len(cipherBytes) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	iv := cipherBytes[:aes.BlockSize]
	cipherBytes = cipherBytes[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherBytes, cipherBytes)
	return string(cipherBytes), nil
}

func isValidUUID(id string) bool {
	return len(id) == 36 && strings.Count(id, "-") == 4
}

func generateUUID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatalf("Failed to generate UUID: %v", err)
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
