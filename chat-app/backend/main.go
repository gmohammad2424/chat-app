package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"firebase.google.com/go/v4"
	"firebase.google.com/go/v4/messaging"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

var (
	clients      = make(map[string]*Client)
	messages     = make(map[string][]Message)
	clientsMutex sync.Mutex
	messagesMutex sync.Mutex
	fcmClient    *messaging.Client
)

type Client struct {
	Conn      *websocket.Conn
	PushToken string
}

type Message struct {
	Sender    string    `json:"sender"`
	Receiver  string    `json:"receiver"`
	Content   string    `json:"content,omitempty"`
	FileURL   string    `json:"file_url,omitempty"`
	FileType  string    `json:"file_type,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Status    string    `json:"status"`
}

type PushRegistration struct {
	Username string `json:"username"`
	Token    string `json:"token"`
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func main() {
	// Initialize Firebase Admin SDK
	ctx := context.Background()
	app, err := firebase.NewApp(ctx, nil)
	if err != nil {
		log.Fatalf("Error initializing Firebase app: %v\n", err)
	}

	fcmClient, err = app.Messaging(ctx)
	if err != nil {
		log.Fatalf("Error initializing FCM client: %v\n", err)
	}

	r := mux.NewRouter()

	// Serve static files
	r.PathPrefix("/frontend/").Handler(http.StripPrefix("/frontend/", http.FileServer(http.Dir("./frontend"))))

	// API routes
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/messages", authMiddleware(messagesHandler)).Methods("GET")
	r.HandleFunc("/register-push", authMiddleware(registerPushHandler)).Methods("POST")
	r.HandleFunc("/ws", wsHandler)

	// Root handler
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Chat App Backend")
	})

	// CORS middleware
	corsHandler := handlers.CORS(
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowedMethods([]string{"GET", "POST", "OPTIONS"}),
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization"}),
	)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server running on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, corsHandler(r)))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if creds.Username == "" || creds.Password == "" {
		http.Error(w, "Invalid credentials", http.StatusBadRequest)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": creds.Username,
		"exp":      time.Now().Add(time.Hour * 1).Unix(),
	})

	tokenString, err := token.SignedString([]byte("your_jwt_secret"))
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Token is required", http.StatusForbidden)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte("your_jwt_secret"), nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	}
}

func messagesHandler(w http.ResponseWriter, r *http.Request) {
	chatID := r.URL.Query().Get("chat_id")
	messagesMutex.Lock()
	defer messagesMutex.Unlock()

	chatMessages := messages[chatID]
	if chatMessages == nil {
		chatMessages = []Message{}
	}

	json.NewEncoder(w).Encode(chatMessages)
}

func registerPushHandler(w http.ResponseWriter, r *http.Request) {
	var pushReg PushRegistration
	if err := json.NewDecoder(r.Body).Decode(&pushReg); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if pushReg.Username == "" || pushReg.Token == "" {
		http.Error(w, "Username and token are required", http.StatusBadRequest)
		return
	}

	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	client, exists := clients[pushReg.Username]
	if !exists {
		client = &Client{}
	}
	client.PushToken = pushReg.Token
	clients[pushReg.Username] = client

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Push token registered"})
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade error:", err)
		return
	}

	clientsMutex.Lock()
	client, exists := clients[username]
	if !exists {
		client = &Client{}
	}
	client.Conn = conn
	clients[username] = client
	clientsMutex.Unlock()

	defer func() {
		clientsMutex.Lock()
		if client, exists := clients[username]; exists {
			client.Conn = nil // Keep the push token, just mark the WebSocket as closed
			clients[username] = client
		}
		clientsMutex.Unlock()
		conn.Close()
	}()

	for {
		var msg Message
		err := conn.ReadJSON(&msg)
		if err != nil {
			log.Println("WebSocket read error:", err)
			break
		}

		msg.Timestamp = time.Now()

		chatID := fmt.Sprintf("%s:%s", msg.Sender, msg.Receiver)
		reverseChatID := fmt.Sprintf("%s:%s", msg.Receiver, msg.Sender)

		messagesMutex.Lock()
		if _, exists := messages[chatID]; !exists {
			if _, exists := messages[reverseChatID]; !exists {
				messages[chatID] = []Message{}
			}
		}

		targetChatID := chatID
		if _, exists := messages[chatID]; !exists {
			targetChatID = reverseChatID
		}

		messages[targetChatID] = append(messages[targetChatID], msg)
		messagesMutex.Unlock()

		clientsMutex.Lock()
		receiverClient, exists := clients[msg.Receiver]
		if exists && receiverClient.Conn != nil {
			err = receiverClient.Conn.WriteJSON(msg)
			if err != nil {
				log.Println("WebSocket write error:", err)
			}
		} else if exists && receiverClient.PushToken != "" {
			// Send push notification via FCM
			message := &messaging.Message{
				Notification: &messaging.Notification{
					Title: fmt.Sprintf("New message from %s", msg.Sender),
					Body:  msg.Content,
				},
				Token: receiverClient.PushToken,
			}

			_, err := fcmClient.Send(context.Background(), message)
			if err != nil {
				log.Printf("Error sending push notification to %s: %v", msg.Receiver, err)
			} else {
				log.Printf("Push notification sent to %s", msg.Receiver)
			}
		}
		clientsMutex.Unlock()
	}
}
