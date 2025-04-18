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
	"github.com/joho/godotenv"
	"github.com/supabase-community/supabase-go"
)

// Global variables
var (
	clients      = make(map[string]*Client) // Map of usernames to WebSocket clients
	clientsMutex sync.Mutex                 // Mutex for thread-safe access
	fcmClient    *messaging.Client          // Firebase Cloud Messaging client
	supabase     *supabase.Client           // Supabase client
	jwtSecret    string                     // JWT secret from environment
)

// Client struct to store WebSocket connection and push token
type Client struct {
	Conn      *websocket.Conn
	PushToken string
}

// Message struct for chat messages
type Message struct {
	Type      string    `json:"type"`      // "text", "file", "call_signal"
	Sender    string    `json:"sender"`
	Receiver  string    `json:"receiver"`
	Content   string    `json:"content,omitempty"`
	FileURL   string    `json:"file_url,omitempty"`
	FileType  string    `json:"file_type,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Status    string    `json:"status"`
	Signal    SignalData `json:"signal,omitempty"` // For WebRTC signaling
}

// SignalData for WebRTC signaling messages
type SignalData struct {
	Type       string      `json:"type"`       // "offer", "answer", "ice-candidate", "call-initiate", "call-accept", "call-reject"
	Offer      interface{} `json:"offer,omitempty"`
	Answer     interface{} `json:"answer,omitempty"`
	Candidate  interface{} `json:"candidate,omitempty"`
	CallType   string      `json:"call_type,omitempty"` // "video" or "audio"
	CallStatus string      `json:"call_status,omitempty"`
}

// User struct for registration
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// PushRegistration struct for FCM tokens
type PushRegistration struct {
	Username string `json:"username"`
	Token    string `json:"token"`
}

// WebSocket upgrader
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func main() {
	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found, relying on environment variables")
	}

	// Get JWT secret
	jwtSecret = os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable is required")
	}

	// Initialize Supabase
	supabaseURL := os.Getenv("SUPABASE_URL")
	supabaseKey := os.Getenv("SUPABASE_KEY")
	if supabaseURL == "" || supabaseKey == "" {
		log.Fatal("SUPABASE_URL and SUPABASE_KEY environment variables are required")
	}
	supabase, err = supabase.InitClient(supabaseURL, supabaseKey, nil)
	if err != nil {
		log.Fatalf("Error initializing Supabase client: %v\n", err)
	}

	// Initialize Firebase
	ctx := context.Background()
	app, err := firebase.NewApp(ctx, nil)
	if err != nil {
		log.Fatalf("Error initializing Firebase app: %v\n", err)
	}
	fcmClient, err = app.Messaging(ctx)
	if err != nil {
		log.Fatalf("Error initializing FCM client: %v\n", err)
	}

	// Initialize router
	r := mux.NewRouter()

	// Serve static files
	r.PathPrefix("/frontend/").Handler(http.StripPrefix("/frontend/", http.FileServer(http.Dir("./frontend"))))

	// API routes
	r.HandleFunc("/register", registerHandler).Methods("POST")
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

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server running on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, corsHandler(r)))
}

// Register handler
func registerHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if user.Username == "" || user.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	// Check if user exists
	var existingUsers []map[string]interface{}
	_, err := supabase.DB.From("users").Select("*").Eq("username", user.Username).Execute(&existingUsers)
	if err != nil {
		log.Printf("Error checking user in Supabase: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if len(existingUsers) > 0 {
		http.Error(w, "Username already exists", http.StatusConflict)
		return
	}

	// Insert new user
	newUser := map[string]interface{}{
		"username": user.Username,
		"password": user.Password, // In production, hash the password
	}
	var result []map[string]interface{}
	_, err = supabase.DB.From("users").Insert(newUser).Execute(&result)
	if err != nil {
		log.Printf("Error registering user in Supabase: %v", err)
		http.Error(w, "Failed to register user", http.StatusInternalServerError)
		return
	}

	log.Printf("User registered: %s", user.Username)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
}

// Login handler
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

	// Verify user
	var users []map[string]interface{}
	_, err := supabase.DB.From("users").Select("*").Eq("username", creds.Username).Execute(&users)
	if err != nil {
		log.Printf("Error fetching user from Supabase: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if len(users) == 0 {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	user := users[0]
	storedPassword := user["password"].(string)
	if storedPassword != creds.Password {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Generate JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": creds.Username,
		"exp":      time.Now().Add(time.Hour * 1).Unix(),
	})

	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

// Authentication middleware
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
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	}
}

// Messages handler
func messagesHandler(w http.ResponseWriter, r *http.Request) {
	chatID := r.URL.Query().Get("chat_id")
	if chatID == "" {
		http.Error(w, "Chat ID is required", http.StatusBadRequest)
		return
	}

	parts := strings.Split(chatID, ":")
	if len(parts) != 2 {
		http.Error(w, "Invalid chat ID format", http.StatusBadRequest)
		return
	}
	sender, receiver := parts[0], parts[1]

	var messages []Message
	_, err := supabase.DB.From("messages").
		Select("*").
		Or(fmt.Sprintf("and(sender.eq.%s,receiver.eq.%s),and(sender.eq.%s,receiver.eq.%s)", sender, receiver, receiver, sender)).
		Order("timestamp", "asc").
		Execute(&messages)
	if err != nil {
		log.Printf("Error fetching messages from Supabase: %v", err)
		http.Error(w, "Failed to fetch messages", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(messages)
}

// Push registration handler
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
	client, exists := clients[pushReg.Username]
	if !exists {
		client = &Client{}
	}
	client.PushToken = pushReg.Token
	clients[pushReg.Username] = client
	clientsMutex.Unlock()

	log.Printf("Push token registered for user: %s", pushReg.Username)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Push token registered"})
}

// WebSocket handler
func wsHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade error:", err)
		return
	}

	// Register client
	clientsMutex.Lock()
	client, exists := clients[username]
	if !exists {
		client = &Client{}
	}
	client.Conn = conn
	clients[username] = client
	clientsMutex.Unlock()

	// Clean up on disconnect
	defer func() {
		clientsMutex.Lock()
		if client, exists := clients[username]; exists {
			client.Conn = nil
			clients[username] = client
		}
		clientsMutex.Unlock()
		conn.Close()
		log.Printf("WebSocket connection closed for user: %s", username)
	}()

	log.Printf("WebSocket connection established for user: %s", username)

	// Handle incoming messages
	for {
		var msg Message
		err := conn.ReadJSON(&msg)
		if err != nil {
			log.Println("WebSocket read error:", err)
			break
		}

		// Set timestamp
		msg.Timestamp = time.Now()

		// Handle different message types
		switch msg.Type {
		case "text", "file":
			// Store message in Supabase
			newMessage := map[string]interface{}{
				"sender":    msg.Sender,
				"receiver":  msg.Receiver,
				"content":   msg.Content,
				"file_url":  msg.FileURL,
				"file_type": msg.FileType,
				"timestamp": msg.Timestamp,
				"status":    msg.Status,
				"type":      msg.Type,
			}
			var result []map[string]interface{}
			_, err = supabase.DB.From("messages").Insert(newMessage).Execute(&result)
			if err != nil {
				log.Printf("Error storing message in Supabase: %v", err)
				continue
			}

			// Send to receiver
			clientsMutex.Lock()
			receiverClient, exists := clients[msg.Receiver]
			if exists && receiverClient.Conn != nil {
				err = receiverClient.Conn.WriteJSON(msg)
				if err != nil {
					log.Println("WebSocket write error:", err)
				}
			} else if exists && receiverClient.PushToken != "" {
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

		case "call_signal":
			// Handle WebRTC signaling
			clientsMutex.Lock()
			receiverClient, exists := clients[msg.Receiver]
			if exists && receiverClient.Conn != nil {
				err = receiverClient.Conn.WriteJSON(msg)
				if err != nil {
					log.Println("WebSocket write error:", err)
				}
			} else if exists && receiverClient.PushToken != "" && msg.Signal.Type == "call-initiate" {
				// Notify receiver of incoming call
				message := &messaging.Message{
					Notification: &messaging.Notification{
						Title: fmt.Sprintf("Incoming %s call from %s", msg.Signal.CallType, msg.Sender),
						Body:  "Tap to accept the call",
					},
					Data: map[string]string{
						"call_initiator": msg.Sender,
						"call_type":      msg.Signal.CallType,
					},
					Token: receiverClient.PushToken,
				}
				_, err := fcmClient.Send(context.Background(), message)
				if err != nil {
					log.Printf("Error sending call notification to %s: %v", msg.Receiver, err)
				} else {
					log.Printf("Call notification sent to %s", msg.Receiver)
				}
			}
			clientsMutex.Unlock()

			// Optionally store call metadata in Supabase
			if msg.Signal.Type == "call-initiate" {
				newCall := map[string]interface{}{
					"caller":     msg.Sender,
					"callee":     msg.Receiver,
					"call_type":  msg.Signal.CallType,
					"start_time": msg.Timestamp,
					"status":     "initiated",
				}
				var result []map[string]interface{}
				_, err = supabase.DB.From("calls").Insert(newCall).Execute(&result)
				if err != nil {
					log.Printf("Error storing call in Supabase: %v", err)
				}
			} else if msg.Signal.Type == "call-accept" || msg.Signal.Type == "call-reject" {
				var calls []map[string]interface{}
				_, err := supabase.DB.From("calls").
					Select("*").
					Eq("caller", msg.Receiver).
					Eq("callee", msg.Sender).
					Eq("status", "initiated").
					Execute(&calls)
				if err == nil && len(calls) > 0 {
					updateCall := map[string]interface{}{
						"status":    msg.Signal.CallStatus,
						"end_time":  time.Now(),
					}
					_, err = supabase.DB.From("calls").
						Update(updateCall).
						Eq("id", fmt.Sprintf("%v", calls[0]["id"])).
						Execute(&calls)
					if err != nil {
						log.Printf("Error updating call status in Supabase: %v", err)
					}
				}
			}
		}
	}
}
