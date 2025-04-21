package main

import (
    "context"
    "encoding/json"
    "fmt"
    "io"
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
    "golang.org/x/crypto/bcrypt"
    supabaseClient "github.com/supabase-community/supabase-go"
    "github.com/supabase-community/postgrest-go"
)

// Global variables
var (
    clients      = make(map[string]*Client) // Map of usernames to WebSocket clients
    clientsMutex sync.Mutex                 // Mutex for thread-safe access
    fcmClient    *messaging.Client          // Firebase Cloud Messaging client
    supaClient   *supabaseClient.Client     // Supabase client
    jwtSecret    string                     // JWT secret from environment
    fcmEnabled   bool                       // Flag to indicate if FCM is enabled
)

// Client struct to store WebSocket connection and push token
type Client struct {
    Conn      *websocket.Conn
    PushToken string
}

// Message struct for chat messages
type Message struct {
    Type      string      `json:"type"`      // "text", "file", "call_signal"
    Sender    string      `json:"sender"`
    Receiver  string      `json:"receiver"`
    Content   string      `json:"content,omitempty"`
    FileURL   string      `json:"file_url,omitempty"`
    FileType  string      `json:"file_type,omitempty"`
    Timestamp time.Time   `json:"timestamp"`
    Status    string      `json:"status"`
    Signal    SignalData  `json:"signal,omitempty"` // For WebRTC signaling
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
    var errClient error
    supaClient, errClient = supabaseClient.NewClient(supabaseURL, supabaseKey, nil)
    if errClient != nil {
        log.Fatalf("Error initializing Supabase client: %v\n", errClient)
    }
    if supaClient == nil {
        log.Fatal("Failed to initialize Supabase client")
    }

    // Initialize Firebase
    ctx := context.Background()
    credentialsPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
    if credentialsPath == "" {
        log.Println("GOOGLE_APPLICATION_CREDENTIALS not set, push notifications will be disabled")
        fcmEnabled = false
    } else {
        log.Printf("Using Firebase credentials from GOOGLE_APPLICATION_CREDENTIALS: %s", credentialsPath)

        // Check both possible paths for the credentials file
        possiblePaths := []string{
            credentialsPath,
            "/etc/secrets/firebase-adminsdk.json", // Alternative path in Render.com
        }

        for _, path := range possiblePaths {
            log.Printf("Checking for Firebase credentials at: %s", path)
            if _, err := os.Stat(path); os.IsNotExist(err) {
                log.Printf("Firebase credentials file not found at %s", path)
                continue
            }

            // Temporarily set GOOGLE_APPLICATION_CREDENTIALS to the found path
            os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)
            log.Printf("Set GOOGLE_APPLICATION_CREDENTIALS to %s for Firebase initialization", path)

            app, err := firebase.NewApp(ctx, nil)
            if err != nil {
                log.Printf("Error initializing Firebase app with credentials at %s: %v", path, err)
                continue
            }

            fcmClient, err = app.Messaging(ctx)
            if err != nil {
                log.Printf("Error initializing FCM client with credentials at %s: %v", path, err)
                continue
            }

            fcmEnabled = true
            log.Println("Firebase Cloud Messaging initialized successfully")
            break
        }

        if !fcmEnabled {
            log.Println("Firebase credentials not found or invalid in any path, push notifications will be disabled")
        }
    }

    // Initialize router
    r := mux.NewRouter()

    // API routes
    r.HandleFunc("/register", registerHandler).Methods("POST")
    r.HandleFunc("/login", loginHandler).Methods("POST")
    r.HandleFunc("/messages", authMiddleware(messagesHandler)).Methods("GET")
    r.HandleFunc("/upload", authMiddleware(uploadHandler)).Methods("POST")
    r.HandleFunc("/register-push", authMiddleware(registerPushHandler)).Methods("POST")
    r.HandleFunc("/ws", wsHandler).Methods("GET")

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
        log.Printf("Invalid request body for /register: %v", err)
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    if user.Username == "" || user.Password == "" {
        log.Println("Username or password missing in /register request")
        http.Error(w, "Username and password are required", http.StatusBadRequest)
        return
    }

    // Check if user exists
    var existingUsers []map[string]interface{}
    data, err := supaClient.From("users").Select("*", "exact", false).Eq("username", user.Username).ExecuteTo(&existingUsers)
    if err != nil {
        log.Printf("Error checking user in Supabase: %v, response data: %s", err, string(data))
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    if len(existingUsers) > 0 {
        log.Printf("Username %s already exists", user.Username)
        http.Error(w, "Username already exists", http.StatusConflict)
        return
    }

    // Hash the password
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
    if err != nil {
        log.Printf("Error hashing password for user %s: %v", user.Username, err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    // Insert new user
    newUser := map[string]interface{}{
        "username": user.Username,
        "password": string(hashedPassword),
    }
    var result []map[string]interface{}
    _, err = supaClient.From("users").Insert(newUser, false, "", "representation", "exact").ExecuteTo(&result)
    if err != nil {
        log.Printf("Error registering user %s in Supabase: %v", user.Username, err)
        http.Error(w, "Failed to register user", http.StatusInternalServerError)
        return
    }

    log.Printf("User registered successfully: %s", user.Username)
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
        log.Printf("Invalid request body for /login: %v", err)
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    log.Printf("Login attempt for user: %s", creds.Username)

    if creds.Username == "" || creds.Password == "" {
        log.Println("Username or password missing in /login request")
        http.Error(w, "Invalid credentials", http.StatusBadRequest)
        return
    }

    // Verify user
    var users []map[string]interface{}
    _, err := supaClient.From("users").Select("*", "exact", false).Eq("username", creds.Username).ExecuteTo(&users)
    if err != nil {
        log.Printf("Error fetching user %s from Supabase: %v", creds.Username, err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    if len(users) == 0 {
        log.Printf("User %s not found in Supabase", creds.Username)
        http.Error(w, "Invalid username or password", http.StatusUnauthorized)
        return
    }

    user := users[0]
    storedPassword, ok := user["password"].(string)
    if !ok {
        log.Printf("Invalid password format for user %s in Supabase", creds.Username)
        http.Error(w, "Invalid username or password", http.StatusUnauthorized)
        return
    }

    // Compare hashed password
    err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(creds.Password))
    if err != nil {
        log.Printf("Password mismatch for user %s: %v", creds.Username, err)
        http.Error(w, "Invalid username or password", http.StatusUnauthorized)
        return
    }

    // Generate JWT
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "username": creds.Username,
        "exp":      time.Now().Add(time.Hour * 24).Unix(),
    })

    tokenString, err := token.SignedString([]byte(jwtSecret))
    if err != nil {
        log.Printf("Error generating JWT for user %s: %v", creds.Username, err)
        http.Error(w, "Failed to generate token", http.StatusInternalServerError)
        return
    }

    log.Printf("Login successful for user: %s", creds.Username)
    json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

// Authentication middleware
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        log.Printf("Incoming request to %s", r.URL.Path)
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            log.Println("Authorization header missing")
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
            log.Printf("Invalid token: %v", err)
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        log.Println("Token validated successfully")
        next.ServeHTTP(w, r)
    }
}

// Upload handler for files
func uploadHandler(w http.ResponseWriter, r *http.Request) {
    // Parse multipart form
    err := r.ParseMultipartForm(10 << 20) // 10 MB limit
    if err != nil {
        log.Printf("Error parsing multipart form: %v", err)
        http.Error(w, "Failed to parse form", http.StatusBadRequest)
        return
    }

    file, handler, err := r.FormFile("file")
    if err != nil {
        log.Printf("Error retrieving file from form: %v", err)
        http.Error(w, "Failed to retrieve file", http.StatusBadRequest)
        return
    }
    defer file.Close()

    // Read file bytes
    fileBytes, err := io.ReadAll(file)
    if err != nil {
        log.Printf("Error reading file: %v", err)
        http.Error(w, "Failed to read file", http.StatusInternalServerError)
        return
    }

    // Upload to Supabase Storage
    filePath := fmt.Sprintf("chat-files/%s-%d", handler.Filename, time.Now().UnixNano())
    _, err = supaClient.Storage().Bucket("chat-files").Upload(filePath, fileBytes, nil)
    if err != nil {
        log.Printf("Error uploading file to Supabase Storage: %v", err)
        http.Error(w, "Failed to upload file", http.StatusInternalServerError)
        return
    }

    // Get public URL
    fileURL := fmt.Sprintf("%s/storage/v1/object/public/chat-files/%s", os.Getenv("SUPABASE_URL"), filePath)
    log.Printf("File uploaded successfully: %s", fileURL)

    json.NewEncoder(w).Encode(map[string]string{"file_url": fileURL})
}

// Messages handler
func messagesHandler(w http.ResponseWriter, r *http.Request) {
    chatID := r.URL.Query().Get("chat_id")
    if chatID == "" {
        log.Println("Chat ID missing in /messages request")
        http.Error(w, "Chat ID is required", http.StatusBadRequest)
        return
    }

    parts := strings.Split(chatID, ":")
    if len(parts) != 2 {
        log.Printf("Invalid chat ID format: %s", chatID)
        http.Error(w, "Invalid chat ID format", http.StatusBadRequest)
        return
    }
    sender, receiver := parts[0], parts[1]

    log.Printf("Fetching messages for chat ID %s (sender: %s, receiver: %s)", chatID, sender, receiver)
    var messages []Message
    _, err := supaClient.From("messages").
        Select("*", "exact", false).
        Or(fmt.Sprintf("and(sender.eq.%s,receiver.eq.%s)", sender, receiver), fmt.Sprintf("and(sender.eq.%s,receiver.eq.%s)", receiver, sender)).
        Order("timestamp", &postgrest.OrderOpts{Ascending: true}).
        ExecuteTo(&messages)
    if err != nil {
        log.Printf("Error fetching messages from Supabase: %v", err)
        http.Error(w, "Failed to fetch messages", http.StatusInternalServerError)
        return
    }

    log.Printf("Fetched %d messages for chat ID %s", len(messages), chatID)
    json.NewEncoder(w).Encode(messages)
}

// Push registration handler
func registerPushHandler(w http.ResponseWriter, r *http.Request) {
    var pushReg PushRegistration
    if err := json.NewDecoder(r.Body).Decode(&pushReg); err != nil {
        log.Printf("Invalid request body for /register-push: %v", err)
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    if pushReg.Username == "" || pushReg.Token == "" {
        log.Println("Username or token missing in /register-push request")
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
        log.Println("Username missing in /ws request")
        http.Error(w, "Username is required", http.StatusBadRequest)
        return
    }

    log.Printf("WebSocket connection attempt for user: %s", username)

    // Check for token in Authorization header or query string
    tokenString := r.Header.Get("Authorization")
    if tokenString != "" {
        tokenString = strings.TrimPrefix(tokenString, "Bearer ")
        log.Println("Token found in Authorization header")
    } else {
        tokenString = r.URL.Query().Get("token")
        if tokenString == "" {
            log.Println("Token missing in both Authorization header and query string")
            http.Error(w, "Token is required", http.StatusForbidden)
            return
        }
        log.Println("Token found in query string")
    }

    // Validate token
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return []byte(jwtSecret), nil
    })

    if err != nil || !token.Valid {
        log.Printf("Invalid token for WebSocket connection: %v", err)
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }

    log.Println("WebSocket token validated successfully")

    // Upgrade to WebSocket
    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Printf("WebSocket upgrade error for user %s: %v", username, err)
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
            log.Printf("WebSocket read error for user %s: %v", username, err)
            break
        }

        // Set timestamp
        msg.Timestamp = time.Now()

        // Handle different message types
        switch msg.Type {
        case "text", "file":
            // Store message in Supabase (skip if ephemeral)
            if msg.Status != "ephemeral" {
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
                _, err = supaClient.From("messages").Insert(newMessage, false, "", "representation", "exact").ExecuteTo(&result)
                if err != nil {
                    log.Printf("Error storing message in Supabase for user %s: %v", username, err)
                    continue
                }
            } else {
                log.Printf("Ephemeral message from %s to %s, not stored in Supabase", msg.Sender, msg.Receiver)
            }

            // Send to receiver
            clientsMutex.Lock()
            receiverClient, exists := clients[msg.Receiver]
            if exists && receiverClient.Conn != nil {
                err = receiverClient.Conn.WriteJSON(msg)
                if err != nil {
                    log.Printf("WebSocket write error for user %s to receiver %s: %v", username, msg.Receiver, err)
                }
            } else if exists && receiverClient.PushToken != "" {
                if !fcmEnabled {
                    log.Printf("Push notifications disabled, skipping notification to %s", msg.Receiver)
                    clientsMutex.Unlock()
                    continue
                }
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
                    log.Printf("WebSocket write error for user %s to receiver %s: %v", username, msg.Receiver, err)
                }
            } else if exists && receiverClient.PushToken != "" && msg.Signal.Type == "call-initiate" {
                if !fcmEnabled {
                    log.Printf("Push notifications disabled, skipping call notification to %s", msg.Receiver)
                    clientsMutex.Unlock()
                    continue
                }
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

            // Store call metadata in Supabase
            if msg.Signal.Type == "call-initiate" {
                newCall := map[string]interface{}{
                    "caller":     msg.Sender,
                    "callee":     msg.Receiver,
                    "call_type":  msg.Signal.CallType,
                    "start_time": msg.Timestamp,
                    "status":     "initiated",
                }
                var result []map[string]interface{}
                _, err = supaClient.From("calls").Insert(newCall, false, "", "representation", "exact").ExecuteTo(&result)
                if err != nil {
                    log.Printf("Error storing call in Supabase for user %s: %v", username, err)
                }
            } else if msg.Signal.Type == "call-accept" || msg.Signal.Type == "call-reject" {
                var calls []map[string]interface{}
                _, err := supaClient.From("calls").
                    Select("*", "exact", false).
                    Eq("caller", msg.Receiver).
                    Eq("callee", msg.Sender).
                    Eq("status", "initiated").
                    ExecuteTo(&calls)
                if err == nil && len(calls) > 0 {
                    updateCall := map[string]interface{}{
                        "status":   msg.Signal.CallStatus,
                        "end_time": time.Now(),
                    }
                    _, err = supaClient.From("calls").
                        Update(updateCall, "representation", "exact").
                        Eq("id", fmt.Sprintf("%v", calls[0]["id"])).
                        ExecuteTo(&calls)
                    if err != nil {
                        log.Printf("Error updating call status in Supabase: %v", err)
                    }
                }
            }
        }
    }
}
