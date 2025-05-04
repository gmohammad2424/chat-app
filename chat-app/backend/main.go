package main

import (
    "bytes"
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
    "strings"
    "sync"
    "time"
    "path/filepath"
    "regexp"

    "firebase.google.com/go/v4"
    "firebase.google.com/go/v4/messaging"
    "github.com/dgrijalva/jwt-go"
    "github.com/gorilla/handlers"
    "github.com/gorilla/mux"
    "github.com/gorilla/websocket"
    "github.com/joho/godotenv"
    "github.com/supabase-community/gotrue-go"
    "github.com/supabase-community/gotrue-go/types"
    "github.com/supabase-community/postgrest-go"
    "github.com/supabase-community/storage-go"
)

// Global variables
var (
    clients      = make(map[string]*Client) // Map of user_ids to WebSocket clients
    clientsMutex sync.Mutex                 // Mutex for thread-safe access
    fcmClient    *messaging.Client          // Firebase Cloud Messaging client
    postgrestClient *postgrest.Client       // PostgREST client for database operations
    storageClient *storage_go.Client        // Supabase client for storage
    authClient   gotrue.Client              // Supabase client for authentication
    jwtSecret    string                     // JWT secret for token generation
    encryptionKey []byte                    // Encryption key for file URLs
    fcmEnabled   bool                       // Flag to indicate if FCM is enabled
    adminUserID  = "550e8400-e29b-41d4-a716-446655440000" // Admin's UUID
    supabaseURL  string
    supabaseServiceKey string
    supabaseAnonKey    string
    // Rate limiting for pong messages
    lastPongLog = make(map[string]time.Time) // Track last pong log time per client
    pongLogInterval = 30 * time.Second       // Log pong messages at most once every 30 seconds
)

// Client struct for WebSocket connections
type Client struct {
    Conn      *websocket.Conn
    PushToken string
}

// Chat struct to match the chats table schema
type Chat struct {
    ID           string `json:"id"`
    Participant1 string `json:"participant1"` // UUID
    Participant2 string `json:"participant2"` // UUID
}

// Message struct for chat messages
type Message struct {
    Type      string     `json:"type"`      // "text", "file", "call_signal", "ping", "pong"
    Sender    string     `json:"sender"`    // UUID
    Receiver  string     `json:"receiver"`  // UUID
    Content   string     `json:"content,omitempty"`
    FileURL   string     `json:"file_url,omitempty"`
    FileType  string     `json:"file_type,omitempty"`
    Timestamp time.Time  `json:"timestamp"`
    Status    string     `json:"status"`
    Signal    SignalData `json:"signal,omitempty"` // For WebRTC signaling
}

// SignalData for WebRTC signaling
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
    Email    string `json:"email"`
    Password string `json:"password"`
}

// UserResponse struct for the /users endpoint response
type UserResponse struct {
    UserID   string `json:"user_id"`
    Username string `json:"username"`
}

// PushRegistration struct for FCM tokens
type PushRegistration struct {
    UserID string `json:"user_id"` // UUID
    Token  string `json:"token"`
}

// WebSocket upgrader
var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool {
        return true // Allow all origins for WebSocket
    },
}

// Encrypt a string using AES-256-GCM
func encryptString(plaintext string) (string, error) {
    block, err := aes.NewCipher(encryptionKey)
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

// Decrypt a string using AES-256-GCM
func decryptString(encrypted string) (string, error) {
    data, err := base64.StdEncoding.DecodeString(encrypted)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(encryptionKey)
    if err != nil {
        return "", err
    }

    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonceSize := aesGCM.NonceSize()
    if len(data) < nonceSize {
        return "", fmt.Errorf("ciphertext too short")
    }

    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }

    return string(plaintext), nil
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

    // Get encryption key
    encryptionKeyString := os.Getenv("ENCRYPTION_KEY")
    if encryptionKeyString == "" {
        log.Fatal("ENCRYPTION_KEY environment variable is required")
    }
    encryptionKey, err = base64.StdEncoding.DecodeString(encryptionKeyString)
    if err != nil {
        log.Fatalf("Error decoding ENCRYPTION_KEY: %v", err)
    }
    if len(encryptionKey) != 32 { // AES-256 requires a 32-byte key
        log.Fatal("ENCRYPTION_KEY must be a 32-byte key (base64 encoded)")
    }

    // Initialize Supabase clients
    supabaseURL = os.Getenv("SUPABASE_URL")
    supabaseServiceKey = os.Getenv("SUPABASE_SERVICE_KEY")
    supabaseAnonKey = os.Getenv("SUPABASE_ANON_KEY")
    if supabaseURL == "" || supabaseServiceKey == "" || supabaseAnonKey == "" {
        log.Fatal("SUPABASE_URL, SUPABASE_SERVICE_KEY, and SUPABASE_ANON_KEY environment variables are required")
    }

    // Clean and validate Supabase URL
    supabaseURL = strings.TrimSpace(supabaseURL)
    supabaseURL = strings.TrimPrefix(supabaseURL, "https://https//")
    supabaseURL = strings.TrimPrefix(supabaseURL, "https//")
    supabaseURL = strings.TrimSuffix(supabaseURL, "/")
    if !strings.HasPrefix(supabaseURL, "https://") {
        supabaseURL = "https://" + supabaseURL
    }
    if strings.Count(supabaseURL, ".supabase.co") > 1 {
        parts := strings.SplitAfterN(supabaseURL, ".supabase.co", 2)
        supabaseURL = parts[0]
    }
    if !strings.HasSuffix(supabaseURL, ".supabase.co") || !strings.Contains(supabaseURL, "vridcilbrgyrxxmnjcqq") {
        log.Fatal("SUPABASE_URL must be in the format https://vridcilbrgyrxxmnjcqq.supabase.co")
    }
    log.Printf("Cleaned SUPABASE_URL: %s", supabaseURL)

    // PostgREST client (for database operations)
    postgrestURL := supabaseURL + "/rest/v1"
    log.Printf("PostgREST URL: %s", postgrestURL)
    postgrestClient = postgrest.NewClient(postgrestURL, "", map[string]string{
        "Authorization": "Bearer " + supabaseServiceKey,
        "apikey":        supabaseServiceKey,
    })
    if postgrestClient == nil {
        log.Fatal("Failed to initialize PostgREST client")
    }

    // Storage client
    storageURL := supabaseURL + "/storage/v1"
    log.Printf("Storage URL: %s", storageURL)
    storageClient = storage_go.NewClient(storageURL, supabaseServiceKey, nil)

    // Auth client (uses anon key for user authentication)
    authURL := supabaseURL + "/auth/v1"
    log.Printf("Auth URL: %s", authURL)
    authClient = gotrue.New(supabaseURL, supabaseAnonKey)
    if authClient == nil {
        log.Fatal("Failed to initialize Supabase auth client")
    }

    // Initialize Firebase
    ctx := context.Background()
    credentialsPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
    if credentialsPath == "" {
        log.Println("GOOGLE_APPLICATION_CREDENTIALS not set, push notifications will be disabled")
        fcmEnabled = false
    } else {
        log.Printf("Using Firebase credentials from GOOGLE_APPLICATION_CREDENTIALS: %s", credentialsPath)
        app, err := firebase.NewApp(ctx, nil)
        if err != nil {
            log.Printf("Error initializing Firebase app: %v", err)
            fcmEnabled = false
        } else {
            fcmClient, err = app.Messaging(ctx)
            if err != nil {
                log.Printf("Error initializing FCM client: %v", err)
                fcmEnabled = false
            } else {
                fcmEnabled = true
                log.Println("Firebase Cloud Messaging initialized successfully")
            }
        }
    }

    // Initialize router
    router := mux.NewRouter()

    // API routes
    router.HandleFunc("/signup", signupHandler).Methods("POST")
    router.HandleFunc("/login", loginHandler).Methods("POST")
    router.HandleFunc("/users", authMiddleware(usersHandler)).Methods("GET")
    router.HandleFunc("/messages", authMiddleware(messagesHandler)).Methods("GET")
    router.HandleFunc("/allowed-chats", authMiddleware(allowedChatsHandler)).Methods("GET")
    router.HandleFunc("/upload", authMiddleware(uploadHandler)).Methods("POST")
    router.HandleFunc("/file/{path:.*}", authMiddleware(fileHandler)).Methods("GET")
    router.HandleFunc("/register-push", authMiddleware(registerPushHandler)).Methods("POST")
    router.HandleFunc("/ws", wsHandler).Methods("GET")

    // Root handler
    router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "Chat App Backend")
    })

    // CORS middleware
    corsHandler := handlers.CORS(
        handlers.AllowedOrigins([]string{"*"}),
        handlers.AllowedMethods([]string{"GET", "POST", "OPTIONS"}),
        handlers.AllowedHeaders([]string{"Content-Type", "Authorization"}),
        handlers.AllowCredentials(),
        handlers.OptionStatusCode(http.StatusNoContent),
    )

    // Wrap router with CORS and logging
    loggedRouter := corsHandler(router)

    // Start server with logging
    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }
    log.Printf("Server running on port %s", port)
    log.Fatal(http.ListenAndServe(":"+port, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        log.Printf("Received request: %s %s from %s", r.Method, r.URL.Path, r.Header.Get("Origin"))
        log.Printf("Request headers: %v", r.Header)
        loggedRouter.ServeHTTP(w, r)
        log.Printf("Response headers: %v", w.Header())
    })))
}

// Signup handler
func signupHandler(w http.ResponseWriter, r *http.Request) {
    var user User
    if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
        log.Printf("Invalid request body for /signup: %v", err)
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    if user.Username == "" || user.Email == "" || user.Password == "" {
        log.Println("Username, email, or password missing in /signup request")
        http.Error(w, "Username, email, and password are required", http.StatusBadRequest)
        return
    }

    // Check if username exists
    var existingUsers []map[string]interface{}
    data, _, err := postgrestClient.From("users").Select("*", "exact", false).Eq("username", user.Username).Execute()
    if err != nil {
        log.Printf("Error checking user in Supabase: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    if err := json.Unmarshal(data, &existingUsers); err != nil {
        log.Printf("Error unmarshaling users: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    if len(existingUsers) > 0 {
        log.Printf("Username %s already exists", user.Username)
        http.Error(w, "Username already exists", http.StatusConflict)
        return
    }

    // Create user in Supabase Auth
    signupRequest := types.SignupRequest{
        Email:    user.Email,
        Password: user.Password,
        Data: map[string]interface{}{
            "username": user.Username,
        },
    }
    authUser, err := authClient.Signup(signupRequest)
    if err != nil {
        log.Printf("Error creating user in Supabase auth: %v", err)
        http.Error(w, "Failed to register user", http.StatusInternalServerError)
        return
    }

    // Sign in to get JWT (using custom authentication)
    tokenRequest := map[string]interface{}{
        "grant_type": "password",
        "email":      user.Email,
        "password":   user.Password,
    }
    tokenRequestBody, err := json.Marshal(tokenRequest)
    if err != nil {
        log.Printf("Error marshaling token request: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    authURL := supabaseURL + "/auth/v1/token?grant_type=password"
    req, err := http.NewRequest("POST", authURL, bytes.NewBuffer(tokenRequestBody))
    if err != nil {
        log.Printf("Error creating token request: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("apikey", supabaseAnonKey)

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        log.Printf("Error signing in user %s to get JWT: %v", user.Username, err)
        http.Error(w, "Failed to generate token", http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        log.Printf("Error signing in user %s: %s", user.Username, string(body))
        http.Error(w, "Failed to generate token", http.StatusInternalServerError)
        return
    }

    var authResponse struct {
        AccessToken string `json:"access_token"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
        log.Printf("Error decoding token response: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    // Insert user into users table
    newUser := map[string]interface{}{
        "user_id":  authUser.ID.String(),
        "username": user.Username,
        "email":    user.Email,
    }
    var result []map[string]interface{}
    data, _, err = postgrestClient.From("users").Insert(newUser, false, "", "representation", "exact").Execute()
    if err != nil {
        log.Printf("Error registering user %s in Supabase: %v", user.Username, err)
        http.Error(w, "Failed to register user", http.StatusInternalServerError)
        return
    }
    if err := json.Unmarshal(data, &result); err != nil {
        log.Printf("Error unmarshaling insert result: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    log.Printf("User signed up successfully: %s (user_id: %s)", user.Username, authUser.ID.String())
    json.NewEncoder(w).Encode(map[string]string{
        "token":   authResponse.AccessToken,
        "chat_id": authUser.ID.String() + ":",
    })
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

    log.Printf("Login attempt for username: %s", creds.Username)

    if creds.Username == "" || creds.Password == "" {
        log.Println("Username or password missing in /login request")
        http.Error(w, "Invalid credentials", http.StatusBadRequest)
        return
    }

    // Fetch user from users table to get email
    var users []map[string]interface{}
    data, _, err := postgrestClient.From("users").Select("*", "exact", false).Eq("username", creds.Username).Execute()
    if err != nil {
        log.Printf("Error fetching user %s from Supabase: %v", creds.Username, err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    if err := json.Unmarshal(data, &users); err != nil {
        log.Printf("Error unmarshaling users: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    if len(users) == 0 {
        log.Printf("User %s not found in Supabase", creds.Username)
        http.Error(w, "Invalid username or password", http.StatusUnauthorized)
        return
    }

    user := users[0]
    email, ok := user["email"].(string)
    if !ok {
        log.Printf("Invalid email format for user %s in Supabase", creds.Username)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    userID, ok := user["user_id"].(string)
    if !ok {
        log.Printf("Invalid user_id format for user %s in Supabase", creds.Username)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    // Custom authentication request to Supabase
    tokenRequest := map[string]interface{}{
        "grant_type": "password",
        "email":      email,
        "password":   creds.Password,
    }
    tokenRequestBody, err := json.Marshal(tokenRequest)
    if err != nil {
        log.Printf("Error marshaling token request for user %s: %v", creds.Username, err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    authURL := supabaseURL + "/auth/v1/token?grant_type=password"
    log.Printf("Sending authentication request to: %s", authURL)

    req, err := http.NewRequest("POST", authURL, bytes.NewBuffer(tokenRequestBody))
    if err != nil {
        log.Printf("Error creating token request for user %s: %v", creds.Username, err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("apikey", supabaseAnonKey)

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        log.Printf("Error signing in user %s with Supabase auth: %v", creds.Username, err)
        http.Error(w, "Invalid username or password", http.StatusUnauthorized)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        log.Printf("Error signing in user %s: %s", creds.Username, string(body))
        http.Error(w, "Invalid username or password", http.StatusUnauthorized)
        return
    }

    var authResponse struct {
        AccessToken string `json:"access_token"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
        log.Printf("Error decoding token response for user %s: %v", creds.Username, err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    log.Printf("Login successful for user: %s (user_id: %s)", creds.Username, userID)
    json.NewEncoder(w).Encode(map[string]string{
        "token":   authResponse.AccessToken,
        "chat_id": userID + ":",
    })
}

// Authentication middleware
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
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

        claims, ok := token.Claims.(jwt.MapClaims)
        if !ok || claims["sub"] == nil || claims["username"] == nil {
            log.Println("Invalid token claims")
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }
        userID := claims["sub"].(string)
        username := claims["username"].(string)
        ctx := context.WithValue(r.Context(), "user_id", userID)
        ctx = context.WithValue(ctx, "username", username)
        next.ServeHTTP(w, r.WithContext(ctx))
    }
}

// Users handler
func usersHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value("user_id").(string)
    username := r.Context().Value("username").(string)
    log.Printf("Fetching users for authenticated user: %s (user_id: %s)", username, userID)

    var rawUsers []map[string]interface{}
    data, _, err := postgrestClient.From("users").Select("user_id, username", "exact", false).Execute()
    if err != nil {
        log.Printf("Error fetching users from Supabase: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    log.Printf("Raw response from Supabase: %s", string(data))

    if err := json.Unmarshal(data, &rawUsers); err != nil {
        log.Printf("Error unmarshaling users: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    log.Printf("Fetched %d users from Supabase", len(rawUsers))

    users := make([]UserResponse, 0, len(rawUsers))
    for _, rawUser := range rawUsers {
        user := UserResponse{
            UserID:   rawUser["user_id"].(string),
            Username: rawUser["username"].(string),
        }
        users = append(users, user)
    }

    responseBytes, _ := json.Marshal(users)
    log.Printf("Sending response: %s", string(responseBytes))

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(users)
}

// Messages handler
func messagesHandler(w http.ResponseWriter, r *http.Request) {
    chatID := r.URL.Query().Get("chat_id")
    if chatID == "" {
        log.Println("chat_id parameter missing in /messages request")
        http.Error(w, "chat_id is required", http.StatusBadRequest)
        return
    }

    var messages []Message
    data, _, err := postgrestClient.From("messages").Select("*", "exact", false).Eq("chat_id", chatID).Execute()
    if err != nil {
        log.Printf("Error fetching messages for chat %s: %v", chatID, err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    if err := json.Unmarshal(data, &messages); err != nil {
        log.Printf("Error unmarshaling messages: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    json.NewEncoder(w).Encode(messages)
}

// Allowed chats handler
func allowedChatsHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value("user_id").(string)

    var chats []Chat
    query := postgrestClient.From("chats").Select("*", "exact", false)
    query = query.Or(fmt.Sprintf("participant1.eq.%s,participant2.eq.%s", userID, userID), "")
    data, _, err := query.Execute()
    if err != nil {
        log.Printf("Error fetching allowed chats for user %s: %v", userID, err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    if err := json.Unmarshal(data, &chats); err != nil {
        log.Printf("Error unmarshaling chats: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    json.NewEncoder(w).Encode(chats)
}

// Sanitize file name to remove invalid characters
func sanitizeFileName(filename string) string {
    // Remove invalid characters (e.g., /, \, :, etc.)
    reg, err := regexp.Compile("[^a-zA-Z0-9._-]")
    if err != nil {
        log.Printf("Error compiling regex for sanitizing filename: %v", err)
        return filename
    }
    sanitized := reg.ReplaceAllString(filename, "_")
    // Limit length to avoid issues with long filenames
    if len(sanitized) > 100 {
        ext := filepath.Ext(sanitized)
        base := sanitized[:100-len(ext)]
        sanitized = base + ext
    }
    return sanitized
}

// Upload handler for files
func uploadHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value("user_id").(string)

    err := r.ParseMultipartForm(10 << 20) // 10 MB limit
    if err != nil {
        log.Printf("Error parsing multipart form: %v", err)
        errorResponse := map[string]string{"error": "Unable to parse form"}
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(errorResponse)
        return
    }

    file, handler, err := r.FormFile("file")
    if err != nil {
        log.Printf("Error retrieving file from form: %v", err)
        errorResponse := map[string]string{"error": "Unable to retrieve file"}
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(errorResponse)
        return
    }
    defer file.Close()

    fileType := handler.Header.Get("Content-Type")
    fileBytes, err := io.ReadAll(file)
    if err != nil {
        log.Printf("Error reading file: %v", err)
        errorResponse := map[string]string{"error": "Unable to read file"}
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(errorResponse)
        return
    }

    // Generate a more descriptive file name: userID/timestamp_originalfilename
    timestamp := time.Now().Format("20060102-150405") // YYYYMMDD-HHMMSS
    originalFileName := sanitizeFileName(handler.Filename)
    fileName := fmt.Sprintf("%s/%s_%s", userID, timestamp, originalFileName)
    log.Printf("Uploading file to chat-files bucket: %s", fileName)

    _, err = storageClient.UploadFile("chat-files", fileName, bytes.NewReader(fileBytes))
    if err != nil {
        log.Printf("Error uploading file to Supabase: %v", err)
        errorResponse := map[string]string{"error": "Unable to upload file to storage"}
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(errorResponse)
        return
    }

    signedURLResponse, err := storageClient.CreateSignedUrl("chat-files", fileName, 3600)
    if err != nil {
        log.Printf("Error generating signed URL: %v", err)
        errorResponse := map[string]string{"error": "Unable to generate file URL"}
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(errorResponse)
        return
    }

    signedURL := signedURLResponse.SignedURL
    encryptedURL, err := encryptString(signedURL)
    if err != nil {
        log.Printf("Error encrypting file URL: %v", err)
        errorResponse := map[string]string{"error": "Unable to process file URL"}
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(errorResponse)
        return
    }

    response := map[string]string{
        "file_url":  encryptedURL,
        "file_type": fileType,
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

// File handler to serve files
func fileHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    encryptedPath := vars["path"]

    signedURL, err := decryptString(encryptedPath)
    if err != nil {
        log.Printf("Error decrypting file URL: %v", err)
        http.Error(w, "Invalid file URL", http.StatusBadRequest)
        return
    }

    resp, err := http.Get(signedURL)
    if err != nil || resp.StatusCode != http.StatusOK {
        log.Printf("Error fetching file from Supabase: %v", err)
        http.Error(w, "Unable to fetch file", http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
    io.Copy(w, resp.Body)
}

// Register push token handler
func registerPushHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value("user_id").(string)

    var pushReg PushRegistration
    if err := json.NewDecoder(r.Body).Decode(&pushReg); err != nil {
        log.Printf("Invalid request body for /register-push: %v", err)
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    if pushReg.Token == "" {
        log.Println("Push token missing in /register-push request")
        http.Error(w, "Push token is required", http.StatusBadRequest)
        return
    }

    clientsMutex.Lock()
    if client, exists := clients[userID]; exists {
        client.PushToken = pushReg.Token
    } else {
        clients[userID] = &Client{PushToken: pushReg.Token}
    }
    clientsMutex.Unlock()

    log.Printf("Push token registered for user %s", userID)
    w.WriteHeader(http.StatusOK)
}

// WebSocket handler for real-time messaging and signaling
func wsHandler(w http.ResponseWriter, r *http.Request) {
    token := r.URL.Query().Get("token")
    if token == "" {
        log.Println("Token missing in WebSocket request")
        http.Error(w, "Token is required", http.StatusUnauthorized)
        return
    }

    // Validate token with Supabase
    authURL := supabaseURL + "/auth/v1/user"
    req, err := http.NewRequest("GET", authURL, nil)
    if err != nil {
        log.Printf("Error creating user request for token validation: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("apikey", supabaseServiceKey)

    httpClient := &http.Client{}
    resp, err := httpClient.Do(req)
    if err != nil {
        log.Printf("Error validating token with Supabase: %v", err)
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        log.Printf("Error validating token: %s", string(body))
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }

    var userResponse struct {
        ID       string                 `json:"id"`
        UserMeta map[string]interface{} `json:"user_metadata"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&userResponse); err != nil {
        log.Printf("Error decoding user response: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    userID := userResponse.ID
    if userID == "" {
        log.Println("User ID not found in token response")
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }

    // Upgrade to WebSocket
    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Printf("Error upgrading to WebSocket: %v", err)
        return
    }

    // Register client
    clientsMutex.Lock()
    wsClient := &Client{Conn: conn}
    if existingClient, exists := clients[userID]; exists {
        wsClient.PushToken = existingClient.PushToken
    }
    clients[userID] = wsClient
    clientsMutex.Unlock()

    log.Printf("WebSocket client connected: %s", userID)
    defer func() {
        clientsMutex.Lock()
        delete(clients, userID)
        clientsMutex.Unlock()
        conn.Close()
        log.Printf("WebSocket client disconnected: %s", userID)
    }()

    // Set up ping mechanism
    pingTicker := time.NewTicker(30 * time.Second)
    defer pingTicker.Stop()

    go func() {
        for range pingTicker.C {
            clientsMutex.Lock()
            if client, exists := clients[userID]; exists && client.Conn != nil {
                err := client.Conn.WriteJSON(Message{Type: "ping", Timestamp: time.Now()})
                if err != nil {
                    log.Printf("Error sending ping to client %s: %v", userID, err)
                    clientsMutex.Unlock()
                    return
                }
            }
            clientsMutex.Unlock()
        }
    }()

    ctx := context.Background()

    for {
        var msg Message
        err := conn.ReadJSON(&msg)
        if err != nil {
            if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
                log.Printf("WebSocket closed for user %s: code=%d, reason=%s", userID, websocket.CloseNormalClosure, err.Error())
            } else {
                log.Printf("Error reading WebSocket message for user %s: %v", userID, err)
                // Log additional details for debugging
                if websocket.IsUnexpectedCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
                    log.Printf("Unexpected WebSocket closure for user %s: %v", userID, err)
                }
            }
            break
        }

        if msg.Type == "pong" {
            // Rate-limit pong logging
            clientsMutex.Lock()
            lastLog, exists := lastPongLog[userID]
            shouldLog := !exists || time.Since(lastLog) >= pongLogInterval
            if shouldLog {
                log.Printf("Received pong from client %s", userID)
                lastPongLog[userID] = time.Now()
            }
            clientsMutex.Unlock()
            continue
        }

        msg.Timestamp = time.Now()
        // Temporarily disable status field until the database schema is updated
        // msg.Status = "sent"

        switch msg.Type {
        case "text", "file":
            messageData := map[string]interface{}{
                "chat_id":  fmt.Sprintf("%s:%s", msg.Sender, msg.Receiver),
                "sender":   msg.Sender,
                "receiver": msg.Receiver,
                "content":  msg.Content,
                "file_url": msg.FileURL,
                "type":     msg.Type,
                "timestamp": msg.Timestamp,
                // "status":   msg.Status, // Commented out until schema is updated
            }
            // Only include file_type if it's present and non-empty
            if msg.FileType != "" {
                messageData["file_type"] = msg.FileType
            }

            var result []map[string]interface{}
            data, _, err := postgrestClient.From("messages").Insert(messageData, false, "", "representation", "exact").Execute()
            if err != nil {
                log.Printf("Error saving message to Supabase: %v", err)
                // Notify the sender of the failure
                if senderClient, exists := clients[msg.Sender]; exists && senderClient.Conn != nil {
                    err = senderClient.Conn.WriteJSON(map[string]interface{}{
                        "type":  "error",
                        "error": "Failed to save message to database",
                    })
                    if err != nil {
                        log.Printf("Error notifying sender %s of message save failure: %v", msg.Sender, err)
                    }
                }
                continue
            }
            if err := json.Unmarshal(data, &result); err != nil {
                log.Printf("Error unmarshaling insert result: %v", err)
                continue
            }

            clientsMutex.Lock()
            if receiverClient, exists := clients[msg.Receiver]; exists && receiverClient.Conn != nil {
                err = receiverClient.Conn.WriteJSON(msg)
                if err != nil {
                    log.Printf("Error sending message to receiver %s: %v", msg.Receiver, err)
                } else {
                    // Temporarily disable status update until schema is updated
                    // msg.Status = "delivered"
                    // _, _, err = postgrestClient.From("messages").Update(map[string]interface{}{"status": "delivered"}, "", "exact").Eq("id", result[0]["id"].(string)).Execute()
                    // if err != nil {
                    //     log.Printf("Error updating message status: %v", err)
                    // }
                }
            } else {
                if fcmEnabled {
                    clientsMutex.Lock()
                    if receiverClient != nil && receiverClient.PushToken != "" {
                        message := &messaging.Message{
                            Notification: &messaging.Notification{
                                Title: "New Message",
                                Body:  fmt.Sprintf("You have a new message from %s", msg.Sender),
                            },
                            Token: receiverClient.PushToken,
                        }
                        _, err := fcmClient.Send(ctx, message)
                        if err != nil {
                            log.Printf("Error sending push notification to %s: %v", msg.Receiver, err)
                        }
                    }
                    clientsMutex.Unlock()
                }
            }
            clientsMutex.Unlock()

        case "call_signal":
            clientsMutex.Lock()
            if receiverClient, exists := clients[msg.Receiver]; exists && receiverClient.Conn != nil {
                err = receiverClient.Conn.WriteJSON(msg)
                if err != nil {
                    log.Printf("Error sending call signal to receiver %s: %v", msg.Receiver, err)
                }
            }
            clientsMutex.Unlock()

            if msg.Signal.Type == "call-initiate" {
                callData := map[string]interface{}{
                    "caller":     msg.Sender,
                    "callee":     msg.Receiver,
                    "call_type":  msg.Signal.CallType,
                    "start_time": time.Now(),
                    "status":     "initiated",
                }
                _, _, err = postgrestClient.From("calls").Insert(callData, false, "", "representation", "exact").Execute()
                if err != nil {
                    log.Printf("Error logging call to Supabase: %v", err)
                }
            } else if msg.Signal.Type == "call-accept" || msg.Signal.Type == "call-reject" {
                _, _, err = postgrestClient.From("calls").Update(map[string]interface{}{
                    "status":    msg.Signal.CallStatus,
                    "end_time":  time.Now(),
                }, "", "exact").Eq("caller", msg.Sender).Eq("callee", msg.Receiver).Execute()
                if err != nil {
                    log.Printf("Error updating call status: %v", err)
                }
            }
        }
    }
}
