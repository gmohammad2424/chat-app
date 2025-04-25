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

    "firebase.google.com/go/v4"
    "firebase.google.com/go/v4/messaging"
    "github.com/dgrijalva/jwt-go"
    "github.com/gorilla/handlers"
    "github.com/gorilla/mux"
    "github.com/gorilla/websocket"
    "github.com/joho/godotenv"
    "github.com/supabase-community/gotrue-go"
    supabaseClient "github.com/supabase-community/supabase-go"
    "github.com/supabase-community/postgrest-go"
)

// Global variables
var (
    clients      = make(map[string]*Client) // Map of user_ids to WebSocket clients
    clientsMutex sync.Mutex                 // Mutex for thread-safe access
    fcmClient    *messaging.Client          // Firebase Cloud Messaging client
    supaClient   *supabaseClient.Client     // Supabase client for database
    authClient   gotrue.Client              // Supabase client for authentication
    jwtSecret    string                     // JWT secret from environment
    encryptionKey []byte                    // Encryption key for file URLs
    fcmEnabled   bool                       // Flag to indicate if FCM is enabled
    adminUserID  = "550e8400-e29b-41d4-a716-446655440000" // Admin's UUID from auth.users
)

// Client struct to store WebSocket connection and push token
type Client struct {
    Conn      *websocket.Conn
    PushToken string
}

// Chat struct to match the chats table schema
type Chat struct {
    ID           string `json:"id"`
    Participant1 string `json:"participant1"` // Now a UUID
    Participant2 string `json:"participant2"` // Now a UUID
}

// Message struct for chat messages
type Message struct {
    Type      string      `json:"type"`      // "text", "file", "call_signal"
    Sender    string      `json:"sender"`    // Now a UUID
    Receiver  string      `json:"receiver"`  // Now a UUID
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
    UserID string `json:"user_id"` // Now a UUID
    Token  string `json:"token"`
}

// WebSocket upgrader
var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool {
        return true
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

    // Initialize Supabase database client
    supabaseURL := os.Getenv("SUPABASE_URL")
    supabaseKey := os.Getenv("SUPABASE_KEY") // Should be the service_role key
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

    // Initialize Supabase auth client
    supabaseServiceKey := os.Getenv("SUPABASE_SERVICE_KEY")
    if supabaseServiceKey == "" {
        log.Fatal("SUPABASE_SERVICE_KEY environment variable is required for auth")
    }
    authClient = gotrue.New(supabaseURL, supabaseServiceKey)
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

        possiblePaths := []string{
            credentialsPath,
            "/etc/secrets/firebase-adminsdk.json",
        }

        for _, path := range possiblePaths {
            log.Printf("Checking for Firebase credentials at: %s", path)
            if _, err := os.Stat(path); os.IsNotExist(err) {
                log.Printf("Firebase credentials file not found at %s", path)
                continue
            }

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
    r.HandleFunc("/signup", signupHandler).Methods("POST")
    r.HandleFunc("/login", loginHandler).Methods("POST")
    r.HandleFunc("/messages", authMiddleware(messagesHandler)).Methods("GET")
    r.HandleFunc("/allowed-chats", authMiddleware(allowedChatsHandler)).Methods("GET")
    r.HandleFunc("/upload", authMiddleware(uploadHandler)).Methods("POST")
    r.HandleFunc("/file/{path:.*}", authMiddleware(fileHandler)).Methods("GET")
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
        handlers.AllowCredentials(),
        handlers.OptionStatusCode(http.StatusNoContent),
    )

    // Wrap the router with CORS
    corsWrappedRouter := corsHandler(r)

    // Add logging middleware
    loggedRouter := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        log.Printf("Received request: %s %s from %s", r.Method, r.URL.Path, r.Header.Get("Origin"))
        log.Printf("Request headers: %v", r.Header)
        corsWrappedRouter.ServeHTTP(w, r)
        log.Printf("Response headers: %v", w.Header())
    })

    // Start server
    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }
    log.Printf("Server running on port %s", port)
    log.Fatal(http.ListenAndServe(":"+port, loggedRouter))
}

// Register handler (optional, can be removed if signupHandler is sufficient)
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

    // Create user in Supabase auth
    authUser, err := authClient.Signup(gotrue.SignupCredentials{
        Email:    user.Username + "@example.com", // Generate a dummy email
        Password: user.Password,
        Data: map[string]interface{}{
            "username": user.Username,
        },
    })
    if err != nil {
        log.Printf("Error creating user in Supabase auth: %v", err)
        http.Error(w, "Failed to register user", http.StatusInternalServerError)
        return
    }

    // Insert new user into the users table
    newUser := map[string]interface{}{
        "user_id":  authUser.ID.String(),
        "username": user.Username,
    }
    var result []map[string]interface{}
    _, err = supaClient.From("users").Insert(newUser, false, "", "representation", "exact").ExecuteTo(&result)
    if err != nil {
        log.Printf("Error registering user %s in Supabase: %v", user.Username, err)
        http.Error(w, "Failed to register user", http.StatusInternalServerError)
        return
    }

    log.Printf("User registered successfully: %s (user_id: %s)", user.Username, authUser.ID.String())
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
}

// Signup handler
func signupHandler(w http.ResponseWriter, r *http.Request) {
    var user struct {
        Username string `json:"username"`
        Email    string `json:"email"`
        Password string `json:"password"`
    }
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

    // Check if user exists in the users table
    var existingUsers []map[string]interface{}
    _, err := supaClient.From("users").Select("*", "exact", false).Eq("username", user.Username).ExecuteTo(&existingUsers)
    if err != nil {
        log.Printf("Error checking user in Supabase: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    if len(existingUsers) > 0 {
        log.Printf("Username %s already exists", user.Username)
        http.Error(w, "Username already exists", http.StatusConflict)
        return
    }

    // Create user in Supabase auth
    authUser, err := authClient.Signup(gotrue.SignupCredentials{
        Email:    user.Email,
        Password: user.Password,
        Data: map[string]interface{}{
            "username": user.Username,
        },
    })
    if err != nil {
        log.Printf("Error creating user in Supabase auth: %v", err)
        http.Error(w, "Failed to register user", http.StatusInternalServerError)
        return
    }

    // Sign in the user to get a JWT
    authResponse, err := authClient.SignInWithPassword(gotrue.SignInWithPasswordCredentials{
        Email:    user.Email,
        Password: user.Password,
    })
    if err != nil {
        log.Printf("Error signing in user %s to get JWT: %v", user.Username, err)
        http.Error(w, "Failed to generate token", http.StatusInternalServerError)
        return
    }

    // Insert new user into the users table
    newUser := map[string]interface{}{
        "user_id":  authUser.ID.String(),
        "username": user.Username,
        "email":    user.Email,
    }
    var result []map[string]interface{}
    _, err = supaClient.From("users").Insert(newUser, false, "", "representation", "exact").ExecuteTo(&result)
    if err != nil {
        log.Printf("Error registering user %s in Supabase: %v", user.Username, err)
        http.Error(w, "Failed to register user", http.StatusInternalServerError)
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

    // Fetch user from users table to get their email
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

    // Sign in user with Supabase auth to verify credentials
    authResponse, err := authClient.SignInWithPassword(gotrue.SignInWithPasswordCredentials{
        Email:    email,
        Password: creds.Password,
    })
    if err != nil {
        log.Printf("Error signing in user %s with Supabase auth: %v", creds.Username, err)
        http.Error(w, "Invalid username or password", http.StatusUnauthorized)
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
        r = r.WithContext(ctx)

        log.Println("Token validated successfully")
        next.ServeHTTP(w, r)
    }
}

// Check if two users are allowed to chat
func canUsersChat(user1, user2 string) (bool, error) {
    var chats []Chat
    _, err := supaClient.From("chats").
        Select("*", "exact", false).
        Filter("participant1", "eq", user1).
        Filter("participant2", "eq", user2).
        Or(fmt.Sprintf("and(participant1.eq.%s,participant2.eq.%s),and(participant1.eq.%s,participant2.eq.%s)", user1, user2, user2, user1), "or").
        ExecuteTo(&chats)
    if err != nil {
        return false, err
    }
    return len(chats) > 0, nil
}

// Allowed chats handler
func allowedChatsHandler(w http.ResponseWriter, r *http.Request) {
    userID, ok := r.Context().Value("user_id").(string)
    if !ok {
        log.Println("User ID not found in request context")
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    username, ok := r.Context().Value("username").(string)
    if !ok {
        log.Println("Username not found in request context")
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    log.Printf("Fetching allowed chats for user: %s (user_id: %s)", username, userID)
    var chats []Chat
    _, err := supaClient.From("chats").
        Select("id, participant1, participant2", "exact", false).
        Filter("participant1", "eq", userID).
        Or(fmt.Sprintf("participant1.eq.%s,participant2.eq.%s", userID, userID), "or").
        ExecuteTo(&chats)
    if err != nil {
        log.Printf("Error fetching allowed chats from Supabase for user %s: %v", userID, err)
        http.Error(w, "Failed to fetch allowed chats", http.StatusInternalServerError)
        return
    }

    allowedUserIDs := []string{}
    for _, chat := range chats {
        if chat.Participant1 == userID {
            allowedUserIDs = append(allowedUserIDs, chat.Participant2)
        } else {
            allowedUserIDs = append(allowedUserIDs, chat.Participant1)
        }
    }

    // Convert user IDs to usernames for the response
    allowedUsernames := []string{}
    for _, uid := range allowedUserIDs {
        var users []map[string]interface{}
        _, err := supaClient.From("users").Select("username", "exact", false).Eq("user_id", uid).ExecuteTo(&users)
        if err != nil {
            log.Printf("Error fetching username for user_id %s: %v", uid, err)
            continue
        }
        if len(users) > 0 {
            if username, ok := users[0]["username"].(string); ok {
                allowedUsernames = append(allowedUsernames, username)
            }
        }
    }

    // For non-admins, ensure they only have one chat partner (excluding admin)
    if userID != adminUserID {
        nonAdminChats := []string{}
        for _, user := range allowedUserIDs {
            if user != adminUserID {
                nonAdminChats = append(nonAdminChats, user)
            }
        }
        if len(nonAdminChats) > 1 {
            log.Printf("Non-admin user %s has more than one non-admin chat partner, which is not allowed", userID)
            http.Error(w, "Non-admin users can only have one chat partner", http.StatusForbidden)
            return
        }
    }

    log.Printf("Found %d allowed chats for user %s", len(allowedUsernames), userID)
    json.NewEncoder(w).Encode(allowedUsernames)
}

// Upload handler for files
func uploadHandler(w http.ResponseWriter, r *http.Request) {
    userID, ok := r.Context().Value("user_id").(string)
    if !ok {
        log.Println("User ID not found in request context")
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

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
    bucket := "chat-files"
    filePath := fmt.Sprintf("%s-%d", handler.Filename, time.Now().UnixNano())
    uploadURL := fmt.Sprintf("%s/storage/v1/object/%s/%s", os.Getenv("SUPABASE_URL"), bucket, filePath)

    req, err := http.NewRequest("POST", uploadURL, bytes.NewReader(fileBytes))
    if err != nil {
        log.Printf("Error creating HTTP request for file upload: %v", err)
        http.Error(w, "Failed to upload file", http.StatusInternalServerError)
        return
    }

    // Set headers for Supabase Storage API
    req.Header.Set("Authorization", "Bearer "+os.Getenv("SUPABASE_KEY"))
    req.Header.Set("Content-Type", "application/octet-stream")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        log.Printf("Error uploading file to Supabase Storage: %v", err)
        http.Error(w, "Failed to upload file", http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        log.Printf("Error uploading file to Supabase Storage: %s, response: %s", resp.Status, string(body))
        http.Error(w, "Failed to upload file", http.StatusInternalServerError)
        return
    }

    // Return a URL to the backend's file serving endpoint
    backendURL := os.Getenv("BACKEND_URL")
    if backendURL == "" {
        backendURL = "https://chat-backend-gxh8.onrender.com"
    }
    fileURL := fmt.Sprintf("%s/file/%s", backendURL, filePath)

    // Encrypt the file URL before returning
    encryptedFileURL, err := encryptString(fileURL)
    if err != nil {
        log.Printf("Error encrypting file URL for user %s: %v", userID, err)
        http.Error(w, "Failed to process file", http.StatusInternalServerError)
        return
    }

    log.Printf("File uploaded successfully for user %s, accessible at: %s (encrypted)", userID, fileURL)

    json.NewEncoder(w).Encode(map[string]string{"file_url": encryptedFileURL})
}

// File handler to serve files from Supabase Storage
func fileHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    filePath := vars["path"]

    userID, ok := r.Context().Value("user_id").(string)
    if !ok {
        log.Println("User ID not found in request context")
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    backendURL := os.Getenv("BACKEND_URL")
    if backendURL == "" {
        backendURL = "https://chat-backend-gxh8.onrender.com"
    }
    fileURL := fmt.Sprintf("%s/file/%s", backendURL, filePath)

    // Encrypt the file URL to match the stored value
    encryptedFileURL, err := encryptString(fileURL)
    if err != nil {
        log.Printf("Error encrypting file URL for user %s: %v", userID, err)
        http.Error(w, "Failed to verify access", http.StatusInternalServerError)
        return
    }

    // Check if the user has access to the file (sender or receiver)
    var messages []Message
    _, err = supaClient.From("messages").
        Select("*", "exact", false).
        Eq("file_url", encryptedFileURL).
        Filter("sender", "eq", userID).
        Or(fmt.Sprintf("sender.eq.%s,receiver.eq.%s", userID, userID), "or").
        ExecuteTo(&messages)
    if err != nil {
        log.Printf("Error checking file access in messages table: %v", err)
        http.Error(w, "Failed to verify access", http.StatusInternalServerError)
        return
    }

    if len(messages) == 0 {
        log.Printf("User %s does not have access to file %s", userID, filePath)
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

    // Download the file from Supabase Storage
    downloadURL := fmt.Sprintf("%s/storage/v1/object/%s/%s", os.Getenv("SUPABASE_URL"), "chat-files", filePath)
    req, err := http.NewRequest("GET", downloadURL, nil)
    if err != nil {
        log.Printf("Error creating HTTP request for file download: %v", err)
        http.Error(w, "Failed to fetch file", http.StatusInternalServerError)
        return
    }

    req.Header.Set("Authorization", "Bearer "+os.Getenv("SUPABASE_KEY"))

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        log.Printf("Error downloading file from Supabase Storage: %v", err)
        http.Error(w, "Failed to fetch file", http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        log.Printf("Error downloading file from Supabase Storage: %s, response: %s", resp.Status, string(body))
        http.Error(w, "Failed to fetch file", http.StatusInternalServerError)
        return
    }

    contentType := "application/octet-stream"
    if strings.HasSuffix(filePath, ".jpg") || strings.HasSuffix(filePath, ".jpeg") {
        contentType = "image/jpeg"
    } else if strings.HasSuffix(filePath, ".png") {
        contentType = "image/png"
    } else if strings.HasSuffix(filePath, ".mp4") {
        contentType = "video/mp4"
    }
    w.Header().Set("Content-Type", contentType)

    _, err = io.Copy(w, resp.Body)
    if err != nil {
        log.Printf("Error streaming file to client: %v", err)
        http.Error(w, "Failed to stream file", http.StatusInternalServerError)
        return
    }

    log.Printf("File served successfully to user %s: %s", userID, filePath)
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

    userID, ok := r.Context().Value("user_id").(string)
    if !ok {
        log.Println("User ID not found in request context")
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    // Verify that the user is part of this chat
    if userID != sender {
        log.Printf("User %s does not match sender %s in chat ID", userID, sender)
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

    // Verify that the chat is allowed
    allowed, err := canUsersChat(sender, receiver)
    if err != nil {
        log.Printf("Error checking if users can chat: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    if !allowed {
        log.Printf("Chat between %s and %s is not allowed", sender, receiver)
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

    // For non-admins, ensure they only have one non-admin chat partner
    if userID != adminUserID {
        var chats []Chat
        _, err := supaClient.From("chats").
            Select("id, participant1, participant2", "exact", false).
            Filter("participant1", "eq", userID).
            Or(fmt.Sprintf("participant1.eq.%s,participant2.eq.%s", userID, userID), "or").
            ExecuteTo(&chats)
        if err != nil {
            log.Printf("Error fetching chats for user %s: %v", userID, err)
            http.Error(w, "Internal server error", http.StatusInternalServerError)
            return
        }

        nonAdminChats := 0
        for _, chat := range chats {
            otherUser := chat.Participant1
            if chat.Participant1 == userID {
                otherUser = chat.Participant2
            }
            if otherUser != adminUserID {
                nonAdminChats++
            }
        }

        if nonAdminChats > 1 {
            log.Printf("Non-admin user %s has more than one non-admin chat partner, which is not allowed", userID)
            http.Error(w, "Non-admin users can only have one chat partner", http.StatusForbidden)
            return
        }
    }

    log.Printf("Fetching messages for chat ID %s (sender: %s, receiver: %s)", chatID, sender, receiver)
    var messages []Message
    _, err = supaClient.From("messages").
        Select("*", "exact", false).
        Filter("sender", "eq", sender).
        Filter("receiver", "eq", receiver).
        Or(fmt.Sprintf("and(sender.eq.%s,receiver.eq.%s),and(sender.eq.%s,receiver.eq.%s)", sender, receiver, receiver, sender), "or").
        Order("timestamp", &postgrest.OrderOpts{Ascending: true}).
        ExecuteTo(&messages)
    if err != nil {
        log.Printf("Error fetching messages from Supabase for chat ID %s: %v", chatID, err)
        http.Error(w, "Failed to fetch messages", http.StatusInternalServerError)
        return
    }

    // Decrypt file URLs in messages
    for i := range messages {
        if messages[i].FileURL != "" {
            decryptedURL, err := decryptString(messages[i].FileURL)
            if err != nil {
                log.Printf("Error decrypting file URL for message: %v", err)
                continue
            }
            messages[i].FileURL = decryptedURL
        }
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

    if pushReg.UserID == "" || pushReg.Token == "" {
        log.Println("User ID or token missing in /register-push request")
        http.Error(w, "User ID and token are required", http.StatusBadRequest)
        return
    }

    userID, ok := r.Context().Value("user_id").(string)
    if !ok || userID != pushReg.UserID {
        log.Println("User ID mismatch in /register-push request")
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    clientsMutex.Lock()
    client, exists := clients[pushReg.UserID]
    if !exists {
        client = &Client{}
    }
    client.PushToken = pushReg.Token
    clients[pushReg.UserID] = client
    clientsMutex.Unlock()

    log.Printf("Push token registered for user: %s", pushReg.UserID)
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"message": "Push token registered"})
}

// WebSocket handler
func wsHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.URL.Query().Get("user_id")
    if userID == "" {
        log.Println("User ID missing in /ws request")
        http.Error(w, "User ID is required", http.StatusBadRequest)
        return
    }

    log.Printf("WebSocket connection attempt for user: %s", userID)

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

    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok || claims["sub"] == nil {
        log.Println("Invalid token claims for WebSocket connection")
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }

    tokenUserID := claims["sub"].(string)
    if tokenUserID != userID {
        log.Printf("User ID mismatch in WebSocket connection: token user_id %s, query user_id %s", tokenUserID, userID)
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    log.Println("WebSocket token validated successfully")

    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Printf("WebSocket upgrade error for user %s: %v", userID, err)
        return
    }

    clientsMutex.Lock()
    client, exists := clients[userID]
    if !exists {
        client = &Client{}
    }
    client.Conn = conn
    clients[userID] = client
    clientsMutex.Unlock()

    defer func() {
        clientsMutex.Lock()
        if client, exists := clients[userID]; exists {
            client.Conn = nil
            clients[userID] = client
        }
        clientsMutex.Unlock()
        conn.Close()
        log.Printf("WebSocket connection closed for user: %s", userID)
    }()

    // For non-admins, ensure they only have one non-admin chat partner
    if userID != adminUserID {
        var chats []Chat
        _, err := supaClient.From("chats").
            Select("id, participant1, participant2", "exact", false).
            Filter("participant1", "eq", userID).
            Or(fmt.Sprintf("participant1.eq.%s,participant2.eq.%s", userID, userID), "or").
            ExecuteTo(&chats)
        if err != nil {
            log.Printf("Error fetching chats for user %s in WebSocket handler: %v", userID, err)
            return
        }

        nonAdminChats := 0
        for _, chat := range chats {
            otherUser := chat.Participant1
            if chat.Participant1 == userID {
                otherUser = chat.Participant2
            }
            if otherUser != adminUserID {
                nonAdminChats++
            }
        }

        if nonAdminChats > 1 {
            log.Printf("Non-admin user %s has more than one non-admin chat partner, which is not allowed", userID)
            return
        }
    }

    log.Printf("WebSocket connection established for user: %s", userID)

    for {
        var msg Message
        err := conn.ReadJSON(&msg)
        if err != nil {
            log.Printf("WebSocket read error for user %s: %v", userID, err)
            break
        }

        // Validate that the sender matches the authenticated user
        if msg.Sender != userID {
            log.Printf("Sender %s does not match authenticated user %s", msg.Sender, userID)
            continue
        }

        // Validate that the sender and receiver are allowed to chat
        allowed, err := canUsersChat(msg.Sender, msg.Receiver)
        if err != nil {
            log.Printf("Error checking if users can chat: %v", err)
            continue
        }
        if !allowed {
            log.Printf("Chat between %s and %s is not allowed", msg.Sender, msg.Receiver)
            continue
        }

        msg.Timestamp = time.Now()

        switch msg.Type {
        case "text", "file":
            if msg.Status != "ephemeral" {
                // Encrypt the file URL if present
                var encryptedFileURL string
                if msg.FileURL != "" {
                    encryptedFileURL, err = encryptString(msg.FileURL)
                    if err != nil {
                        log.Printf("Error encrypting file URL for user %s: %v", userID, err)
                        continue
                    }
                }

                newMessage := map[string]interface{}{
                    "sender":    msg.Sender,
                    "receiver":  msg.Receiver,
                    "content":   msg.Content,
                    "file_url":  encryptedFileURL,
                    "file_type": msg.FileType,
                    "timestamp": msg.Timestamp,
                    "status":    msg.Status,
                    "type":      msg.Type,
                }
                var result []map[string]interface{}
                _, err := supaClient.From("messages").Insert(newMessage, false, "", "representation", "exact").ExecuteTo(&result)
                if err != nil {
                    log.Printf("Error storing message in Supabase for user %s: %v", userID, err)
                    continue
                }

                // Decrypt the file URL for sending over WebSocket
                if msg.FileURL != "" {
                    msg.FileURL, err = decryptString(encryptedFileURL)
                    if err != nil {
                        log.Printf("Error decrypting file URL for user %s: %v", userID, err)
                        continue
                    }
                }
            } else {
                log.Printf("Ephemeral message from %s to %s, not stored in Supabase", msg.Sender, msg.Receiver)
            }

            clientsMutex.Lock()
            receiverClient, exists := clients[msg.Receiver]
            if exists && receiverClient.Conn != nil {
                err = receiverClient.Conn.WriteJSON(msg)
                if err != nil {
                    log.Printf("WebSocket write error for user %s to receiver %s: %v", userID, msg.Receiver, err)
                }
            } else if exists && receiverClient.PushToken != "" {
                if !fcmEnabled {
                    log.Printf("Push notifications disabled, skipping notification to %s", msg.Receiver)
                    clientsMutex.Unlock()
                    continue
                }
                // Fetch sender's username for notification
                var users []map[string]interface{}
                _, err := supaClient.From("users").Select("username", "exact", false).Eq("user_id", msg.Sender).ExecuteTo(&users)
                senderUsername := msg.Sender
                if err == nil && len(users) > 0 {
                    if username, ok := users[0]["username"].(string); ok {
                        senderUsername = username
                    }
                }
                message := &messaging.Message{
                    Notification: &messaging.Notification{
                        Title: fmt.Sprintf("New message from %s", senderUsername),
                        Body:  msg.Content,
                    },
                    Token: receiverClient.PushToken,
                }
                _, err = fcmClient.Send(context.Background(), message)
                if err != nil {
                    log.Printf("Error sending push notification to %s: %v", msg.Receiver, err)
                } else {
                    log.Printf("Push notification sent to %s", msg.Receiver)
                }
            }
            clientsMutex.Unlock()

        case "call_signal":
            clientsMutex.Lock()
            receiverClient, exists := clients[msg.Receiver]
            if exists && receiverClient.Conn != nil {
                err = receiverClient.Conn.WriteJSON(msg)
                if err != nil {
                    log.Printf("WebSocket write error for user %s to receiver %s: %v", userID, msg.Receiver, err)
                }
            } else if exists && receiverClient.PushToken != "" && msg.Signal.Type == "call-initiate" {
                if !fcmEnabled {
                    log.Printf("Push notifications disabled, skipping call notification to %s", msg.Receiver)
                    clientsMutex.Unlock()
                    continue
                }
                // Fetch sender's username for notification
                var users []map[string]interface{}
                _, err := supaClient.From("users").Select("username", "exact", false).Eq("user_id", msg.Sender).ExecuteTo(&users)
                senderUsername := msg.Sender
                if err == nil && len(users) > 0 {
                    if username, ok := users[0]["username"].(string); ok {
                        senderUsername = username
                    }
                }
                message := &messaging.Message{
                    Notification: &messaging.Notification{
                        Title: fmt.Sprintf("Incoming %s call from %s", msg.Signal.CallType, senderUsername),
                        Body:  "Tap to accept the call",
                    },
                    Data: map[string]string{
                        "call_initiator": msg.Sender,
                        "call_type":      msg.Signal.CallType,
                    },
                    Token: receiverClient.PushToken,
                }
                _, err = fcmClient.Send(context.Background(), message)
                if err != nil {
                    log.Printf("Error sending call notification to %s: %v", msg.Receiver, err)
                } else {
                    log.Printf("Call notification sent to %s", msg.Receiver)
                }
            }
            clientsMutex.Unlock()

            if msg.Signal.Type == "call-initiate" {
                newCall := map[string]interface{}{
                    "caller":     msg.Sender,
                    "callee":     msg.Receiver,
                    "call_type":  msg.Signal.CallType,
                    "start_time": msg.Timestamp,
                    "status":     "initiated",
                }
                var result []map[string]interface{}
                _, err := supaClient.From("calls").Insert(newCall, false, "", "representation", "exact").ExecuteTo(&result)
                if err != nil {
                    log.Printf("Error storing call in Supabase for user %s: %v", userID, err)
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
