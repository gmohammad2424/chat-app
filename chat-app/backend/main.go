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
    "path/filepath"
    "regexp"
    "sort"
    "strings"
    "sync"
    "time"

    "firebase.google.com/go/v4"
    "firebase.google.com/go/v4/messaging"
    "github.com/gorilla/handlers"
    "github.com/gorilla/mux"
    "github.com/gorilla/websocket"
    "github.com/joho/godotenv"
    "github.com/supabase-community/gotrue-go"
    "github.com/supabase-community/postgrest-go"
    "github.com/supabase-community/storage-go"
)

// Global variables
var (
    clients           = make(map[string]*Client)
    clientsMutex      sync.Mutex
    fcmClient         *messaging.Client
    postgrestClient   *postgrest.Client
    storageClient     *storage_go.Client
    authClient        gotrue.Client
    encryptionKey     []byte
    fcmEnabled        bool
    supabaseURL       string
    supabaseServiceKey string
    supabaseAnonKey   string
    lastPongLog       = make(map[string]time.Time)
    pongLogInterval   = 30 * time.Second
)

// Client struct
type Client struct {
    Conn      *websocket.Conn
    PushToken string
}

// Chat struct (uses int ID for int4)
type Chat struct {
    ID           int    `json:"id"`
    Participant1 string `json:"participant1"`
    Participant2 string `json:"participant2"`
}

// Message struct
type Message struct {
    Type      string     `json:"type"`
    Sender    string     `json:"sender"`
    Receiver  string     `json:"receiver"`
    Content   string     `json:"content,omitempty"`
    FileURL   string     `json:"file_url,omitempty"`
    FileType  string     `json:"file_type,omitempty"`
    Timestamp time.Time  `json:"timestamp"`
    Signal    SignalData `json:"signal,omitempty"`
}

// SignalData struct
type SignalData struct {
    Type       string      `json:"type"`
    Offer      interface{} `json:"offer,omitempty"`
    Answer     interface{} `json:"answer,omitempty"`
    Candidate  interface{} `json:"candidate,omitempty"`
    CallType   string      `json:"call_type,omitempty"`
    CallStatus string      `json:"call_status,omitempty"`
}

// User struct
type User struct {
    Username string `json:"username"`
    Email    string `json:"email"`
    Password string `json:"password"`
}

// UserResponse struct
type UserResponse struct {
    UserID   string `json:"user_id"`
    Username string `json:"username"`
}

// PushRegistration struct
type PushRegistration struct {
    UserID string `json:"user_id"`
    Token  string `json:"token"`
}

// SupabaseUser struct for parsing /user endpoint response
type SupabaseUser struct {
    ID           string                 `json:"id"`
    Email        string                 `json:"email"`
    UserMetadata map[string]interface{} `json:"user_metadata"`
}

// WebSocket upgrader
var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool {
        return true // Adjust for production
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

// Validate UUID format for user IDs
func isValidUUID(id string) bool {
    return regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(id)
}

// Check if user exists
func userExists(userID string) (bool, error) {
    if !isValidUUID(userID) {
        return false, fmt.Errorf("invalid UUID format: %s", userID)
    }
    var users []map[string]interface{}
    data, _, err := postgrestClient.From("users").Select("user_id", "exact", false).Eq("user_id", userID).Execute()
    if err != nil {
        return false, fmt.Errorf("error checking user %s: %v", userID, err)
    }
    if err := json.Unmarshal(data, &users); err != nil {
        return false, fmt.Errorf("error unmarshaling users: %v", err)
    }
    return len(users) > 0, nil
}

// Get or create chat ID
func getOrCreateChatID(sender, receiver string) (int, error) {
    if sender == "" || receiver == "" {
        return 0, fmt.Errorf("sender or receiver ID is empty")
    }
    if !isValidUUID(sender) || !isValidUUID(receiver) {
        return 0, fmt.Errorf("invalid UUID format for sender %s or receiver %s", sender, receiver)
    }

    senderExists, err := userExists(sender)
    if err != nil {
        return 0, fmt.Errorf("error checking sender %s: %v", sender, err)
    }
    if !senderExists {
        return 0, fmt.Errorf("sender %s does not exist", sender)
    }

    receiverExists, err := userExists(receiver)
    if err != nil {
        return 0, fmt.Errorf("error checking receiver %s: %v", receiver, err)
    }
    if !receiverExists {
        return 0, fmt.Errorf("receiver %s does not exist", receiver)
    }

    participants := []string{sender, receiver}
    sort.Strings(participants)
    participant1, participant2 := participants[0], participants[1]

    var chats []Chat
    query := postgrestClient.From("chats").Select("id", "exact", false)
    query = query.Eq("participant1", participant1).Eq("participant2", participant2)
    data, _, err := query.Execute()
    if err != nil {
        return 0, fmt.Errorf("error checking chat between %s and %s: %v", participant1, participant2, err)
    }
    if err := json.Unmarshal(data, &chats); err != nil {
        return 0, fmt.Errorf("error unmarshaling chats: %v", err)
    }

    if len(chats) > 0 {
        log.Printf("Found chat ID %d for %s and %s", chats[0].ID, participant1, participant2)
        return chats[0].ID, nil
    }

    newChat := map[string]interface{}{
        "participant1": participant1,
        "participant2": participant2,
        "created_at":   time.Now(),
    }
    var result []map[string]interface{}
    data, _, err = postgrestClient.From("chats").Insert([]interface{}{newChat}, false, "", "representation", "exact").Execute()
    if err != nil {
        return 0, fmt.Errorf("error creating chat for %s and %s: %v", participant1, participant2, err)
    }
    if err := json.Unmarshal(data, &result); err != nil {
        return 0, fmt.Errorf("error unmarshaling new chat: %v", err)
    }

    if len(result) == 0 {
        return 0, fmt.Errorf("no chat ID returned")
    }

    chatID, ok := result[0]["id"].(float64) // JSON numbers are float64
    if !ok {
        return 0, fmt.Errorf("invalid chat ID format")
    }

    log.Printf("Created chat ID %d for %s and %s", int(chatID), participant1, participant2)
    return int(chatID), nil
}

// Validate token and get user
func validateToken(token string) (*SupabaseUser, error) {
    authURL := supabaseURL + "/auth/v1/user"
    req, err := http.NewRequest("GET", authURL, nil)
    if err != nil {
        return nil, fmt.Errorf("error creating user request: %v", err)
    }
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("apikey", supabaseAnonKey)

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return nil, fmt.Errorf("error fetching user: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("invalid token: %s", string(body))
    }

    var user SupabaseUser
    if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
        return nil, fmt.Errorf("error decoding user response: %v", err)
    }

    if user.ID == "" {
        return nil, fmt.Errorf("user ID not found in response")
    }

    return &user, nil
}

// WebSocket handler
func wsHandler(w http.ResponseWriter, r *http.Request) {
    token := r.URL.Query().Get("token")
    receiverID := r.URL.Query().Get("receiver_id")
    chatIDStr := r.URL.Query().Get("chat_id")

    if token == "" {
        log.Println("Token missing in WebSocket request")
        http.Error(w, "Token is required", http.StatusUnauthorized)
        return
    }

    if receiverID == "" {
        log.Println("receiver_id missing in WebSocket request")
        http.Error(w, "receiver_id is required", http.StatusBadRequest)
        return
    }

    if !isValidUUID(receiverID) {
        log.Printf("Invalid receiver_id format: %s", receiverID)
        http.Error(w, "Invalid receiver_id format", http.StatusBadRequest)
        return
    }

    // Validate token
    user, err := validateToken(token)
    if err != nil {
        log.Printf("Error validating token: %v", err)
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }
    userID := user.ID
    if userID == "" {
        log.Println("User ID not found in token response")
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }

    // Validate receiver
    receiverExists, err := userExists(receiverID)
    if err != nil {
        log.Printf("Error checking receiver %s: %v", receiverID, err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    if !receiverExists {
        log.Printf("Receiver %s does not exist", receiverID)
        http.Error(w, "Receiver not found", http.StatusBadRequest)
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

    // Get or validate chat ID
    var resolvedChatID int
    if chatIDStr != "" {
        var chatID int
        _, err := fmt.Sscanf(chatIDStr, "%d", &chatID)
        if err != nil {
            log.Printf("Invalid chat_id format: %s", chatIDStr)
            conn.WriteJSON(map[string]interface{}{"type": "error", "error": "Invalid chat_id"})
            conn.Close()
            return
        }
        var chats []Chat
        query := postgrestClient.From("chats").Select("id", "exact", false)
        query = query.Eq("id", fmt.Sprintf("%d", chatID)).Or(fmt.Sprintf("participant1.eq.%s,participant2.eq.%s", userID, userID), "")
        data, _, err := query.Execute()
        if err != nil {
            log.Printf("Error validating chat_id %d: %v", chatID, err)
            conn.WriteJSON(map[string]interface{}{"type": "error", "error": "Invalid chat_id"})
            conn.Close()
            return
        }
        if err := json.Unmarshal(data, &chats); err != nil {
            log.Printf("Error unmarshaling chats: %v", err)
            conn.WriteJSON(map[string]interface{}{"type": "error", "error": "Internal server error"})
            conn.Close()
            return
        }
        if len(chats) == 0 {
            log.Printf("Chat ID %d not found for user %s", chatID, userID)
            conn.WriteJSON(map[string]interface{}{"type": "error", "error": "Invalid chat_id"})
            conn.Close()
            return
        }
        resolvedChatID = chats[0].ID
    } else {
        resolvedChatID, err = getOrCreateChatID(userID, receiverID)
        if err != nil {
            log.Printf("Error getting or creating chat ID: %v", err)
            conn.WriteJSON(map[string]interface{}{"type": "error", "error": fmt.Sprintf("Failed to get or create chat: %v", err)})
            conn.Close()
            return
        }
    }

    // Send chat_id to client
    err = conn.WriteJSON(map[string]interface{}{"type": "chat_id", "chat_id": resolvedChatID})
    if err != nil {
        log.Printf("Error sending chat_id to client %s: %v", userID, err)
        conn.Close()
        return
    }

    // Ping mechanism
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

    // Handle incoming WebSocket messages
    for {
        var msg Message
        err := conn.ReadJSON(&msg)
        if err != nil {
            if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
                log.Printf("WebSocket closed for user %s: code=%d", userID, websocket.CloseNormalClosure)
            } else {
                log.Printf("Error reading WebSocket message for user %s: %v", userID, err)
            }
            break
        }

        if msg.Type == "pong" {
            clientsMutex.Lock()
            lastLog, exists := lastPongLog[userID]
            shouldLog := !exists || time.Since(lastLog) >= pongLogInterval
            if shouldLog {
                log.Printf("Received pong from client %s at %s", userID, time.Now().Format(time.RFC3339))
                lastPongLog[userID] = time.Now()
            }
            clientsMutex.Unlock()
            continue
        }

        msg.Timestamp = time.Now()

        switch msg.Type {
        case "text", "file":
            // Encrypt content for text messages
            var encryptedContent string
            if msg.Type == "text" && msg.Content != "" {
                encryptedContent, err = encryptString(msg.Content)
                if err != nil {
                    log.Printf("Error encrypting message content: %v", err)
                    conn.WriteJSON(map[string]interface{}{"type": "error", "error": "Failed to encrypt message"})
                    continue
                }
            } else {
                encryptedContent = msg.Content
            }

            // File URLs are already encrypted by uploadHandler
            messageData := map[string]interface{}{
                "chat_id":   resolvedChatID,
                "sender":    msg.Sender,
                "receiver":  msg.Receiver,
                "content":   encryptedContent,
                "file_url":  msg.FileURL,
                "type":      msg.Type,
                "timestamp": msg.Timestamp,
            }
            if msg.FileType != "" {
                messageData["file_type"] = msg.FileType
            }

            var result []map[string]interface{}
            data, _, err := postgrestClient.From("messages").Insert([]interface{}{messageData}, false, "", "representation", "exact").Execute()
            if err != nil {
                log.Printf("Error saving message to Supabase: %v", err)
                log.Printf("Attempted message data: %v", messageData)
                log.Printf("Response data: %s", string(data))
                conn.WriteJSON(map[string]interface{}{"type": "error", "error": "Failed to save message"})
                continue
            }
            if err := json.Unmarshal(data, &result); err != nil {
                log.Printf("Error unmarshaling insert result: %v", err)
                conn.WriteJSON(map[string]interface{}{"type": "error", "error": "Internal server error"})
                continue
            }

            // Decrypt content for sending to clients
            decryptedMsg := msg
            if msg.Type == "text" && msg.Content != "" {
                decryptedMsg.Content = msg.Content // Original content from client
            }
            if msg.FileURL != "" {
                decryptedURL, err := decryptString(msg.FileURL)
                if err != nil {
                    log.Printf("Error decrypting file_url: %v", err)
                    continue
                }
                decryptedMsg.FileURL = decryptedURL
            }

            clientsMutex.Lock()
            if receiverClient, exists := clients[msg.Receiver]; exists && receiverClient.Conn != nil {
                err = receiverClient.Conn.WriteJSON(decryptedMsg)
                if err != nil {
                    log.Printf("Error sending message to receiver %s: %v", msg.Receiver, err)
                }
            } else if fcmEnabled {
                if receiverClient != nil && receiverClient.PushToken != "" {
                    pushMsg := &messaging.Message{
                        Notification: &messaging.Notification{
                            Title: "New Message",
                            Body:  fmt.Sprintf("You have a new %s from %s", msg.Type, msg.Sender),
                        },
                        Token: receiverClient.PushToken,
                    }
                    _, err := fcmClient.Send(ctx, pushMsg)
                    if err != nil {
                        log.Printf("Error sending push notification to %s: %v", msg.Receiver, err)
                    }
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
                _, _, err = postgrestClient.From("calls").Insert([]interface{}{callData}, false, "", "representation", "exact").Execute()
                if err != nil {
                    log.Printf("Error logging call: %v", err)
                }
            } else if msg.Signal.Type == "call-accept" || msg.Signal.Type == "call-reject" {
                _, _, err = postgrestClient.From("calls").Update(map[string]interface{}{
                    "status":   msg.Signal.CallStatus,
                    "end_time": time.Now(),
                }, "", "exact").Eq("caller", msg.Sender).Eq("callee", msg.Receiver).Execute()
                if err != nil {
                    log.Printf("Error updating call status: %v", err)
                }
            }
        }
    }
}

// Authentication and user handlers
func signupHandler(w http.ResponseWriter, r *http.Request) {
    var user User
    if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
        log.Printf("Invalid request body for /signup: %v", err)
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    if user.Username == "" || user.Email == "" || user.Password == "" {
        log.Println("Username, email, or password missing")
        http.Error(w, "Username, email, and password are required", http.StatusBadRequest)
        return
    }

    var existingUsers []map[string]interface{}
    data, _, err := postgrestClient.From("users").Select("*", "exact", false).Eq("username", user.Username).Execute()
    if err != nil {
        log.Printf("Error checking user: %v", err)
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

    // Sign up user with Supabase Auth API directly
    signupRequest := map[string]interface{}{
        "email":    user.Email,
        "password": user.Password,
        "data": map[string]interface{}{
            "username": user.Username,
        },
    }
    signupRequestBody, err := json.Marshal(signupRequest)
    if err != nil {
        log.Printf("Error marshaling signup request: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    authURL := supabaseURL + "/auth/v1/signup"
    req, err := http.NewRequest("POST", authURL, bytes.NewBuffer(signupRequestBody))
    if err != nil {
        log.Printf("Error creating signup request: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("apikey", supabaseAnonKey)

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        log.Printf("Error signing up user %s: %v", user.Username, err)
        http.Error(w, "Failed to register user", http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        log.Printf("Error signing up user %s: %s", user.Username, string(body))
        http.Error(w, "Failed to register user", http.StatusInternalServerError)
        return
    }

    var authUser struct {
        ID           string                 `json:"id"`
        Email        string                 `json:"email"`
        UserMetadata map[string]interface{} `json:"user_metadata"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&authUser); err != nil {
        log.Printf("Error decoding signup response: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    // Generate token
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

    tokenURL := supabaseURL + "/auth/v1/token?grant_type=password"
    req, err = http.NewRequest("POST", tokenURL, bytes.NewBuffer(tokenRequestBody))
    if err != nil {
        log.Printf("Error creating token request: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("apikey", supabaseAnonKey)

    resp, err = client.Do(req)
    if err != nil {
        log.Printf("Error signing in user %s: %v", user.Username, err)
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
        "user_id":  authUser.ID,
        "username": user.Username,
        "email":    user.Email,
    }
    var result []map[string]interface{}
    data, _, err = postgrestClient.From("users").Insert([]interface{}{newUser}, false, "", "representation", "exact").Execute()
    if err != nil {
        log.Printf("Error registering user %s: %v", user.Username, err)
        http.Error(w, "Failed to register user", http.StatusInternalServerError)
        return
    }
    if err := json.Unmarshal(data, &result); err != nil {
        log.Printf("Error unmarshaling insert result: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    log.Printf("User signed up: %s (user_id: %s)", user.Username, authUser.ID)
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "token": authResponse.AccessToken,
    })
}

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
        log.Println("Username or password missing")
        http.Error(w, "Invalid credentials", http.StatusBadRequest)
        return
    }

    // Fetch user from Supabase
    var users []map[string]interface{}
    data, _, err := postgrestClient.From("users").Select("*", "exact", false).Eq("username", creds.Username).Execute()
    if err != nil {
        log.Printf("Error fetching user %s: %v", creds.Username, err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    if err := json.Unmarshal(data, &users); err != nil {
        log.Printf("Error unmarshaling users: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    if len(users) == 0 {
        log.Printf("User %s not found", creds.Username)
        http.Error(w, "Invalid username or password", http.StatusUnauthorized)
        return
    }

    user := users[0]
    email, ok := user["email"].(string)
    if !ok {
        log.Printf("Invalid email format for user %s", creds.Username)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    userID, ok := user["user_id"].(string)
    if !ok {
        log.Printf("Invalid user_id format for user %s", creds.Username)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    // Request token from Supabase
    tokenRequest := map[string]interface{}{
        "grant_type": "password",
        "email":      email,
        "password":   creds.Password,
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
        log.Printf("Error signing in user %s: %v", creds.Username, err)
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
        log.Printf("Error decoding token response: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    log.Printf("Login successful for user: %s (user_id: %s)", creds.Username, userID)
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "token": authResponse.AccessToken,
    })
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            log.Println("Authorization header missing")
            http.Error(w, "Token is required", http.StatusForbidden)
            return
        }

        tokenString := strings.TrimPrefix(authHeader, "Bearer ")
        user, err := validateToken(tokenString)
        if err != nil {
            log.Printf("Invalid token: %v", err)
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        ctx := context.WithValue(r.Context(), "user_id", user.ID)
        ctx = context.WithValue(ctx, "username", user.UserMetadata["username"])
        next.ServeHTTP(w, r.WithContext(ctx))
    }
}

func usersHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value("user_id").(string)
    username := r.Context().Value("username").(string)
    log.Printf("Fetching users for user: %s (user_id: %s)", username, userID)

    var rawUsers []map[string]interface{}
    data, _, err := postgrestClient.From("users").Select("user_id, username", "exact", false).Execute()
    if err != nil {
        log.Printf("Error fetching users: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    if err := json.Unmarshal(data, &rawUsers); err != nil {
        log.Printf("Error unmarshaling users: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    users := make([]UserResponse, 0, len(rawUsers))
    for _, rawUser := range rawUsers {
        user := UserResponse{
            UserID:   rawUser["user_id"].(string),
            Username: rawUser["username"].(string),
        }
        users = append(users, user)
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(users)
}

func messagesHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value("user_id").(string)
    chatIDStr := r.URL.Query().Get("chat_id")
    if chatIDStr == "" {
        log.Println("chat_id parameter missing")
        http.Error(w, "chat_id is required", http.StatusBadRequest)
        return
    }

    var chatID int
    _, err := fmt.Sscanf(chatIDStr, "%d", &chatID)
    if err != nil {
        log.Printf("Invalid chat_id format: %s", chatIDStr)
        http.Error(w, "Invalid chat_id format", http.StatusBadRequest)
        return
    }

    // Verify user has access to chat
    var chats []Chat
    query := postgrestClient.From("chats").Select("id", "exact", false)
    query = query.Eq("id", fmt.Sprintf("%d", chatID)).Or(fmt.Sprintf("participant1.eq.%s,participant2.eq.%s", userID, userID), "")
    data, _, err := query.Execute()
    if err != nil {
        log.Printf("Error validating chat_id %d for user %s: %v", chatID, userID, err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    if err := json.Unmarshal(data, &chats); err != nil {
        log.Printf("Error unmarshaling chats: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    if len(chats) == 0 {
        log.Printf("Chat ID %d not accessible for user %s", chatID, userID)
        http.Error(w, "Unauthorized access to chat", http.StatusUnauthorized)
        return
    }

    var messages []map[string]interface{}
    data, _, err = postgrestClient.From("messages").Select("*", "exact", false).Eq("chat_id", fmt.Sprintf("%d", chatID)).Execute()
    if err != nil {
        log.Printf("Error fetching messages for chat %d: %v", chatID, err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    if err := json.Unmarshal(data, &messages); err != nil {
        log.Printf("Error unmarshaling messages: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    // Decrypt messages
    for _, msg := range messages {
        if msg["type"] == "text" && msg["content"] != nil && msg["content"] != "" {
            content, ok := msg["content"].(string)
            if !ok {
                log.Printf("Invalid content format for message in chat %d", chatID)
                continue
            }
            decrypted, err := decryptString(content)
            if err != nil {
                log.Printf("Error decrypting message content: %v", err)
                continue
            }
            msg["content"] = decrypted
        }
        if msg["file_url"] != nil && msg["file_url"] != "" {
            fileURL, ok := msg["file_url"].(string)
            if !ok {
                log.Printf("Invalid file_url format for message in chat %d", chatID)
                continue
            }
            decryptedURL, err := decryptString(fileURL)
            if err != nil {
                log.Printf("Error decrypting file_url: %v", err)
                continue
            }
            msg["file_url"] = decryptedURL
        }
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(messages)
}

func allowedChatsHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value("user_id").(string)

    var chats []Chat
    query := postgrestClient.From("chats").Select("*", "exact", false)
    query = query.Or(fmt.Sprintf("participant1.eq.%s,participant2.eq.%s", userID, userID), "")
    data, _, err := query.Execute()
    if err != nil {
        log.Printf("Error fetching chats for user %s: %v", userID, err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    if err := json.Unmarshal(data, &chats); err != nil {
        log.Printf("Error unmarshaling chats: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(chats)
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value("user_id").(string)
    log.Printf("File upload attempt by user %s", userID)

    err := r.ParseMultipartForm(10 << 20)
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
        log.Printf("Error retrieving file: %v", err)
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

    timestamp := time.Now().Format("20060102-150405")
    originalFileName := sanitizeFileName(handler.Filename)
    fileName := fmt.Sprintf("%s/%s_%s", userID, timestamp, originalFileName)
    log.Printf("Uploading file to chat-files: %s", fileName)

    _, err = storageClient.UploadFile("chat-files", fileName, bytes.NewReader(fileBytes))
    if err != nil {
        log.Printf("Error uploading file: %v", err)
        errorResponse := map[string]string{"error": "Unable to upload file"}
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
        log.Printf("Error fetching file: %v", err)
        http.Error(w, "Unable to fetch file", http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
    io.Copy(w, resp.Body)
}

func registerPushHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value("user_id").(string)

    var pushReg PushRegistration
    if err := json.NewDecoder(r.Body).Decode(&pushReg); err != nil {
        log.Printf("Invalid request body for /register-push: %v", err)
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    if pushReg.Token == "" {
        log.Println("Push token missing")
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

func sanitizeFileName(filename string) string {
    reg, err := regexp.Compile("[^a-zA-Z0-9._-]")
    if err != nil {
        log.Printf("Error compiling regex: %v", err)
        return filename
    }
    sanitized := reg.ReplaceAllString(filename, "_")
    if len(sanitized) > 100 {
        ext := filepath.Ext(sanitized)
        base := sanitized[:100-len(ext)]
        sanitized = base + ext
    }
    return sanitized
}

func main() {
    err := godotenv.Load()
    if err != nil {
        log.Println("No .env file found")
    }

    encryptionKeyString := os.Getenv("ENCRYPTION_KEY")
    if encryptionKeyString == "" {
        log.Fatal("ENCRYPTION_KEY is required")
    }
    encryptionKey, err = base64.StdEncoding.DecodeString(encryptionKeyString)
    if err != nil {
        log.Fatalf("Error decoding ENCRYPTION_KEY: %v", err)
    }
    if len(encryptionKey) != 32 {
        log.Fatal("ENCRYPTION_KEY must be 32 bytes")
    }

    supabaseURL = os.Getenv("SUPABASE_URL")
    supabaseServiceKey = os.Getenv("SUPABASE_SERVICE_KEY")
    supabaseAnonKey = os.Getenv("SUPABASE_ANON_KEY")
    if supabaseURL == "" || supabaseServiceKey == "" || supabaseAnonKey == "" {
        log.Fatal("SUPABASE_URL, SUPABASE_SERVICE_KEY, and SUPABASE_ANON_KEY are required")
    }

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
        log.Fatal("SUPABASE_URL must be https://vridcilbrgyrxxmnjcqq.supabase.co")
    }
    log.Printf("Cleaned SUPABASE_URL: %s", supabaseURL)

    postgrestURL := supabaseURL + "/rest/v1"
    postgrestClient = postgrest.NewClient(postgrestURL, "", map[string]string{
        "Authorization": "Bearer " + supabaseServiceKey,
        "apikey":        supabaseServiceKey,
    })
    if postgrestClient == nil {
        log.Fatal("Failed to initialize PostgREST client")
    }

    storageURL := supabaseURL + "/storage/v1"
    storageClient = storage_go.NewClient(storageURL, supabaseServiceKey, nil)

    authClient = gotrue.New(supabaseURL, supabaseAnonKey)
    if authClient == nil {
        log.Fatal("Failed to initialize Supabase auth client")
    }

    ctx := context.Background()
    credentialsPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
    if credentialsPath == "" {
        log.Println("GOOGLE_APPLICATION_CREDENTIALS not set, push notifications disabled")
        fcmEnabled = false
    } else {
        log.Printf("Using Firebase credentials: %s", credentialsPath)
        app, err := firebase.NewApp(ctx, nil)
        if err != nil {
            log.Printf("Error initializing Firebase: %v", err)
            fcmEnabled = false
        } else {
            fcmClient, err = app.Messaging(ctx)
            if err != nil {
                log.Printf("Error initializing FCM: %v", err)
                fcmEnabled = false
            } else {
                fcmEnabled = true
                log.Println("Firebase Cloud Messaging initialized")
            }
        }
    }

    router := mux.NewRouter()
    router.HandleFunc("/signup", signupHandler).Methods("POST")
    router.HandleFunc("/login", loginHandler).Methods("POST")
    router.HandleFunc("/users", authMiddleware(usersHandler)).Methods("GET")
    router.HandleFunc("/messages", authMiddleware(messagesHandler)).Methods("GET")
    router.HandleFunc("/allowed-chats", authMiddleware(allowedChatsHandler)).Methods("GET")
    router.HandleFunc("/upload", authMiddleware(uploadHandler)).Methods("POST")
    router.HandleFunc("/file/{path:.*}", authMiddleware(fileHandler)).Methods("GET")
    router.HandleFunc("/register-push", authMiddleware(registerPushHandler)).Methods("POST")
    router.HandleFunc("/ws", wsHandler).Methods("GET")
    router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "Chat App Backend")
    })

    corsHandler := handlers.CORS(
        handlers.AllowedOrigins([]string{"*"}),
        handlers.AllowedMethods([]string{"GET", "POST", "OPTIONS"}),
        handlers.AllowedHeaders([]string{"Content-Type", "Authorization"}),
        handlers.AllowCredentials(),
        handlers.OptionStatusCode(http.StatusNoContent),
    )

    loggedRouter := corsHandler(router)
    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }
    log.Printf("Server running on port %s", port)
    log.Fatal(http.ListenAndServe(":"+port, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        log.Printf("Request: %s %s from %s", r.Method, r.URL.Path, r.Header.Get("Origin"))
        loggedRouter.ServeHTTP(w, r)
    })))
}
