package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "time"
    "strings"

    "github.com/dgrijalva/jwt-go"
    "github.com/gorilla/websocket"
    "golang.org/x/crypto/bcrypt"
)

type Message struct {
    ID        int       `json:"id"`
    ChatID    int       `json:"chat_id"`
    Sender    string    `json:"sender"`
    Receiver  string    `json:"receiver"`
    Content   string    `json:"content"`
    FileURL   string    `json:"file_url"`
    Timestamp time.Time `json:"timestamp"`
    Type      string    `json:"type,omitempty"`
    LocalID   string    `json:"local_id,omitempty"`
}

type Client struct {
    username      string
    chatID        int
    conn          *websocket.Conn
    send          chan Message
    lastMessageID int
}

type Hub struct {
    clients        map[*Client]bool
    broadcast      chan Message
    register       chan *Client
    unregister     chan *Client
    connectedUsers map[string][]int
}

var hub = &Hub{
    clients:        make(map[*Client]bool),
    broadcast:      make(chan Message),
    register:       make(chan *Client),
    unregister:     make(chan *Client),
    connectedUsers: make(map[string][]int),
}

var upgrader = websocket.Upgrader{
    ReadBufferSize:  1024,
    WriteBufferSize: 1024,
    CheckOrigin: func(r *http.Request) bool {
        return true
    },
}

var (
    supabaseURL    = os.Getenv("SUPABASE_URL")
    supabaseKey    = os.Getenv("SUPABASE_KEY")
    jwtSecret      = []byte(os.Getenv("JWT_SECRET"))
    supabaseClient = &http.Client{
        Timeout: 10 * time.Second,
    }
)

func corsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Origin", "https://chat-frontend-7v8w.onrender.com")
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
        w.Header().Set("Access-Control-Allow-Credentials", "true")

        if r.Method == http.MethodOptions {
            w.WriteHeader(http.StatusOK)
            return
        }

        next.ServeHTTP(w, r)
    })
}

func (h *Hub) run() {
    for {
        select {
        case client := <-h.register:
            h.clients[client] = true
            h.connectedUsers[client.username] = append(h.connectedUsers[client.username], client.chatID)
            for c := range h.clients {
                if c.chatID == client.chatID && c.username != client.username {
                    statusMessage := Message{
                        ChatID:    client.chatID,
                        Sender:    client.username,
                        Type:      "status",
                        Content:   "online",
                        Timestamp: time.Now(),
                    }
                    c.send <- statusMessage
                }
            }
        case client := <-h.unregister:
            if _, ok := h.clients[client]; ok {
                chatIDs := h.connectedUsers[client.username]
                updatedChatIDs := []int{}
                for _, id := range chatIDs {
                    if id != client.chatID {
                        updatedChatIDs = append(updatedChatIDs, id)
                    }
                }
                if len(updatedChatIDs) > 0 {
                    h.connectedUsers[client.username] = updatedChatIDs
                } else {
                    delete(h.connectedUsers, client.username)
                }
                for c := range h.clients {
                    if c.chatID == client.chatID && c.username != client.username {
                        statusMessage := Message{
                            ChatID:    client.chatID,
                            Sender:    client.username,
                            Type:      "status",
                            Content:   "offline",
                            Timestamp: time.Now(),
                        }
                        c.send <- statusMessage
                    }
                }
                close(client.send)
                delete(h.clients, client)
            }
        case message := <-h.broadcast:
            if message.Type != "status" && message.Content == "" && message.FileURL == "" {
                log.Printf("Skipping empty message: %+v", message)
                continue
            }

            if message.Type != "status" {
                messageData, err := json.Marshal(message)
                if err != nil {
                    log.Printf("Error marshaling message: %v", err)
                } else {
                    req, err := http.NewRequest("POST", supabaseURL+"/rest/v1/messages", bytes.NewBuffer(messageData))
                    if err != nil {
                        log.Printf("Error creating request to save message: %v", err)
                    } else {
                        req.Header.Set("Content-Type", "application/json")
                        req.Header.Set("apikey", supabaseKey)
                        req.Header.Set("Authorization", "Bearer "+supabaseKey)
                        resp, err := supabaseClient.Do(req)
                        if err != nil {
                            log.Printf("Error saving message to Supabase: %v", err)
                        } else {
                            defer resp.Body.Close()
                            if resp.StatusCode != http.StatusCreated {
                                body, _ := io.ReadAll(resp.Body)
                                log.Printf("Supabase save message failed: Status=%d, Response=%s", resp.StatusCode, string(body))
                            } else {
                                log.Printf("Successfully saved message to Supabase: %+v", message)
                            }
                        }
                    }
                }
            }

            log.Printf("Broadcasting message: %+v", message)
            for client := range h.clients {
                if client.chatID == message.ChatID {
                    select {
                    case client.send <- message:
                        client.lastMessageID = message.ID
                    default:
                        log.Printf("Failed to send message to client %s in chat %d, closing connection", client.username, client.chatID)
                        close(client.send)
                        delete(h.clients, client)
                    }
                }
            }
        }
    }
}

func (c *Client) readPump() {
    defer func() {
        hub.unregister <- c
        c.conn.Close()
    }()

    c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))

    c.conn.SetPongHandler(func(string) error {
        c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
        return nil
    })

    for {
        _, message, err := c.conn.ReadMessage()
        if err != nil {
            if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
                log.Printf("readPump error: %v", err)
            }
            break
        }

        var msg Message
        if err := json.Unmarshal(message, &msg); err != nil {
            log.Printf("Error unmarshaling message: %v", err)
            continue
        }

        if msg.Type == "ping" {
            continue
        }

        msg.ChatID = c.chatID
        msg.Sender = c.username
        msg.Timestamp = time.Now()
        hub.broadcast <- msg

        c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
    }
}

func (c *Client) writePump() {
    ticker := time.NewTicker(15 * time.Second)
    defer func() {
        ticker.Stop()
        c.conn.Close()
    }()

    for {
        select {
        case message, ok := <-c.send:
            if !ok {
                c.conn.WriteMessage(websocket.CloseMessage, []byte{})
                return
            }

            w, err := c.conn.NextWriter(websocket.TextMessage)
            if err != nil {
                log.Printf("writePump error (NextWriter): %v", err)
                return
            }

            json.NewEncoder(w).Encode(message)
            if err := w.Close(); err != nil {
                log.Printf("writePump error (Close): %v", err)
                return
            }

        case <-ticker.C:
            if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
                log.Printf("writePump error (Ping): %v", err)
                return
            }
        }
    }
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
    tokenString := r.URL.Query().Get("token")
    if tokenString == "" {
        http.Error(w, `{"error": "Missing token"}`, http.StatusUnauthorized)
        return
    }

    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Method)
        }
        return jwtSecret, nil
    })
    if err != nil || !token.Valid {
        http.Error(w, `{"error": "Invalid token"}`, http.StatusUnauthorized)
        return
    }

    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok || !token.Valid {
        http.Error(w, `{"error": "Invalid token claims"}`, http.StatusUnauthorized)
        return
    }

    username, ok := claims["username"].(string)
    if !ok {
        http.Error(w, `{"error": "Invalid username in token"}`, http.StatusUnauthorized)
        return
    }

    chatIDStr := r.URL.Query().Get("chat_id")
    if chatIDStr == "" {
        http.Error(w, `{"error": "Missing chat_id"}`, http.StatusBadRequest)
        return
    }

    var chatID int
    _, err = fmt.Sscanf(chatIDStr, "%d", &chatID)
    if err != nil {
        http.Error(w, `{"error": "Invalid chat_id"}`, http.StatusBadRequest)
        return
    }

    req, err := http.NewRequest("GET", supabaseURL+"/rest/v1/chats?id=eq."+chatIDStr, nil)
    if err != nil {
        log.Printf("Error creating request to verify chat: %v", err)
        http.Error(w, `{"error": "Error verifying chat: failed to create request"}`, http.StatusInternalServerError)
        return
    }
    req.Header.Set("apikey", supabaseKey)
    req.Header.Set("Authorization", "Bearer "+supabaseKey)
    resp, err := supabaseClient.Do(req)
    if err != nil {
        log.Printf("Error verifying chat: %v", err)
        http.Error(w, `{"error": "Error verifying chat: `+err.Error()+`"}`, http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    var chats []struct {
        Participant1 string `json:"participant1"`
        Participant2 string `json:"participant2"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&chats); err != nil {
        log.Printf("Error decoding chat response: %v", err)
        http.Error(w, `{"error": "Error verifying chat: failed to decode response"}`, http.StatusInternalServerError)
        return
    }
    if len(chats) == 0 || (chats[0].Participant1 != username && chats[0].Participant2 != username) {
        http.Error(w, `{"error": "User not authorized for this chat"}`, http.StatusForbidden)
        return
    }

    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Println("Upgrade error:", err)
        return
    }

    client := &Client{username: username, chatID: chatID, conn: conn, send: make(chan Message), lastMessageID: 0}
    hub.register <- client

    go client.writePump()
    go client.readPump()

    req, err = http.NewRequest("GET", supabaseURL+"/rest/v1/messages?chat_id=eq."+chatIDStr+"&order=timestamp.asc", nil)
    if err != nil {
        log.Printf("Error creating request to fetch messages: %v", err)
        return
    }
    req.Header.Set("apikey", supabaseKey)
    req.Header.Set("Authorization", "Bearer "+supabaseKey)
    resp, err = supabaseClient.Do(req)
    if err != nil {
        log.Printf("Error fetching messages: %v", err)
        return
    }
    defer resp.Body.Close()

    var messages []Message
    json.NewDecoder(resp.Body).Decode(&messages)
    if len(messages) > 0 {
        client.lastMessageID = messages[len(messages)-1].ID
    }

    partner := chats[0].Participant1
    if partner == username {
        partner = chats[0].Participant2
    }
    status := "offline"
    if chatIDs, exists := hub.connectedUsers[partner]; exists {
        for _, id := range chatIDs {
            if id == chatID {
                status = "online"
                break
            }
        }
    }
    statusMessage := Message{
        ChatID:    chatID,
        Sender:    partner,
        Type:      "status",
        Content:   status,
        Timestamp: time.Now(),
    }
    client.send <- statusMessage
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
        return
    }

    var loginData struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }
    if err := json.NewDecoder(r.Body).Decode(&loginData); err != nil {
        http.Error(w, `{"error": "Invalid request body"}`, http.StatusBadRequest)
        return
    }

    req, err := http.NewRequest("GET", supabaseURL+"/rest/v1/users?username=eq."+loginData.Username, nil)
    if err != nil {
        log.Printf("Error creating request to fetch user: %v", err)
        http.Error(w, `{"error": "Error fetching user: failed to create request"}`, http.StatusInternalServerError)
        return
    }
    req.Header.Set("apikey", supabaseKey)
    req.Header.Set("Authorization", "Bearer "+supabaseKey)
    resp, err := supabaseClient.Do(req)
    if err != nil {
        log.Printf("Error fetching user: %v", err)
        http.Error(w, `{"error": "Error fetching user: `+err.Error()+`"}`, http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    var users []struct {
        Password string `json:"password"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
        log.Printf("Error decoding user response: %v", err)
        http.Error(w, `{"error": "Error fetching user: failed to decode response"}`, http.StatusInternalServerError)
        return
    }
    if len(users) == 0 {
        http.Error(w, `{"message": "Invalid username or password"}`, http.StatusUnauthorized)
        return
    }

    if err := bcrypt.CompareHashAndPassword([]byte(users[0].Password), []byte(loginData.Password)); err != nil {
        http.Error(w, `{"message": "Invalid username or password"}`, http.StatusUnauthorized)
        return
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "username": loginData.Username,
        "exp":      time.Now().Add(time.Hour * 1).Unix(),
    })
    tokenString, err := token.SignedString(jwtSecret)
    if err != nil {
        http.Error(w, `{"error": "Error generating token"}`, http.StatusInternalServerError)
        return
    }

    req, err = http.NewRequest("GET", supabaseURL+"/rest/v1/chats?or=(participant1.eq."+loginData.Username+",participant2.eq."+loginData.Username+")", nil)
    if err != nil {
        log.Printf("Error creating request to fetch chats: %v", err)
        http.Error(w, `{"error": "Error fetching chats: failed to create request"}`, http.StatusInternalServerError)
        return
    }
    req.Header.Set("apikey", supabaseKey)
    req.Header.Set("Authorization", "Bearer "+supabaseKey)
    resp, err = supabaseClient.Do(req)
    if err != nil {
        log.Printf("Error fetching chats: %v", err)
        http.Error(w, `{"error": "Error fetching chats: `+err.Error()+`"}`, http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    var chats []struct {
        ID int `json:"id"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&chats); err != nil {
        log.Printf("Error decoding chats response: %v", err)
        http.Error(w, `{"error": "Error fetching chats: failed to decode response"}`, http.StatusInternalServerError)
        return
    }
    if len(chats) == 0 {
        http.Error(w, `{"error": "No chats found for this user"}`, http.StatusNotFound)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "token":   tokenString,
        "chat_id": chats[0].ID,
    })
}

func handleFileUpload(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
        return
    }

    tokenString := r.URL.Query().Get("token")
    if tokenString == "" {
        http.Error(w, `{"error": "Missing token"}`, http.StatusUnauthorized)
        return
    }

    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Method)
        }
        return jwtSecret, nil
    })
    if err != nil || !token.Valid {
        http.Error(w, `{"error": "Invalid token"}`, http.StatusUnauthorized)
        return
    }

    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok || !token.Valid {
        http.Error(w, `{"error": "Invalid token claims"}`, http.StatusUnauthorized)
        return
    }

    username, ok := claims["username"].(string)
    if !ok {
        http.Error(w, `{"error": "Invalid username in token"}`, http.StatusUnauthorized)
        return
    }

    chatIDStr := r.URL.Query().Get("chat_id")
    if chatIDStr == "" {
        http.Error(w, `{"error": "Missing chat_id"}`, http.StatusBadRequest)
        return
    }

    var chatID int
    _, err = fmt.Sscanf(chatIDStr, "%d", &chatID)
    if err != nil {
        http.Error(w, `{"error": "Invalid chat_id"}`, http.StatusBadRequest)
        return
    }

    req, err := http.NewRequest("GET", supabaseURL+"/rest/v1/chats?id=eq."+chatIDStr, nil)
    if err != nil {
        log.Printf("Error creating request to verify chat: %v", err)
        http.Error(w, `{"error": "Error verifying chat: failed to create request"}`, http.StatusInternalServerError)
        return
    }
    req.Header.Set("apikey", supabaseKey)
    req.Header.Set("Authorization", "Bearer "+supabaseKey)
    resp, err := supabaseClient.Do(req)
    if err != nil {
        log.Printf("Error verifying chat: %v", err)
        http.Error(w, `{"error": "Error verifying chat: `+err.Error()+`"}`, http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    var chats []struct {
        Participant1 string `json:"participant1"`
        Participant2 string `json:"participant2"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&chats); err != nil {
        log.Printf("Error decoding chat response: %v", err)
        http.Error(w, `{"error": "Error verifying chat: failed to decode response"}`, http.StatusInternalServerError)
        return
    }
    if len(chats) == 0 || (chats[0].Participant1 != username && chats[0].Participant2 != username) {
        http.Error(w, `{"error": "User not authorized for this chat"}`, http.StatusForbidden)
        return
    }

    receiver := chats[0].Participant1
    if username == receiver {
        receiver = chats[0].Participant2
    }

    err = r.ParseMultipartForm(10 << 20)
    if err != nil {
        log.Printf("Error parsing multipart form: %v", err)
        http.Error(w, `{"error": "Error parsing file: `+err.Error()+`"}`, http.StatusBadRequest)
        return
    }

    file, handler, err := r.FormFile("file")
    if err != nil {
        log.Printf("Error retrieving file from form: %v", err)
        http.Error(w, `{"error": "Error retrieving file: `+err.Error()+`"}`, http.StatusBadRequest)
        return
    }
    defer file.Close()

    fileName := fmt.Sprintf("%d-%s", time.Now().UnixNano(), handler.Filename)
    fileName = strings.ReplaceAll(fileName, " ", "_")
    fileName = strings.ReplaceAll(fileName, "/", "_")
    fileName = strings.ReplaceAll(fileName, "\\", "_")
    fileName = strings.ReplaceAll(fileName, ":", "_")
    fileName = strings.ReplaceAll(fileName, "*", "_")
    fileName = strings.ReplaceAll(fileName, "?", "_")
    fileName = strings.ReplaceAll(fileName, "\"", "_")
    fileName = strings.ReplaceAll(fileName, "<", "_")
    fileName = strings.ReplaceAll(fileName, ">", "_")
    fileName = strings.ReplaceAll(fileName, "|", "_")

    fileData, err := io.ReadAll(file)
    if err != nil {
        log.Printf("Error reading file data: %v", err)
        http.Error(w, `{"error": "Error reading file: `+err.Error()+`"}`, http.StatusInternalServerError)
        return
    }

    if supabaseURL == "" || supabaseKey == "" {
        log.Printf("Supabase URL or Key is missing: URL=%s, Key=%s", supabaseURL, supabaseKey)
        http.Error(w, `{"error": "Server configuration error: missing Supabase URL or Key"}`, http.StatusInternalServerError)
        return
    }

    req, err = http.NewRequest("POST", supabaseURL+"/storage/v1/object/chat-files/"+fileName, bytes.NewReader(fileData))
    if err != nil {
        log.Printf("Error creating Supabase upload request: %v", err)
        http.Error(w, `{"error": "Error uploading file: failed to create request: `+err.Error()+`"}`, http.StatusInternalServerError)
        return
    }
    req.Header.Set("Authorization", "Bearer "+supabaseKey)
    req.Header.Set("Content-Type", handler.Header.Get("Content-Type"))
    resp, err = supabaseClient.Do(req)
    if err != nil {
        log.Printf("Error uploading file to Supabase: %v", err)
        http.Error(w, `{"error": "Error uploading file to storage: `+err.Error()+`"}`, http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        log.Printf("Supabase upload failed: Status=%d, Response=%s", resp.StatusCode, string(body))
        http.Error(w, `{"error": "Error uploading file to storage: Supabase returned status `+fmt.Sprint(resp.StatusCode)+`"}`, http.StatusInternalServerError)
        return
    }

    fileURL := supabaseURL + "/storage/v1/object/public/chat-files/" + fileName

    message := Message{
        ChatID:    chatID,
        Sender:    username,
        Receiver:  receiver,
        Content:   "Sent a file",
        FileURL:   fileURL,
        Timestamp: time.Now(),
    }
    hub.broadcast <- message

    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"message": "File uploaded successfully", "file_url: fileURL})
}

func handleGetChat(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
        return
    }

    tokenString := r.URL.Query().Get("token")
    if tokenString == "" {
        log.Println("Missing token in /chats request")
        http.Error(w, `{"error": "Missing token"}`, http.StatusUnauthorized)
        return
    }

    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Method)
        }
        return jwtSecret, nil
    })
    if err != nil || !token.Valid {
        log.Printf("Invalid token in /chats request: %v", err)
        http.Error(w, `{"error": "Invalid token"}`, http.StatusUnauthorized)
        return
    }

    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok || !token.Valid {
        log.Println("Invalid token claims in /chats request")
        http.Error(w, `{"error": "Invalid token claims"}`, http.StatusUnauthorized)
        return
    }

    username, ok := claims["username"].(string)
    if !ok {
        log.Println("Invalid username in token in /chats request")
        http.Error(w, `{"error": "Invalid username in token"}`, http.StatusUnauthorized)
        return
    }

    chatIDStr := r.URL.Query().Get("chat_id")
    if chatIDStr == "" {
        http.Error(w, `{"error": "Missing chat_id"}`, http.StatusBadRequest)
        return
    }

    req, err := http.NewRequest("GET", supabaseURL+"/rest/v1/chats?id=eq."+chatIDStr, nil)
    if err != nil {
        log.Printf("Error creating request to fetch chat: %v", err)
        http.Error(w, `{"error": "Error fetching chat: failed to create request"}`, http.StatusInternalServerError)
        return
    }
    req.Header.Set("apikey", supabaseKey)
    req.Header.Set("Authorization", "Bearer "+supabaseKey)
    resp, err := supabaseClient.Do(req)
    if err != nil {
        log.Printf("Error fetching chat from Supabase: %v", err)
        http.Error(w, `{"error": "Error fetching chat: `+err.Error()+`"}`, http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    var chats []struct {
        ID           int    `json:"id"`
        Participant1 string `json:"participant1"`
        Participant2 string `json:"participant2"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&chats); err != nil {
        log.Printf("Error decoding chat response: %v", err)
        http.Error(w, `{"error": "Error fetching chat: failed to decode response"}`, http.StatusInternalServerError)
        return
    }
    if len(chats) == 0 {
        log.Printf("Chat not found for chat_id: %s", chatIDStr)
        http.Error(w, `{"error": "Chat not found"}`, http.StatusNotFound)
        return
    }

    if chats[0].Participant1 != username && chats[0].Participant2 != username {
        log.Printf("User %s not authorized for chat %s", username, chatIDStr)
        http.Error(w, `{"error": "User not authorized for this chat"}`, http.StatusForbidden)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(chats[0])
}

func handleGetMessages(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
        return
    }

    tokenString := r.URL.Query().Get("token")
    if tokenString == "" {
        log.Println("Missing token in /messages request")
        http.Error(w, `{"error": "Missing token"}`, http.StatusUnauthorized)
        return
    }

    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Method)
        }
        return jwtSecret, nil
    })
    if err != nil || !token.Valid {
        log.Printf("Invalid token in /messages request: %v", err)
        http.Error(w, `{"error": "Invalid token"}`, http.StatusUnauthorized)
        return
    }

    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok || !token.Valid {
        log.Println("Invalid token claims in /messages request")
        http.Error(w, `{"error": "Invalid token claims"}`, http.StatusUnauthorized)
        return
    }

    username, ok := claims["username"].(string)
    if !ok {
        log.Println("Invalid username in token in /messages request")
        http.Error(w, `{"error": "Invalid username in token"}`, http.StatusUnauthorized)
        return
    }

    chatIDStr := r.URL.Query().Get("chat_id")
    if chatIDStr == "" {
        http.Error(w, `{"error": "Missing chat_id"}`, http.StatusBadRequest)
        return
    }

    req, err := http.NewRequest("GET", supabaseURL+"/rest/v1/chats?id=eq."+chatIDStr, nil)
    if err != nil {
        log.Printf("Error creating request to fetch chat: %v", err)
        http.Error(w, `{"error": "Error fetching chat: failed to create request"}`, http.StatusInternalServerError)
        return
    }
    req.Header.Set("apikey", supabaseKey)
    req.Header.Set("Authorization", "Bearer "+supabaseKey)
    resp, err := supabaseClient.Do(req)
    if err != nil {
        log.Printf("Error fetching chat from Supabase: %v", err)
        http.Error(w, `{"error": "Error fetching chat: `+err.Error()+`"}`, http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    var chats []struct {
        ID           int    `json:"id"`
        Participant1 string `json:"participant1"`
        Participant2 string `json:"participant2"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&chats); err != nil {
        log.Printf("Error decoding chat response: %v", err)
        http.Error(w, `{"error": "Error fetching chat: failed to decode response"}`, http.StatusInternalServerError)
        return
    }
    if len(chats) == 0 {
        log.Printf("Chat not found for chat_id: %s", chatIDStr)
        http.Error(w, `{"error": "Chat not found"}`, http.StatusNotFound)
        return
    }

    if chats[0].Participant1 != username && chats[0].Participant2 != username {
        log.Printf("User %s not authorized for chat %s", username, chatIDStr)
        http.Error(w, `{"error": "User not authorized for this chat"}`, http.StatusForbidden)
        return
    }

    req, err = http.NewRequest("GET", supabaseURL+"/rest/v1/messages?chat_id=eq."+chatIDStr+"&order=timestamp.asc", nil)
    if err != nil {
        log.Printf("Error creating request to fetch messages: %v", err)
        http.Error(w, `{"error": "Error fetching messages: failed to create request"}`, http.StatusInternalServerError)
        return
    }
    req.Header.Set("apikey", supabaseKey)
    req.Header.Set("Authorization", "Bearer "+supabaseKey)
    resp, err = supabaseClient.Do(req)
    if err != nil {
        log.Printf("Error fetching messages: %v", err)
        http.Error(w, `{"error": "Error fetching messages: `+err.Error()+`"}`, http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        log.Printf("Supabase fetch messages failed: Status=%d, Response=%s", resp.StatusCode, string(body))
        http.Error(w, `{"error": "Error fetching messages: Supabase returned status `+fmt.Sprint(resp.StatusCode)+`"}`, http.StatusInternalServerError)
        return
    }

    var messages []Message
    if err := json.NewDecoder(resp.Body).Decode(&messages); err != nil {
        log.Printf("Error decoding messages response: %v", err)
        http.Error(w, `{"error": "Error fetching messages: failed to decode response"}`, http.StatusInternalServerError)
        return
    }

    log.Printf("Fetched %d messages for chat_id %s", len(messages), chatIDStr)
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(messages)
}

func main() {
    go hub.run()

    for _, user := range []struct{ username, password string }{
        {"user1", "password123"},
        {"user2", "password123"},
    } {
        hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.password), bcrypt.DefaultCost)
        if err != nil {
            log.Printf("Error hashing password for user %s: %v", user.username, err)
            continue
        }
        userData, err := json.Marshal(map[string]interface{}{
            "username": user.username,
            "password": string(hashedPassword),
        })
        if err != nil {
            log.Printf("Error marshaling user data for user %s: %v", user.username, err)
            continue
        }
        req, err := http.NewRequest("POST", supabaseURL+"/rest/v1/users", bytes.NewBuffer(userData))
        if err != nil {
            log.Printf("Error creating request to add user %s: %v", user.username, err)
            continue
        }
        req.Header.Set("Content-Type", "application/json")
        req.Header.Set("Authorization", "Bearer "+supabaseKey)
        _, err = supabaseClient.Do(req)
        if err != nil {
            log.Printf("Error adding user %s to Supabase: %v", user.username, err)
        }
    }

    mux := http.NewServeMux()
    mux.HandleFunc("/ws", handleWebSocket)
    mux.HandleFunc("/login", handleLogin)
    mux.HandleFunc("/upload", handleFileUpload)
    mux.HandleFunc("/chats", handleGetChat)
    mux.HandleFunc("/messages", handleGetMessages)

    handler := corsMiddleware(mux)

    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }
    fmt.Printf("Server starting on :%s\n", port)
    if err := http.ListenAndServe(":"+port, handler); err != nil {
        log.Fatal("ListenAndServe: ", err)
    }
}
