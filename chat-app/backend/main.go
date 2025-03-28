package main

  import (
      "bytes"
      "encoding/json"
      "fmt"
      "io"
      "log"
      "net/http"
      "os"
      "strings"
      "time"

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
  }

  type Client struct {
      username string
      chatID   int
      conn     *websocket.Conn
      send     chan Message
  }

  type Hub struct {
      clients    map[*Client]bool
      broadcast  chan Message
      register   chan *Client
      unregister chan *Client
  }

  var hub = &Hub{
      clients:    make(map[*Client]bool),
      broadcast:  make(chan Message),
      register:   make(chan *Client),
      unregister: make(chan *Client),
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
      supabaseClient = &http.Client{}
  )

  func (h *Hub) run() {
      for {
          select {
          case client := <-h.register:
              h.clients[client] = true
          case client := <-h.unregister:
              if _, ok := h.clients[client]; ok {
                  close(client.send)
                  delete(h.clients, client)
              }
          case message := <-h.broadcast:
              // Save the message to Supabase
              messageData, _ := json.Marshal(message)
              req, _ := http.NewRequest("POST", supabaseURL+"/rest/v1/messages", bytes.NewBuffer(messageData))
              req.Header.Set("Content-Type", "application/json")
              req.Header.Set("apikey", supabaseKey)
              req.Header.Set("Authorization", "Bearer "+supabaseKey)
              _, err := supabaseClient.Do(req)
              if err != nil {
                  log.Printf("Error saving message: %v", err)
              }

              // Broadcast the message to clients in the same chat
              for client := range h.clients {
                  if client.chatID == message.ChatID {
                      select {
                      case client.send <- message:
                      default:
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

      for {
          _, message, err := c.conn.ReadMessage()
          if err != nil {
              if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
                  log.Printf("Error: %v", err)
              }
              break
          }

          var msg Message
          if err := json.Unmarshal(message, &msg); err != nil {
              log.Printf("Error unmarshaling message: %v", err)
              continue
          }

          msg.ChatID = c.chatID
          msg.Sender = c.username
          msg.Timestamp = time.Now()
          hub.broadcast <- msg
      }
  }

  func (c *Client) writePump() {
      defer func() {
          c.conn.Close()
      }()

      for message := range c.send {
          w, err := c.conn.NextWriter(websocket.TextMessage)
          if err != nil {
              return
          }

          json.NewEncoder(w).Encode(message)
          if err := w.Close(); err != nil {
              return
          }
      }
  }

  func handleWebSocket(w http.ResponseWriter, r *http.Request) {
      tokenString := r.URL.Query().Get("token")
      if tokenString == "" {
          http.Error(w, "Missing token", http.StatusUnauthorized)
          return
      }

      token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
          if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
              return nil, fmt.Errorf("unexpected signing method: %v", token.Method)
          }
          return jwtSecret, nil
      })
      if err != nil || !token.Valid {
          http.Error(w, "Invalid token", http.StatusUnauthorized)
          return
      }

      claims, ok := token.Claims.(jwt.MapClaims)
      if !ok || !token.Valid {
          http.Error(w, "Invalid token claims", http.StatusUnauthorized)
          return
      }

      username, ok := claims["username"].(string)
      if !ok {
          http.Error(w, "Invalid username in token", http.StatusUnauthorized)
          return
      }

      chatIDStr := r.URL.Query().Get("chat_id")
      if chatIDStr == "" {
          http.Error(w, "Missing chat_id", http.StatusBadRequest)
          return
      }

      var chatID int
      _, err = fmt.Sscanf(chatIDStr, "%d", &chatID)
      if err != nil {
          http.Error(w, "Invalid chat_id", http.StatusBadRequest)
          return
      }

      // Verify the user is a participant in the chat
      req, _ := http.NewRequest("GET", supabaseURL+"/rest/v1/chats?id=eq."+chatIDStr, nil)
      req.Header.Set("apikey", supabaseKey)
      req.Header.Set("Authorization", "Bearer "+supabaseKey)
      resp, err := supabaseClient.Do(req)
      if err != nil {
          http.Error(w, "Error verifying chat", http.StatusInternalServerError)
          return
      }
      defer resp.Body.Close()

      var chats []struct {
          Participant1 string `json:"participant1"`
          Participant2 string `json:"participant2"`
      }
      json.NewDecoder(resp.Body).Decode(&chats)
      if len(chats) == 0 || (chats[0].Participant1 != username && chats[0].Participant2 != username) {
          http.Error(w, "User not authorized for this chat", http.StatusForbidden)
          return
      }

      conn, err := upgrader.Upgrade(w, r, nil)
      if err != nil {
          log.Println(err)
          return
      }

      client := &Client{username: username, chatID: chatID, conn: conn, send: make(chan Message)}
      hub.register <- client

      go client.writePump()
      go client.readPump()

      // Fetch initial messages
      req, _ = http.NewRequest("GET", supabaseURL+"/rest/v1/messages?chat_id=eq."+chatIDStr+"&order=timestamp.asc", nil)
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
      for _, msg := range messages {
          client.send <- msg
      }
  }

  func handleLogin(w http.ResponseWriter, r *http.Request) {
      if r.Method != http.MethodPost {
          http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
          return
      }

      var loginData struct {
          Username string `json:"username"`
          Password string `json:"password"`
      }
      if err := json.NewDecoder(r.Body).Decode(&loginData); err != nil {
          http.Error(w, "Invalid request body", http.StatusBadRequest)
          return
      }

      // Fetch user from Supabase
      req, _ := http.NewRequest("GET", supabaseURL+"/rest/v1/users?username=eq."+loginData.Username, nil)
      req.Header.Set("apikey", supabaseKey)
      req.Header.Set("Authorization", "Bearer "+supabaseKey)
      resp, err := supabaseClient.Do(req)
      if err != nil {
          http.Error(w, "Error fetching user", http.StatusInternalServerError)
          return
      }
      defer resp.Body.Close()

      var users []struct {
          Password string `json:"password"`
      }
      json.NewDecoder(resp.Body).Decode(&users)
      if len(users) == 0 {
          http.Error(w, `{"message": "Invalid username or password"}`, http.StatusUnauthorized)
          return
      }

      // Verify password
      if err := bcrypt.CompareHashAndPassword([]byte(users[0].Password), []byte(loginData.Password)); err != nil {
          http.Error(w, `{"message": "Invalid username or password"}`, http.StatusUnauthorized)
          return
      }

      // Generate JWT token
      token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
          "username": loginData.Username,
          "exp":      time.Now().Add(time.Hour * 1).Unix(),
      })
      tokenString, err := token.SignedString(jwtSecret)
      if err != nil {
          http.Error(w, "Error generating token", http.StatusInternalServerError)
          return
      }

      // Find the chat for this user
      req, _ = http.NewRequest("GET", supabaseURL+"/rest/v1/chats?or=(participant1.eq."+loginData.Username+",participant2.eq."+loginData.Username+")", nil)
      req.Header.Set("apikey", supabaseKey)
      req.Header.Set("Authorization", "Bearer "+supabaseKey)
      resp, err = supabaseClient.Do(req)
      if err != nil {
          http.Error(w, "Error fetching chats", http.StatusInternalServerError)
          return
      }
      defer resp.Body.Close()

      var chats []struct {
          ID int `json:"id"`
      }
      json.NewDecoder(resp.Body).Decode(&chats)
      if len(chats) == 0 {
          http.Error(w, "No chats found for this user", http.StatusNotFound)
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
          http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
          return
      }

      tokenString := r.URL.Query().Get("token")
      if tokenString == "" {
          http.Error(w, "Missing token", http.StatusUnauthorized)
          return
      }

      token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
          if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
              return nil, fmt.Errorf("unexpected signing method: %v", token.Method)
          }
          return jwtSecret, nil
      })
      if err != nil || !token.Valid {
          http.Error(w, "Invalid token", http.StatusUnauthorized)
          return
      }

      claims, ok := token.Claims.(jwt.MapClaims)
      if !ok || !token.Valid {
          http.Error(w, "Invalid token claims", http.StatusUnauthorized)
          return
      }

      username, ok := claims["username"].(string)
      if !ok {
          http.Error(w, "Invalid username in token", http.StatusUnauthorized)
          return
      }

      chatIDStr := r.URL.Query().Get("chat_id")
      if chatIDStr == "" {
          http.Error(w, "Missing chat_id", http.StatusBadRequest)
          return
      }

      var chatID int
      _, err = fmt.Sscanf(chatIDStr, "%d", &chatID)
      if err != nil {
          http.Error(w, "Invalid chat_id", http.StatusBadRequest)
          return
      }

      // Verify the user is a participant in the chat
      req, _ := http.NewRequest("GET", supabaseURL+"/rest/v1/chats?id=eq."+chatIDStr, nil)
      req.Header.Set("apikey", supabaseKey)
      req.Header.Set("Authorization", "Bearer "+supabaseKey)
      resp, err := supabaseClient.Do(req)
      if err != nil {
          http.Error(w, "Error verifying chat", http.StatusInternalServerError)
          return
      }
      defer resp.Body.Close()

      var chats []struct {
          Participant1 string `json:"participant1"`
          Participant2 string `json:"participant2"`
      }
      json.NewDecoder(resp.Body).Decode(&chats)
      if len(chats) == 0 || (chats[0].Participant1 != username && chats[0].Participant2 != username) {
          http.Error(w, "User not authorized for this chat", http.StatusForbidden)
          return
      }

      // Get the receiver
      receiver := chats[0].Participant1
      if username == receiver {
          receiver = chats[0].Participant2
      }

      // Parse the file
      err = r.ParseMultipartForm(10 << 20) // 10 MB limit
      if err != nil {
          http.Error(w, "Error parsing file", http.StatusBadRequest)
          return
      }

      file, handler, err := r.FormFile("file")
      if err != nil {
          http.Error(w, "Error retrieving file", http.StatusBadRequest)
          return
      }
      defer file.Close()

      // Upload the file to Supabase Storage
      fileName := fmt.Sprintf("%d-%s", time.Now().UnixNano(), handler.Filename)
      fileData, err := io.ReadAll(file)
      if err != nil {
          http.Error(w, "Error reading file", http.StatusInternalServerError)
          return
      }

      req, _ = http.NewRequest("POST", supabaseURL+"/storage/v1/object/chat-files/"+fileName, bytes.NewReader(fileData))
      req.Header.Set("Authorization", "Bearer "+supabaseKey)
      req.Header.Set("Content-Type", handler.Header.Get("Content-Type"))
      resp, err = supabaseClient.Do(req)
      if err != nil {
          http.Error(w, "Error uploading file", http.StatusInternalServerError)
          return
      }
      defer resp.Body.Close()

      if resp.StatusCode != http.StatusOK {
          http.Error(w, "Error uploading file to storage", http.StatusInternalServerError)
          return
      }

      // Generate the public URL
      fileURL := supabaseURL + "/storage/v1/object/public/chat-files/" + fileName

      // Save the message with the file URL
      message := Message{
          ChatID:    chatID,
          Sender:    username,
          Receiver:  receiver,
          Content:   "",
          FileURL:   fileURL,
          Timestamp: time.Now(),
      }
      hub.broadcast <- message

      w.WriteHeader(http.StatusOK)
      json.NewEncoder(w).Encode(map[string]string{"message": "File uploaded successfully"})
  }

  func main() {
      go hub.run()

      // Initialize test users if they don't exist
      for _, user := range []struct{ username, password string }{
          {"user1", "password123"},
          {"user2", "password123"},
      } {
          hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(user.password), bcrypt.DefaultCost)
          userData, _ := json.Marshal(map[string]interface{}{
              "username": user.username,
              "password": string(hashedPassword),
          })
          req, _ := http.NewRequest("POST", supabaseURL+"/rest/v1/users", bytes.NewBuffer(userData))
          req.Header.Set("Content-Type", "application/json")
          req.Header.Set("apikey", supabaseKey)
          req.Header.Set("Authorization", "Bearer "+supabaseKey)
          supabaseClient.Do(req)
      }

      http.HandleFunc("/ws", handleWebSocket)
      http.HandleFunc("/login", handleLogin)
      http.HandleFunc("/upload", handleFileUpload)

      port := os.Getenv("PORT")
      if port == "" {
          port = "8080"
      }
      fmt.Printf("Server starting on :%s\n", port)
      if err := http.ListenAndServe(":"+port, nil); err != nil {
          log.Fatal("ListenAndServe: ", err)
      }
  }