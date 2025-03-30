<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chat Page</title>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Roboto', sans-serif;
            background-color: #f5f5f5;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .chat-container {
            width: 100%;
            max-width: 400px;
            background-color: #ffffff;
            border: 1px solid #ddd;
            border-radius: 10px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            display: flex;
            flex-direction: column;
            height: 80vh;
        }
        .chat-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 20px;
            border-bottom: 1px solid #ddd;
        }
        .chat-header h3 {
            margin: 0;
            font-size: 18px;
        }
        .chat-header p {
            margin: 0;
            font-size: 12px;
            color: #999;
        }
        .chat-header .icons span {
            margin-left: 10px;
            cursor: pointer;
        }
        .chat-window {
            flex: 1;
            padding: 20px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
        }
        .chat-bubble {
            margin: 10px 0;
            padding: 10px;
            border-radius: 15px;
            max-width: 70%;
            position: relative;
        }
        .outgoing {
            background-color: #000000;
            color: #ffffff;
            align-self: flex-end;
        }
        .incoming {
            background-color: #e0e0e0;
            color: #000000;
            align-self: flex-start;
        }
        .incoming::before {
            content: '';
            display: inline-block;
            width: 30px;
            height: 30px;
            background: url('https://via.placeholder.com/30') no-repeat center;
            background-size: cover;
            border-radius: 50%;
            position: absolute;
            left: -40px;
            top: 50%;
            transform: translateY(-50%);
        }
        .timestamp {
            font-size: 12px;
            color: #999;
            text-align: center;
            margin: 5px 0;
        }
        .status {
            font-size: 10px;
            color: #666;
            margin-top: 5px;
            text-align: right;
        }
        .chat-input {
            display: flex;
            align-items: center;
            padding: 10px 20px;
            border-top: 1px solid #ddd;
        }
        .messageBox {
            width: fit-content;
            height: 40px;
            display: flex;
            align-items: center;
            justify-content: center;
            background-color: #2d2d2d;
            padding: 0 15px;
            border-radius: 10px;
            border: 1px solid rgb(63, 63, 63);
        }
        .messageBox:focus-within {
            border: 1px solid rgb(110, 110, 110);
        }
        .fileUploadWrapper {
            width: fit-content;
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: Arial, Helvetica, sans-serif;
            margin-right: 10px;
        }
        #file {
            display: none;
        }
        .fileUploadWrapper label {
            cursor: pointer;
            width: fit-content;
            height: fit-content;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
        }
        .fileUploadWrapper label svg {
            height: 18px;
        }
        .fileUploadWrapper label svg path {
            transition: all 0.3s;
        }
        .fileUploadWrapper label svg circle {
            transition: all 0.3s;
        }
        .fileUploadWrapper label:hover svg path {
            stroke: #fff;
        }
        .fileUploadWrapper label:hover svg circle {
            stroke: #fff;
            fill: #3c3c3c;
        }
        .fileUploadWrapper label:hover .tooltip {
            display: block;
            opacity: 1;
        }
        .tooltip {
            position: absolute;
            top: -40px;
            display: none;
            opacity: 0;
            color: white;
            font-size: 10px;
            text-wrap: nowrap;
            background-color: #000;
            padding: 6px 10px;
            border: 1px solid #3c3c3c;
            border-radius: 5px;
            box-shadow: 0px 5px 10px rgba(0, 0, 0, 0.596);
            transition: all 0.3s;
        }
        #messageInput {
            width: 200px;
            height: 100%;
            background-color: transparent;
            outline: none;
            border: none;
            padding-left: 10px;
            color: white;
        }
        #messageInput:focus ~ #sendButton svg path,
        #messageInput:valid ~ #sendButton svg path {
            fill: #3c3c3c;
            stroke: white;
        }
        #sendButton {
            width: fit-content;
            height: 100%;
            background-color: transparent;
            outline: none;
            border: none;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: all 0.3s;
        }
        #sendButton svg {
            height: 18px;
            transition: all 0.3s;
        }
        #sendButton svg path {
            transition: all 0.3s;
        }
        #sendButton:hover svg path {
            fill: #3c3c3c;
            stroke: white;
        }
        .media {
            max-width: 100%;
            border-radius: 10px;
            margin-top: 5px;
            cursor: pointer;
        }
        .uploading {
            opacity: 0.5;
        }
        .error {
            color: red;
            font-style: italic;
        }
    </style>
</head>
<body>
    <div class="chat-container">
        <div class="chat-header">
            <div>
                <h3 id="chatPartner">Loading...</h3>
                <p id="status">Offline</p>
            </div>
            <div class="icons">
                <span>📞</span>
                <span>📹</span>
            </div>
        </div>

        <div class="chat-window" id="chatWindow">
            <!-- Messages will be added dynamically -->
        </div>

        <div class="chat-input">
            <div class="fileUploadWrapper">
                <label for="file">
                    <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M12 22C17.5228 22 22 17.5228 22 12C22 6.47715 17.5228 2 12 2C6.47715 2 2 6.47715 2 12C2 17.5228 6.47715 22 12 22Z" stroke="#8A8A8A" stroke-width="2"/>
                        <path d="M12 8V16" stroke="#8A8A8A" stroke-width="2" stroke-linecap="round"/>
                        <path d="M8 12H16" stroke="#8A8A8A" stroke-width="2" stroke-linecap="round"/>
                    </svg>
                    <div class="tooltip">Upload File</div>
                </label>
                <input type="file" id="file" accept="image/*,video/*,.pdf">
            </div>
            <div class="messageBox">
                <input type="text" id="messageInput" placeholder="Message..." required>
                <button id="sendButton" onclick="sendMessage()">
                    <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M22 2L11 13" stroke="#8A8A8A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                        <path d="M22 2L15 22L11 13L2 9L22 2Z" stroke="#8A8A8A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </button>
            </div>
        </div>
    </div>

    <script>
        let ws;
        const urlParams = new URLSearchParams(window.location.search);
        const chatId = urlParams.get('chat_id');
        const token = localStorage.getItem('token');
        let username;
        let chatPartner;
        let messageCounter = 0;
        let isSendingFile = false;

        if (!chatId || !token) {
            alert("Please log in to access the chat");
            window.location.href = "login.html";
        }

        function debounce(func, wait) {
            let timeout;
            return function (...args) {
                clearTimeout(timeout);
                timeout = setTimeout(() => func.apply(this, args), wait);
            };
        }

        async function fetchChatPartner() {
            try {
                const response = await fetch(`https://chat-backend-gxh8.onrender.com/chats?chat_id=${chatId}&token=${token}`);
                if (!response.ok) {
                    const errorText = await response.text();
                    throw new Error(`Failed to fetch chat: ${response.status} ${response.statusText} - ${errorText}`);
                }
                const chat = await response.json();
                console.log("Fetched chat:", chat);
                if (chat.participant1 === username) {
                    chatPartner = chat.participant2;
                } else {
                    chatPartner = chat.participant1;
                }
                document.getElementById('chatPartner').textContent = chatPartner;
            } catch (err) {
                console.error("Error fetching chat partner:", err);
                document.getElementById('chatPartner').textContent = "Unknown Partner";
            }
        }

        async function fetchMessages() {
            try {
                const response = await fetch(`https://chat-backend-gxh8.onrender.com/messages?chat_id=${chatId}&token=${token}`);
                if (!response.ok) {
                    throw new Error(`Failed to fetch messages: ${response.status} ${response.statusText}`);
                }
                const messages = await response.json();
                console.log("Fetched messages:", messages);
                messages.forEach(message => displayMessage(message, true));
            } catch (err) {
                console.error("Error fetching messages:", err);
            }
        }

        function connectWebSocket() {
            if (ws && ws.readyState !== WebSocket.CLOSED) {
                ws.close();
            }

            ws = new WebSocket(`wss://chat-backend-gxh8.onrender.com/ws?token=${token}&chat_id=${chatId}`);

            ws.onopen = function() {
                console.log("Connected to WebSocket server");
                setInterval(() => {
                    if (ws.readyState === WebSocket.OPEN) {
                        ws.send(JSON.stringify({ type: "ping" }));
                    }
                }, 15000);
            };

            ws.onmessage = function(event) {
                console.log("Received WebSocket message:", event.data);
                const message = JSON.parse(event.data);
                if (message.type === "ping" || message.type === "pong") return;
                if (message.type === "status") {
                    if (message.sender === chatPartner) {
                        document.getElementById('status').textContent = message.content.charAt(0).toUpperCase() + message.content.slice(1);
                    }
                    return;
                }
                const existingMessage = document.querySelector(`[data-local-id="${message.local_id}"]`);
                if (existingMessage && message.sender === username) {
                    const statusDiv = existingMessage.querySelector('.status');
                    if (statusDiv) {
                        statusDiv.textContent = "Delivered";
                    }
                    if (message.file_url) {
                        const media = existingMessage.querySelector('.media');
                        if (media) {
                            media.src = message.file_url;
                        }
                    }
                    existingMessage.classList.remove('uploading');
                    return;
                }
                displayMessage(message, true);
            };

            ws.onclose = function() {
                console.log("Disconnected from WebSocket server. Reconnecting...");
                setTimeout(connectWebSocket, 3000);
            };

            ws.onerror = function(error) {
                console.error("WebSocket error:", error);
            };
        }

        function checkTokenExpiration() {
            try {
                const tokenData = JSON.parse(atob(token.split('.')[1]));
                const exp = tokenData.exp * 1000;
                const now = Date.now();
                console.log("Token expiration check:", { exp, now, isExpired: now >= exp });
                if (now >= exp) {
                    alert("Your session has expired. Please log in again.");
                    localStorage.removeItem('token');
                    window.location.href = "login.html";
                    return true;
                }
                return false;
            } catch (err) {
                console.error("Error checking token expiration:", err);
                alert("Invalid token. Please log in again.");
                localStorage.removeItem('token');
                window.location.href = "login.html";
                return true;
            }
        }

        (async () => {
            try {
                const tokenData = JSON.parse(atob(token.split('.')[1]));
                username = tokenData.username;
                if (checkTokenExpiration()) return;
                await fetchChatPartner();
                await fetchMessages();
                connectWebSocket();
                setInterval(checkTokenExpiration, 60000);
            } catch (err) {
                console.error("Error initializing chat:", err);
                alert("Failed to initialize chat. Please try logging in again.");
                window.location.href = "login.html";
            }
        })();

        function sendMessage() {
            const messageInput = document.getElementById('messageInput');
            const fileInput = document.getElementById('file');
            const messageText = messageInput.value.trim();

            if (checkTokenExpiration()) return;

            if (!messageText && !fileInput.files.length) {
                return;
            }

            const localMessageId = `msg-${messageCounter++}`;
            const currentTimestamp = new Date().toISOString(); // UTC timestamp
            console.log("Sending message with timestamp:", currentTimestamp);

            if (fileInput.files.length > 0) {
                const file = fileInput.files[0];
                const fileExt = file.name.split('.').pop().toLowerCase();
                const isImage = ['jpg', 'jpeg', 'png', 'gif'].includes(fileExt);
                const isVideo = ['mp4', 'webm'].includes(fileExt);

                const message = {
                    sender: username,
                    receiver: chatPartner,
                    content: "Uploading file...",
                    file_url: isImage || isVideo ? URL.createObjectURL(file) : null,
                    timestamp: currentTimestamp,
                    local_id: localMessageId,
                    status: "Sending..."
                };
                displayMessage(message, false);

                const formData = new FormData();
                formData.append('file', file);

                fetch(`https://chat-backend-gxh8.onrender.com/upload?token=${token}&chat_id=${chatId}`, {
                    method: 'POST',
                    body: formData,
                })
                .then(response => {
                    if (!response.ok) {
                        return response.text().then(text => {
                            throw new Error(`Upload failed: ${response.status} ${response.statusText} - ${text}`);
                        });
                    }
                    return response.json();
                })
                .then(result => {
                    const fileMessage = {
                        receiver: chatPartner,
                        content: "Sent a file",
                        file_url: result.file_url,
                        local_id: localMessageId,
                    };
                    ws.send(JSON.stringify(fileMessage));
                })
                .catch(err => {
                    console.error("Upload error:", err);
                    const errorMessage = {
                        sender: username,
                        receiver: chatPartner,
                        content: `Failed to upload file: ${err.message}`,
                        timestamp: new Date().toISOString(),
                        local_id: localMessageId,
                        status: "Failed",
                        error: true
                    };
                    const existingMessage = document.querySelector(`[data-local-id="${localMessageId}"]`);
                    if (existingMessage) {
                        existingMessage.remove();
                    }
                    displayMessage(errorMessage, false);
                });
            }

            if (messageText) {
                const message = {
                    receiver: chatPartner,
                    content: messageText,
                    file_url: "",
                    local_id: localMessageId,
                };

                const localMessage = {
                    sender: username,
                    receiver: chatPartner,
                    content: messageText,
                    timestamp: currentTimestamp,
                    local_id: localMessageId,
                    status: "Sending..."
                };
                displayMessage(localMessage, false);

                if (!ws || ws.readyState !== WebSocket.OPEN) {
                    console.log("WebSocket not open. Retrying...");
                    connectWebSocket();
                    setTimeout(() => sendMessage(), 1000);
                    return;
                }

                ws.send(JSON.stringify(message));
                messageInput.value = '';
            }
        }

        function displayMessage(message, isFromServer) {
            console.log("Displaying message with timestamp:", message.timestamp);
            const chatWindow = document.getElementById('chatWindow');
            
            const timestampDiv = document.createElement('div');
            timestampDiv.classList.add('timestamp');
            // Parse the timestamp (assumed to be in UTC) and convert to local time
            const date = new Date(message.timestamp);
            timestampDiv.textContent = date.toLocaleString('en-US', {
                month: 'short',
                day: 'numeric',
                year: 'numeric',
                hour: 'numeric',
                minute: 'numeric',
                hour12: true
            });

            const messageBubble = document.createElement('div');
            messageBubble.classList.add('chat-bubble');
            if (message.sender === username) {
                messageBubble.classList.add('outgoing');
            } else {
                messageBubble.classList.add('incoming');
            }
            if (message.local_id) {
                messageBubble.setAttribute('data-local-id', message.local_id);
            }
            if (!isFromServer) {
                messageBubble.classList.add('uploading');
            }
            if (message.error) {
                messageBubble.classList.add('error');
            }

            if (message.content) {
                messageBubble.textContent = message.content;
            }

            if (message.file_url) {
                const fileExt = message.file_url.split('.').pop().toLowerCase();
                if (['jpg', 'jpeg', 'png', 'gif'].includes(fileExt)) {
                    const img = document.createElement('img');
                    img.src = message.file_url;
                    img.classList.add('media');
                    img.onclick = () => showFullImage(message.file_url);
                    messageBubble.appendChild(img);
                } else if (['mp4', 'webm'].includes(fileExt)) {
                    const video = document.createElement('video');
                    video.src = message.file_url;
                    video.controls = true;
                    video.classList.add('media');
                    messageBubble.appendChild(video);
                } else {
                    const link = document.createElement('a');
                    link.href = message.file_url;
                    link.textContent = "Download File";
                    link.target = "_blank";
                    messageBubble.appendChild(link);
                }
            }

            if (message.status) {
                const statusDiv = document.createElement('div');
                statusDiv.classList.add('status');
                statusDiv.textContent = message.status;
                messageBubble.appendChild(statusDiv);
            }

            chatWindow.appendChild(timestampDiv);
            chatWindow.appendChild(messageBubble);
            chatWindow.scrollTop = chatWindow.scrollHeight;
        }

        function showFullImage(imageUrl) {
            const fullImage = document.createElement('div');
            fullImage.style.position = 'fixed';
            fullImage.style.top = '0';
            fullImage.style.left = '0';
            fullImage.style.width = '100%';
            fullImage.style.height = '100%';
            fullImage.style.background = 'rgba(0,0,0,0.8)';
            fullImage.style.display = 'flex';
            fullImage.style.justifyContent = 'center';
            fullImage.style.alignItems = 'center';
            fullImage.style.zIndex = '1000';
            fullImage.innerHTML = `<img src="${imageUrl}" style="max-width: 90%; max-height: 90%; border-radius: 10px;" />`;
            fullImage.onclick = () => fullImage.remove();
            document.body.appendChild(fullImage);
        }

        document.getElementById('messageInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                sendMessage();
            }
        });

        document.getElementById('file').addEventListener('change', debounce(() => {
            if (document.getElementById('file').files.length > 0 && !isSendingFile) {
                isSendingFile = true;
                sendMessage().finally(() => {
                    isSendingFile = false;
                    document.getElementById('file').value = '';
                });
            }
        }, 500));
    </script>
</body>
</html>
