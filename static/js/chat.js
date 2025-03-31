// Chat functionality
document.addEventListener('DOMContentLoaded', () => {
    const messageForm = document.getElementById('message-form');
    const messageInput = document.getElementById('message-input');
    const messagesContainer = document.getElementById('messages-container');
    const typingIndicator = document.getElementById('typing-indicator');
    let typingTimeout;

    if (messageForm && messageInput) {
        // Handle message submission
        messageForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const message = messageInput.value.trim();
            if (message) {
                sendMessage(message);
                messageInput.value = '';
            }
        });

        // Handle typing indicator
        messageInput.addEventListener('input', () => {
            if (currentUserId && currentChatUserId) {
                socket.emit('typing', {
                    recipient_id: currentChatUserId
                });
            }
        });
    }

    // Function to send a message
    function sendMessage(message) {
        if (currentUserId && currentChatUserId) {
            socket.emit('send_message', {
                recipient_id: currentChatUserId,
                content: message
            });
        }
    }

    // Function to append a message to the chat
    window.appendMessage = (data) => {
        if (!messagesContainer) return;

        const messageElement = document.createElement('div');
        messageElement.className = `message ${data.sender_id === currentUserId ? 'sent' : 'received'}`;
        
        const messageContent = document.createElement('div');
        messageContent.className = 'message-content';
        
        const username = document.createElement('div');
        username.className = 'message-username';
        username.textContent = data.username;
        
        const text = document.createElement('div');
        text.className = 'message-text';
        text.textContent = data.message;
        
        const time = document.createElement('div');
        time.className = 'message-time';
        time.textContent = new Date(data.created_at).toLocaleTimeString();
        
        messageContent.appendChild(username);
        messageContent.appendChild(text);
        messageContent.appendChild(time);
        messageElement.appendChild(messageContent);
        
        messagesContainer.appendChild(messageElement);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    };

    // Function to show typing indicator
    window.showTypingIndicator = (username) => {
        if (!typingIndicator) return;

        typingIndicator.textContent = `${username} is typing...`;
        typingIndicator.style.display = 'block';

        clearTimeout(typingTimeout);
        typingTimeout = setTimeout(() => {
            typingIndicator.style.display = 'none';
        }, 3000);
    };

    // Join chat room when page loads
    if (currentChatUserId) {
        socket.emit('join_chat', { user_id: currentChatUserId });
    }
}); 