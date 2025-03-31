// Initialize Socket.IO connection
const socket = io();

// Global event handlers
socket.on('connect', () => {
    console.log('Connected to WebSocket server');
    // Join user's personal room if authenticated
    if (currentUserId) {
        socket.emit('join_user_room', { user_id: currentUserId });
    }
});

socket.on('disconnect', () => {
    console.log('Disconnected from WebSocket server');
});

socket.on('error', (data) => {
    console.error('Socket error:', data);
    showNotification(data.message, 'error');
});

// Notification handler
socket.on('notification', (data) => {
    showNotification(data.message, data.type);
    updateNotificationBadge();
});

// Chat message handler
socket.on('new_message', (data) => {
    appendMessage(data);
    updateChatBadge();
});

// Typing indicator handler
socket.on('user_typing', (data) => {
    showTypingIndicator(data.username);
});

// Funding update handler
socket.on('funding_updated', (data) => {
    updateFundingProgress(data);
});

// Utility functions
function showNotification(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-white bg-${type} border-0`;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;
    
    const toastContainer = document.getElementById('toast-container') || createToastContainer();
    toastContainer.appendChild(toast);
    
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();
    
    // Remove toast after it's hidden
    toast.addEventListener('hidden.bs.toast', () => {
        toast.remove();
    });
}

function createToastContainer() {
    const container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container position-fixed bottom-0 end-0 p-3';
    document.body.appendChild(container);
    return container;
}

function updateNotificationBadge() {
    const badge = document.getElementById('notification-badge');
    if (badge) {
        const currentCount = parseInt(badge.textContent) || 0;
        badge.textContent = currentCount + 1;
        badge.style.display = 'inline';
    }
}

function updateChatBadge() {
    const badge = document.getElementById('chat-badge');
    if (badge) {
        const currentCount = parseInt(badge.textContent) || 0;
        badge.textContent = currentCount + 1;
        badge.style.display = 'inline';
    }
}

function showTypingIndicator(username) {
    const typingIndicator = document.getElementById('typing-indicator');
    if (typingIndicator) {
        typingIndicator.textContent = `${username} is typing...`;
        typingIndicator.style.display = 'block';
        
        // Clear typing indicator after 3 seconds
        setTimeout(() => {
            typingIndicator.style.display = 'none';
        }, 3000);
    }
}

function updateFundingProgress(data) {
    const progressBar = document.getElementById('funding-progress');
    const currentAmount = document.getElementById('current-funding');
    const goalAmount = document.getElementById('funding-goal');
    
    if (progressBar) {
        progressBar.style.width = `${data.percent}%`;
    }
    if (currentAmount) {
        currentAmount.textContent = formatCurrency(data.current_funding);
    }
    if (goalAmount) {
        goalAmount.textContent = formatCurrency(data.funding_goal);
    }
}

function formatCurrency(amount) {
    return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: 'USD'
    }).format(amount);
}

// Export socket instance for use in other modules
window.socket = socket; 