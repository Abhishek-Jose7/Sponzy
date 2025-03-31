// Initialize Socket.IO connection
const socket = io();

// Chat functionality
function initializeChat() {
    const messageInput = document.getElementById('message-input');
    const sendButton = document.getElementById('send-message');
    const chatMessages = document.getElementById('chat-messages');

    if (sendButton && messageInput) {
        sendButton.addEventListener('click', () => {
            const recipientId = sendButton.dataset.recipientId;
            const message = messageInput.value.trim();
            
            if (message) {
                socket.emit('private_message', {
                    recipient_id: recipientId,
                    message: message
                });
                messageInput.value = '';
            }
        });
    }

    // Handle incoming messages
    socket.on('new_private_message', (data) => {
        if (chatMessages) {
            const messageElement = document.createElement('div');
            messageElement.className = `message ${data.sender_id === currentUserId ? 'sent' : 'received'}`;
            messageElement.innerHTML = `
                <div class="message-content">
                    <div class="message-text">${data.content}</div>
                    <div class="message-time">${new Date(data.timestamp).toLocaleTimeString()}</div>
                </div>
            `;
            chatMessages.appendChild(messageElement);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }
    });
}

// Funding progress updates
function initializeFundingProgress() {
    const progressBars = document.querySelectorAll('.funding-progress');
    
    socket.on('funding_progress', (data) => {
        const progressBar = document.querySelector(`#progress-${data.event_id}`);
        if (progressBar) {
            progressBar.style.width = `${data.progress}%`;
            progressBar.setAttribute('aria-valuenow', data.progress);
            
            // Update funding amount display
            const fundingAmount = document.querySelector(`#funding-amount-${data.event_id}`);
            if (fundingAmount) {
                fundingAmount.textContent = new Intl.NumberFormat('en-US', {
                    style: 'currency',
                    currency: 'USD'
                }).format(data.current_funding);
            }
            
            // Show celebration animation if goal reached
            if (data.progress >= 100) {
                showCelebration(data.event_id);
            }
        }
    });
}

// Event countdown timer
function initializeCountdown() {
    const countdownElements = document.querySelectorAll('.event-countdown');
    
    countdownElements.forEach(element => {
        const eventId = element.dataset.eventId;
        socket.emit('join_event_room', { event_id: eventId });
    });
    
    socket.on('countdown_update', (data) => {
        const countdownElement = document.querySelector(`#countdown-${data.event_id}`);
        if (countdownElement) {
            countdownElement.innerHTML = `
                <div class="countdown-item">${data.days}d</div>
                <div class="countdown-item">${data.hours}h</div>
                <div class="countdown-item">${data.minutes}m</div>
                <div class="countdown-item">${data.seconds}s</div>
            `;
        }
    });
}

// Live activity feed
function initializeActivityFeed() {
    const activityFeed = document.getElementById('activity-feed');
    
    socket.on('new_activity', (data) => {
        if (activityFeed) {
            const activityElement = document.createElement('div');
            activityElement.className = 'activity-item';
            
            let activityContent = '';
            switch (data.type) {
                case 'follow':
                    activityContent = `<strong>${data.data.username}</strong> started following a user`;
                    break;
                case 'like':
                    activityContent = `<strong>${data.data.username}</strong> liked an event`;
                    break;
                case 'funding':
                    activityContent = `<strong>${data.data.username}</strong> sponsored an event`;
                    break;
            }
            
            activityElement.innerHTML = `
                <div class="activity-content">
                    ${activityContent}
                    <small class="text-muted">${new Date(data.timestamp).toLocaleTimeString()}</small>
                </div>
            `;
            
            activityFeed.insertBefore(activityElement, activityFeed.firstChild);
            
            // Limit the number of visible activities
            if (activityFeed.children.length > 50) {
                activityFeed.removeChild(activityFeed.lastChild);
            }
        }
    });
}

// Real-time notifications
function initializeNotifications() {
    const notificationsList = document.getElementById('notifications-list');
    const notificationCount = document.getElementById('notification-count');
    
    socket.on('notifications_count', (data) => {
        if (notificationCount) {
            notificationCount.textContent = data.count;
            if (data.count > 0) {
                notificationCount.classList.remove('d-none');
            } else {
                notificationCount.classList.add('d-none');
            }
        }
    });
    
    // Handle new notifications
    socket.on('new_notification', (data) => {
        if (notificationsList) {
            const notificationElement = document.createElement('div');
            notificationElement.className = 'notification-item unread';
            notificationElement.innerHTML = `
                <div class="notification-content">
                    <div class="notification-title">${data.title}</div>
                    <div class="notification-message">${data.message}</div>
                    <small class="text-muted">${new Date(data.timestamp).toLocaleTimeString()}</small>
                </div>
            `;
            
            notificationsList.insertBefore(notificationElement, notificationsList.firstChild);
            
            // Update notification count
            if (notificationCount) {
                const currentCount = parseInt(notificationCount.textContent) || 0;
                notificationCount.textContent = currentCount + 1;
                notificationCount.classList.remove('d-none');
            }
            
            // Show toast notification
            showToast(data.title, data.message);
        }
    });
}

// Helper function to show celebration animation
function showCelebration(eventId) {
    const eventCard = document.querySelector(`#event-${eventId}`);
    if (eventCard) {
        eventCard.classList.add('celebration');
        confetti({
            particleCount: 100,
            spread: 70,
            origin: { y: 0.6 }
        });
        setTimeout(() => {
            eventCard.classList.remove('celebration');
        }, 3000);
    }
}

// Helper function to show toast notifications
function showToast(title, message) {
    const toastContainer = document.getElementById('toast-container');
    if (toastContainer) {
        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.innerHTML = `
            <div class="toast-header">
                <strong class="me-auto">${title}</strong>
                <button type="button" class="btn-close" data-bs-dismiss="toast"></button>
            </div>
            <div class="toast-body">${message}</div>
        `;
        
        toastContainer.appendChild(toast);
        const bsToast = new bootstrap.Toast(toast);
        bsToast.show();
        
        toast.addEventListener('hidden.bs.toast', () => {
            toastContainer.removeChild(toast);
        });
    }
}

// Initialize all real-time features
document.addEventListener('DOMContentLoaded', () => {
    initializeChat();
    initializeFundingProgress();
    initializeCountdown();
    initializeActivityFeed();
    initializeNotifications();
}); 