// Initialize Socket.IO
const socket = io();

// Notification System
function updateNotificationCount(count) {
    const badge = document.getElementById('notificationCount');
    if (badge) {
        badge.textContent = count;
        badge.style.display = count > 0 ? 'block' : 'none';
    }
}

function addNotification(notification) {
    const notificationsList = document.querySelector('.notifications-list');
    if (notificationsList) {
        const notificationElement = document.createElement('div');
        notificationElement.className = 'notification-item fade-in';
        notificationElement.innerHTML = `
            <div class="d-flex align-items-center">
                <i class="fas fa-${getNotificationIcon(notification.type)} me-2"></i>
                <div>
                    <h6 class="mb-0">${notification.title}</h6>
                    <small class="text-muted">${formatTimeAgo(notification.created_at)}</small>
                </div>
            </div>
            <p class="mb-0 mt-1">${notification.message}</p>
            ${notification.link ? `<a href="${notification.link}" class="btn btn-sm btn-primary mt-2">View</a>` : ''}
        `;
        notificationsList.insertBefore(notificationElement, notificationsList.firstChild);
    }
}

function getNotificationIcon(type) {
    const icons = {
        'new_sponsorship': 'handshake',
        'sponsorship_approved': 'check-circle',
        'sponsorship_rejected': 'times-circle',
        'sponsorship_cancelled': 'ban',
        'message': 'envelope',
        'default': 'bell'
    };
    return icons[type] || icons.default;
}

// Chat System
function initializeChat(eventId) {
    const chatContainer = document.querySelector('.chat-container');
    const messageForm = document.querySelector('.message-form');
    const messageInput = document.querySelector('.message-input');
    
    if (chatContainer && messageForm && messageInput) {
        // Join event room
        socket.emit('join_event', { event_id: eventId });
        
        // Handle new messages
        socket.on('new_message', (data) => {
            appendMessage(data);
        });
        
        // Handle typing indicators
        socket.on('user_typing', (data) => {
            showTypingIndicator(data);
        });
        
        // Handle message submission
        messageForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const message = messageInput.value.trim();
            if (message) {
                socket.emit('send_message', {
                    event_id: eventId,
                    message: message
                });
                messageInput.value = '';
            }
        });
        
        // Handle typing events
        let typingTimeout;
        messageInput.addEventListener('input', () => {
            socket.emit('typing', { event_id: eventId });
            
            clearTimeout(typingTimeout);
            typingTimeout = setTimeout(() => {
                socket.emit('stop_typing', { event_id: eventId });
            }, 1000);
        });
    }
}

function appendMessage(message) {
    const chatContainer = document.querySelector('.chat-container');
    if (chatContainer) {
        const messageElement = document.createElement('div');
        messageElement.className = `chat-message ${message.user_id === currentUserId ? 'sent' : 'received'} fade-in`;
        messageElement.innerHTML = `
            <div class="message-header">
                <strong>${message.username}</strong>
                <small class="text-muted ms-2">${formatTime(message.created_at)}</small>
            </div>
            <div class="message-content">${message.message}</div>
        `;
        chatContainer.appendChild(messageElement);
        chatContainer.scrollTop = chatContainer.scrollHeight;
    }
}

function showTypingIndicator(data) {
    const typingIndicator = document.querySelector('.typing-indicator');
    if (typingIndicator) {
        typingIndicator.textContent = `${data.username} is typing...`;
        typingIndicator.style.display = 'block';
        
        setTimeout(() => {
            typingIndicator.style.display = 'none';
        }, 1000);
    }
}

// Event Management
function initializeEventPage(eventId) {
    // Handle funding updates
    socket.on('funding_updated', (data) => {
        updateFundingProgress(data);
    });
    
    // Handle bookmark functionality
    const bookmarkBtn = document.querySelector('.bookmark-btn');
    if (bookmarkBtn) {
        bookmarkBtn.addEventListener('click', () => {
            toggleBookmark(eventId);
        });
    }
}

function updateFundingProgress(data) {
    const progressBar = document.querySelector('.funding-progress');
    const currentAmount = document.querySelector('.current-amount');
    const goalAmount = document.querySelector('.goal-amount');
    const percentage = document.querySelector('.funding-percentage');
    
    if (progressBar) {
        progressBar.style.width = `${data.percent}%`;
    }
    if (currentAmount) {
        currentAmount.textContent = formatCurrency(data.current_funding);
    }
    if (percentage) {
        percentage.textContent = `${data.percent.toFixed(1)}%`;
    }
}

function toggleBookmark(eventId) {
    fetch(`/event/${eventId}/bookmark`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCsrfToken()
        }
    })
    .then(response => response.json())
    .then(data => {
        const bookmarkBtn = document.querySelector('.bookmark-btn i');
        if (bookmarkBtn) {
            bookmarkBtn.className = data.bookmarked ? 'fas fa-bookmark' : 'far fa-bookmark';
        }
    })
    .catch(error => console.error('Error:', error));
}

// Utility Functions
function formatTimeAgo(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diff = now - date;
    
    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) return `${days}d ago`;
    if (hours > 0) return `${hours}h ago`;
    if (minutes > 0) return `${minutes}m ago`;
    return 'just now';
}

function formatTime(dateString) {
    const date = new Date(dateString);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function formatCurrency(amount) {
    return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: 'USD'
    }).format(amount);
}

function getCsrfToken() {
    return document.querySelector('meta[name="csrf-token"]').getAttribute('content');
}

// Search and Filter System
function initializeSearchAndFilters() {
    const searchForm = document.querySelector('.search-form');
    const filterForm = document.querySelector('.filter-form');
    
    if (searchForm) {
        searchForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const searchQuery = new FormData(searchForm).get('q');
            performSearch(searchQuery);
        });
    }
    
    if (filterForm) {
        filterForm.addEventListener('change', () => {
            const filterData = new FormData(filterForm);
            applyFilters(filterData);
        });
    }
}

function performSearch(query) {
    fetch(`/search?q=${encodeURIComponent(query)}`)
        .then(response => response.json())
        .then(data => {
            updateSearchResults(data);
        })
        .catch(error => console.error('Error:', error));
}

function applyFilters(filterData) {
    const params = new URLSearchParams(filterData);
    fetch(`/events/filter?${params.toString()}`)
        .then(response => response.json())
        .then(data => {
            updateEventList(data);
        })
        .catch(error => console.error('Error:', error));
}

function updateSearchResults(data) {
    const resultsContainer = document.querySelector('.search-results');
    if (resultsContainer) {
        resultsContainer.innerHTML = data.map(item => `
            <div class="search-result-item fade-in">
                <h5>${item.title}</h5>
                <p>${item.description}</p>
                <a href="${item.url}" class="btn btn-primary btn-sm">View Details</a>
            </div>
        `).join('');
    }
}

function updateEventList(data) {
    const eventList = document.querySelector('.event-list');
    if (eventList) {
        eventList.innerHTML = data.map(event => `
            <div class="event-card fade-in">
                <img src="${event.image}" class="card-img-top" alt="${event.title}">
                <div class="card-body">
                    <h5 class="card-title">${event.title}</h5>
                    <p class="card-text">${event.description}</p>
                    <div class="progress">
                        <div class="progress-bar" role="progressbar" style="width: ${event.funding_percentage}%"></div>
                    </div>
                    <div class="d-flex justify-content-between mt-2">
                        <span>${formatCurrency(event.current_funding)} raised</span>
                        <span>${event.funding_percentage}%</span>
                    </div>
                    <a href="/event/${event.id}" class="btn btn-primary mt-3">View Details</a>
                </div>
            </div>
        `).join('');
    }
}

// Initialize all components when the page loads
document.addEventListener('DOMContentLoaded', () => {
    // Initialize notifications
    socket.on('notification', (data) => {
        updateNotificationCount(data.count);
        addNotification(data.notification);
    });
    
    // Initialize chat if on chat page
    const eventId = document.querySelector('meta[name="event-id"]')?.getAttribute('content');
    if (eventId) {
        initializeChat(eventId);
    }
    
    // Initialize event page if on event page
    if (eventId) {
        initializeEventPage(eventId);
    }
    
    // Initialize search and filters
    initializeSearchAndFilters();

    // Initialize loading screen
    const loading = document.querySelector('.loading');
    if (loading) {
        setTimeout(() => {
            loading.classList.add('hidden');
        }, 1000);
    }

    // Header scroll effect
    const header = document.querySelector('.header');
    if (header) {
        window.addEventListener('scroll', () => {
            if (window.scrollY > 50) {
                header.classList.add('scrolled');
            } else {
                header.classList.remove('scrolled');
            }
        });
    }

    // Intersection Observer for fade-in animations
    const observerOptions = {
        root: null,
        rootMargin: '0px',
        threshold: 0.1
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
            }
        });
    }, observerOptions);

    // Observe all feature cards
    document.querySelectorAll('.feature-card').forEach(card => {
        observer.observe(card);
    });

    // Smooth scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Mobile menu toggle
    const menuButton = document.querySelector('.navbar-toggler');
    const navLinks = document.querySelector('.navbar-collapse');
    
    if (menuButton && navLinks) {
        menuButton.addEventListener('click', () => {
            navLinks.classList.toggle('show');
        });
    }

    // Parallax effect for hero section
    const hero = document.querySelector('.hero');
    if (hero) {
        window.addEventListener('scroll', () => {
            const scrolled = window.pageYOffset;
            hero.style.backgroundPositionY = scrolled * 0.5 + 'px';
        });
    }

    // Add hover effect to CTA buttons
    document.querySelectorAll('.cta-button').forEach(button => {
        button.addEventListener('mouseenter', () => {
            button.style.transform = 'translateY(-3px)';
        });
        
        button.addEventListener('mouseleave', () => {
            button.style.transform = 'translateY(0)';
        });
    });

    // Animate Elements on Scroll
    const animateOnScroll = () => {
        const elements = document.querySelectorAll('.feature-card, .step-card');
        elements.forEach(element => {
            const elementTop = element.getBoundingClientRect().top;
            const elementBottom = element.getBoundingClientRect().bottom;
            
            if (elementTop < window.innerHeight && elementBottom > 0) {
                element.classList.add('visible');
            }
        });
    };

    window.addEventListener('scroll', animateOnScroll);
    animateOnScroll(); // Initial check

    // Button Hover Effects
    const buttons = document.querySelectorAll('.btn-hero, .btn-light');
    buttons.forEach(button => {
        button.addEventListener('mouseenter', () => {
            button.style.transform = 'translateY(-3px)';
        });
        
        button.addEventListener('mouseleave', () => {
            button.style.transform = 'translateY(0)';
        });
    });

    // Feature Card Hover Effects
    const featureCards = document.querySelectorAll('.feature-card');
    featureCards.forEach(card => {
        card.addEventListener('mouseenter', () => {
            card.style.transform = 'translateY(-10px)';
        });
        
        card.addEventListener('mouseleave', () => {
            card.style.transform = 'translateY(0)';
        });
    });

    // Step Card Hover Effects
    const stepCards = document.querySelectorAll('.step-card');
    stepCards.forEach(card => {
        card.addEventListener('mouseenter', () => {
            card.style.transform = 'translateY(-10px)';
        });
        
        card.addEventListener('mouseleave', () => {
            card.style.transform = 'translateY(0)';
        });
    });

    // Initialize AOS (Animate On Scroll)
    if (typeof AOS !== 'undefined') {
        AOS.init({
            duration: 800,
            once: true,
            offset: 100
        });
    }

    // Fix for button links
    document.querySelectorAll('a[href]').forEach(link => {
        link.addEventListener('click', function(e) {
            if (!this.getAttribute('href').startsWith('#')) {
                e.preventDefault();
                const href = this.getAttribute('href');
                if (href) {
                    window.location.href = href;
                }
            }
        });
    });
});

// Preloader
window.addEventListener('load', function() {
    const preloader = document.getElementById('preloader');
    preloader.style.display = 'none';
});

// Navbar scroll effect
window.addEventListener('scroll', function() {
    const navbar = document.querySelector('.navbar');
    if (window.scrollY > 50) {
        navbar.classList.add('scrolled');
    } else {
        navbar.classList.remove('scrolled');
    }
});

// Flash message auto-dismiss
document.querySelectorAll('.alert').forEach(alert => {
    setTimeout(() => {
        alert.classList.add('animate__fadeOut');
        setTimeout(() => {
            alert.remove();
        }, 500);
    }, 5000);
});

// Form validation with animation
document.querySelectorAll('form').forEach(form => {
    form.addEventListener('submit', function(e) {
        let isValid = true;
        const inputs = form.querySelectorAll('input[required], select[required], textarea[required]');
        
        inputs.forEach(input => {
            if (!input.value.trim()) {
                isValid = false;
                input.classList.add('animate__animated', 'animate__shakeX');
                setTimeout(() => {
                    input.classList.remove('animate__animated', 'animate__shakeX');
                }, 500);
            }
        });
        
        if (!isValid) {
            e.preventDefault();
            const errorMessage = document.createElement('div');
            errorMessage.className = 'alert alert-danger animate__animated animate__fadeIn';
            errorMessage.textContent = 'Please fill in all required fields';
            form.insertBefore(errorMessage, form.firstChild);
            setTimeout(() => {
                errorMessage.remove();
            }, 5000);
        }
    });
});

// Card hover effect
document.querySelectorAll('.card').forEach(card => {
    card.addEventListener('mouseenter', function() {
        this.style.transform = 'translateY(-10px)';
    });
    
    card.addEventListener('mouseleave', function() {
        this.style.transform = 'translateY(0)';
    });
});

// Progress bar animation
document.querySelectorAll('.progress-bar').forEach(bar => {
    const targetWidth = bar.getAttribute('aria-valuenow') + '%';
    bar.style.width = '0%';
    setTimeout(() => {
        bar.style.width = targetWidth;
    }, 100);
});

// Tooltip initialization
document.querySelectorAll('.tooltip').forEach(tooltip => {
    tooltip.addEventListener('mouseenter', function() {
        const tooltipText = this.querySelector('.tooltip-text');
        tooltipText.style.visibility = 'visible';
        tooltipText.style.opacity = '1';
    });
    
    tooltip.addEventListener('mouseleave', function() {
        const tooltipText = this.querySelector('.tooltip-text');
        tooltipText.style.visibility = 'hidden';
        tooltipText.style.opacity = '0';
    });
});

// Modal animation
document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('show.bs.modal', function() {
        this.querySelector('.modal-content').classList.add('animate__animated', 'animate__fadeInDown');
    });
    
    modal.addEventListener('hide.bs.modal', function() {
        this.querySelector('.modal-content').classList.remove('animate__animated', 'animate__fadeInDown');
    });
});

// Dropdown animation
document.querySelectorAll('.dropdown-toggle').forEach(toggle => {
    toggle.addEventListener('click', function() {
        const dropdownMenu = this.nextElementSibling;
        dropdownMenu.classList.add('animate__animated', 'animate__fadeIn');
    });
});

// Image lazy loading
document.addEventListener('DOMContentLoaded', function() {
    const images = document.querySelectorAll('img[data-src]');
    
    const imageObserver = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const img = entry.target;
                img.src = img.dataset.src;
                img.classList.add('animate__animated', 'animate__fadeIn');
                observer.unobserve(img);
            }
        });
    });
    
    images.forEach(img => imageObserver.observe(img));
});

// Smooth scroll for pagination
document.querySelectorAll('.pagination .page-link').forEach(link => {
    link.addEventListener('click', function(e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// Form input animation
document.querySelectorAll('.form-control').forEach(input => {
    input.addEventListener('focus', function() {
        this.parentElement.classList.add('animate__animated', 'animate__pulse');
        setTimeout(() => {
            this.parentElement.classList.remove('animate__animated', 'animate__pulse');
        }, 500);
    });
});

// Social media links hover effect
document.querySelectorAll('.social-link').forEach(link => {
    link.addEventListener('mouseenter', function() {
        this.style.transform = 'translateY(-5px) rotate(5deg)';
    });
    
    link.addEventListener('mouseleave', function() {
        this.style.transform = 'translateY(0) rotate(0)';
    });
});

// Initialize tooltips
const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
tooltipTriggerList.map(function (tooltipTriggerEl) {
    return new bootstrap.Tooltip(tooltipTriggerEl);
});

// Initialize popovers
const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
popoverTriggerList.map(function (popoverTriggerEl) {
    return new bootstrap.Popover(popoverTriggerEl);
});

// Newsletter Form
const newsletterForm = document.querySelector('.newsletter-form');
if (newsletterForm) {
    newsletterForm.addEventListener('submit', function(e) {
        e.preventDefault();
        const email = this.querySelector('input[type="email"]').value;
        
        // Add loading state
        const button = this.querySelector('button');
        const originalText = button.innerHTML;
        button.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Subscribing...';
        button.disabled = true;
        
        // Simulate API call
        setTimeout(() => {
            button.innerHTML = '<i class="fas fa-check me-2"></i>Subscribed!';
            setTimeout(() => {
                button.innerHTML = originalText;
                button.disabled = false;
                this.reset();
            }, 2000);
        }, 1500);
    });
}

// Socket.IO Event Handlers
socket.on('connect', () => {
    console.log('Connected to server');
});

socket.on('disconnect', () => {
    console.log('Disconnected from server');
});

// Update Notification Count
function updateNotificationCount(count) {
    const badge = document.querySelector('.notification-badge');
    if (badge) {
        badge.textContent = count;
        badge.style.display = count > 0 ? 'block' : 'none';
    }
}

// Parallax Effect
window.addEventListener('scroll', () => {
    const parallaxElements = document.querySelectorAll('.parallax');
    parallaxElements.forEach(element => {
        const speed = element.dataset.speed || 0.5;
        const yPos = -(window.pageYOffset * speed);
        element.style.transform = `translateY(${yPos}px)`;
    });
});

// Theme Switcher
const themeSwitcher = document.querySelector('.theme-switcher');
if (themeSwitcher) {
    themeSwitcher.addEventListener('click', () => {
        document.body.classList.toggle('dark-theme');
        localStorage.setItem('theme', document.body.classList.contains('dark-theme') ? 'dark' : 'light');
    });
    
    // Check for saved theme preference
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'dark') {
        document.body.classList.add('dark-theme');
    }
}

// Search Functionality
const searchInput = document.querySelector('.search-input');
if (searchInput) {
    let searchTimeout;
    searchInput.addEventListener('input', (e) => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            const query = e.target.value.trim();
            if (query.length >= 2) {
                performSearch(query);
            }
        }, 300);
    });
}

async function performSearch(query) {
    try {
        const response = await fetch(`/search?q=${encodeURIComponent(query)}`);
        const data = await response.json();
        updateSearchResults(data);
    } catch (error) {
        console.error('Search error:', error);
    }
}

function updateSearchResults(results) {
    const resultsContainer = document.querySelector('.search-results');
    if (!resultsContainer) return;
    
    resultsContainer.innerHTML = results.map(result => `
        <div class="search-result-item">
            <h4>${result.title}</h4>
            <p>${result.description}</p>
        </div>
    `).join('');
}

// Add to these functions as needed 