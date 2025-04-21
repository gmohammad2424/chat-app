self.addEventListener('push', event => {
    const data = event.data.json();
    self.registration.showNotification(data.title, {
        body: data.body,
        icon: '/icon.png', // Optional: Add an icon for notifications
    });
});

self.addEventListener('notificationclick', event => {
    event.notification.close();
    event.waitUntil(
        clients.openWindow('/chat.html?chat_id=' + data.chat_id) // Adjust URL as needed
    );
});
