self.addEventListener('push', function(event) {
    const data = event.data.json();
    const { title, body } = data;

    event.waitUntil(
        self.registration.showNotification(title, {
            body: body,
            icon: 'https://placehold.co/30x30',
            data: { url: data.url }
        })
    );
});

self.addEventListener('notificationclick', function(event) {
    event.notification.close();
    event.waitUntil(
        clients.openWindow(event.notification.data.url)
    );
});
