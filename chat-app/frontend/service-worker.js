importScripts('https://www.gstatic.com/firebasejs/9.22.0/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/9.22.0/firebase-messaging-compat.js');

// Initialize Firebase in the service worker
const firebaseConfig = {
  apiKey: "AIzaSyAi4RYSgi7bPiAXZLUbB-KS4LuvvMhvrLM",
  authDomain: "chatapp-moh.firebaseapp.com",
  projectId: "chatapp-moh",
  storageBucket: "chatapp-moh.firebasestorage.app",
  messagingSenderId: "814256503636",
  appId: "1:814256503636:web:7ee0ae666170908a3566c1"
};

firebase.initializeApp(firebaseConfig);
const messaging = firebase.messaging();

messaging.onBackgroundMessage((payload) => {
    console.log('[service-worker.js] Received background message:', payload);
    const notificationTitle = payload.notification.title || 'New Message';
    const notificationOptions = {
        body: payload.notification.body || 'You have a new message!',
        icon: payload.notification.icon || 'https://i.ibb.co/2ZqN0jW/user.png',
        data: payload.data || {}
    };
    self.registration.showNotification(notificationTitle, notificationOptions);
});

self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    const data = event.notification.data;
    if (data.call_initiator) {
        event.waitUntil(
            clients.openWindow(`/frontend/chat.html?partner=${data.call_initiator}`)
        );
    } else {
        event.waitUntil(
            clients.openWindow('/frontend/chat.html')
        );
    }
});
