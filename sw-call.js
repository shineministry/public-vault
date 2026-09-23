/**
 * Shine Vault — Push Notification Service Worker
 * Handles incoming push events from the vault backend worker
 * and shows OS-level notifications so the admin never misses a call.
 * 
 * Place this file at the web root alongside admin-incoming-call.html.
 */
const WORKER_URL = self.location.origin;

self.addEventListener('push', function (event) {
  event.waitUntil(
    fetch(WORKER_URL + '/api/active-call')
      .then(function (res) { return res.json(); })
      .then(function (data) {
        if (!data.active || !data.call) return;
        var call = data.call;
        return self.registration.showNotification('Incoming Vault Call', {
          body: call.name + ' (' + call.mode + ') · ' + call.reason,
          icon: '/favicon.png',
          badge: '/favicon.png',
          tag: 'shine-vault-call-' + call.callId,
          requireInteraction: true,
          data: { callId: call.callId, call: call }
        });
      })
      .catch(function () {
        return self.registration.showNotification('Incoming Vault Call', {
          body: 'Someone wants to talk to you on the Vault line.',
          icon: '/favicon.png',
          badge: '/favicon.png',
          tag: 'shine-vault-call',
          requireInteraction: true
        });
      })
  );
});

self.addEventListener('notificationclick', function (event) {
  event.notification.close();
  var callId = event.notification.data && event.notification.data.callId;
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function (clientList) {
      for (var i = 0; i < clientList.length; i++) {
        var client = clientList[i];
        if (client.url.indexOf('admin-incoming-call') !== -1 && 'focus' in client) {
          client.postMessage({ type: 'push-call', callId: callId });
          return client.focus();
        }
      }
      var url = callId ? '/admin-incoming-call.html?callId=' + callId : '/admin-incoming-call.html';
      if (clients.openWindow) return clients.openWindow(url);
    })
  );
});
