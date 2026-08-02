/**
 * Web Push subscription management for the Deadrop PWA.
 *
 * iOS exposes the Push API only inside a web app installed to the Home
 * Screen, and only from iOS 16.4. In a Safari tab `window.PushManager` is
 * undefined, so `supported()` is false and the UI offers an
 * "Add to Home Screen" nudge instead of a toggle that cannot work.
 */

const DeadropPush = {
    /** Push API + service workers available in this context. */
    supported() {
        return (
            'serviceWorker' in navigator &&
            'PushManager' in window &&
            'Notification' in window
        );
    },

    /** Running as an installed web app rather than a browser tab. */
    standalone() {
        return (
            window.matchMedia('(display-mode: standalone)').matches ||
            window.navigator.standalone === true
        );
    },

    /** iOS/iPadOS, where an install is a hard requirement for push. */
    isIOS() {
        return (
            /iPad|iPhone|iPod/.test(navigator.userAgent) ||
            (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1)
        );
    },

    /** Server-side push config: whether it's on, and the VAPID public key. */
    async serverConfig() {
        const response = await fetch('/push/vapid-public-key');
        if (!response.ok) throw new Error('Could not read push configuration');
        return response.json();
    },

    /** The browser's current subscription, or null. */
    async currentSubscription() {
        if (!this.supported()) return null;
        const registration = await navigator.serviceWorker.ready;
        return registration.pushManager.getSubscription();
    },

    /**
     * Why push is unavailable here, or null when it can be enabled.
     * Returned strings are shown to the user verbatim.
     */
    unavailableReason() {
        if (this.isIOS() && !this.standalone()) {
            return 'Add Deadrop to your Home Screen to enable notifications.';
        }
        if (!this.supported()) {
            return 'This browser does not support push notifications.';
        }
        return null;
    },

    /**
     * Ask for permission, subscribe, and register with the server.
     * Must be called from a user gesture — iOS requires it.
     */
    async subscribe(credentials) {
        const blocked = this.unavailableReason();
        if (blocked) throw new Error(blocked);

        const config = await this.serverConfig();
        if (!config.enabled || !config.public_key) {
            throw new Error('Push notifications are not configured on this server.');
        }

        const permission = await Notification.requestPermission();
        if (permission !== 'granted') {
            throw new Error('Notification permission was denied.');
        }

        const registration = await navigator.serviceWorker.ready;
        let subscription = await registration.pushManager.getSubscription();
        if (!subscription) {
            subscription = await registration.pushManager.subscribe({
                // iOS mandates userVisibleOnly — silent push is not offered.
                userVisibleOnly: true,
                applicationServerKey: this._urlBase64ToUint8Array(config.public_key),
            });
        }

        const raw = subscription.toJSON();
        await DeadropAPI.request('POST', `/${credentials.ns}/push/subscriptions`, {
            credentials,
            body: {
                endpoint: raw.endpoint,
                keys: { p256dh: raw.keys.p256dh, auth: raw.keys.auth },
                user_agent: navigator.userAgent.slice(0, 200),
            },
        });
        return subscription;
    },

    /** Unsubscribe locally and drop the server-side row. */
    async unsubscribe(credentials) {
        const subscription = await this.currentSubscription();
        if (!subscription) return false;

        const endpoint = subscription.endpoint;
        await subscription.unsubscribe();
        try {
            await DeadropAPI.request(
                'DELETE',
                `/${credentials.ns}/push/subscriptions?endpoint=${encodeURIComponent(endpoint)}`,
                { credentials },
            );
        } catch (err) {
            // A 404 means the server already pruned it; nothing to undo.
            console.warn('[push] server unsubscribe failed:', err.message);
        }
        return true;
    },

    /** Fire a test notification at every device this identity registered. */
    async sendTest(credentials) {
        return DeadropAPI.request('POST', `/${credentials.ns}/push/test`, { credentials });
    },

    /** base64url VAPID key → Uint8Array, the shape applicationServerKey wants. */
    _urlBase64ToUint8Array(base64String) {
        const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
        const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
        const raw = window.atob(base64);
        const output = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) output[i] = raw.charCodeAt(i);
        return output;
    },
};
