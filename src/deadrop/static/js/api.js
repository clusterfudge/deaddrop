/**
 * API client for Deadrop.
 */

const DeadropAPI = {
    /**
     * Make an authenticated API request.
     */
    async request(method, path, { body = null, credentials = null } = {}) {
        const headers = {
            'Content-Type': 'application/json',
        };
        
        if (credentials) {
            headers['X-Inbox-Secret'] = credentials.secret;
        }
        
        const options = {
            method,
            headers,
        };
        
        if (body) {
            options.body = JSON.stringify(body);
        }
        
        const response = await fetch(path, options);
        
        if (!response.ok) {
            const error = await response.json().catch(() => ({ detail: response.statusText }));
            throw new Error(error.detail || 'Request failed');
        }
        
        return response.json();
    },

    /**
     * Get invite info (public, no auth required).
     */
    async getInviteInfo(inviteId) {
        return this.request('GET', `/api/invites/${inviteId}/info`);
    },

    /**
     * Claim an invite.
     */
    async claimInvite(inviteId) {
        return this.request('POST', `/api/invites/${inviteId}/claim`);
    },

    /**
     * List peers in a namespace.
     */
    async listPeers(credentials) {
        return this.request('GET', `/${credentials.ns}/identities`, { credentials });
    },

    /**
     * Get inbox messages.
     */
    async getInbox(credentials, { unread = false, after = null } = {}) {
        let path = `/${credentials.ns}/inbox/${credentials.id}`;
        const params = new URLSearchParams();
        if (unread) params.set('unread', 'true');
        if (after) params.set('after', after);
        if (params.toString()) path += '?' + params.toString();
        
        return this.request('GET', path, { credentials });
    },

    /**
     * Get archived messages.
     */
    async getArchivedMessages(credentials) {
        return this.request('GET', `/${credentials.ns}/inbox/${credentials.id}/archived`, { credentials });
    },

    /**
     * Send a message.
     */
    async sendMessage(credentials, to, body, ttlHours = null) {
        const data = { to, body };
        if (ttlHours !== null) data.ttl_hours = ttlHours;
        
        return this.request('POST', `/${credentials.ns}/send`, {
            body: data,
            credentials,
        });
    },

    /**
     * Archive a message.
     */
    async archiveMessage(credentials, mid) {
        return this.request('POST', `/${credentials.ns}/inbox/${credentials.id}/${mid}/archive`, { credentials });
    },

    /**
     * Unarchive a message.
     */
    async unarchiveMessage(credentials, mid) {
        return this.request('POST', `/${credentials.ns}/inbox/${credentials.id}/${mid}/unarchive`, { credentials });
    },

    /**
     * Delete a message.
     */
    async deleteMessage(credentials, mid) {
        return this.request('DELETE', `/${credentials.ns}/inbox/${credentials.id}/${mid}`, { credentials });
    },
};

// Export for use in other modules
window.DeadropAPI = DeadropAPI;
