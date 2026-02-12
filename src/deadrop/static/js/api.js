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

    // ==================== ROOM API ====================

    /**
     * List rooms the user is a member of.
     */
    async listRooms(credentials) {
        return this.request('GET', `/${credentials.ns}/rooms`, { credentials });
    },

    /**
     * Get room details.
     */
    async getRoom(credentials, roomId) {
        return this.request('GET', `/${credentials.ns}/rooms/${roomId}`, { credentials });
    },

    /**
     * Get room messages.
     * @param {object} credentials - User credentials
     * @param {string} roomId - Room ID
     * @param {object} options - Optional parameters
     * @param {string} options.afterMid - Get messages after this message ID
     * @param {number} options.limit - Max messages to return
     * @param {number} options.wait - Long-poll timeout in seconds
     */
    async getRoomMessages(credentials, roomId, { afterMid = null, limit = null, wait = null } = {}) {
        let path = `/${credentials.ns}/rooms/${roomId}/messages`;
        const params = new URLSearchParams();
        if (afterMid) params.set('after', afterMid);
        if (limit) params.set('limit', limit.toString());
        if (wait) params.set('wait', wait.toString());
        if (params.toString()) path += '?' + params.toString();
        
        return this.request('GET', path, { credentials });
    },

    /**
     * Send a message to a room.
     */
    async sendRoomMessage(credentials, roomId, body, contentType = 'text/plain') {
        return this.request('POST', `/${credentials.ns}/rooms/${roomId}/messages`, {
            body: { body, content_type: contentType },
            credentials,
        });
    },

    /**
     * Get unread count for a room.
     */
    async getRoomUnread(credentials, roomId) {
        return this.request('GET', `/${credentials.ns}/rooms/${roomId}/unread`, { credentials });
    },

    /**
     * Update read cursor for a room.
     */
    async updateRoomReadCursor(credentials, roomId, lastReadMid) {
        return this.request('POST', `/${credentials.ns}/rooms/${roomId}/read`, {
            body: { last_read_mid: lastReadMid },
            credentials,
        });
    },

    /**
     * List room members.
     */
    async listRoomMembers(credentials, roomId) {
        return this.request('GET', `/${credentials.ns}/rooms/${roomId}/members`, { credentials });
    },
};

// Export for use in other modules
window.DeadropAPI = DeadropAPI;
