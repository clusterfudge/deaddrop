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
     */
    async getRoomMessages(credentials, roomId, { afterMid = null, limit = null } = {}) {
        let path = `/${credentials.ns}/rooms/${roomId}/messages`;
        const params = new URLSearchParams();
        if (afterMid) params.set('after', afterMid);
        if (limit) params.set('limit', limit.toString());
        if (params.toString()) path += '?' + params.toString();
        
        return this.request('GET', path, { credentials });
    },

    /**
     * Send a message to a room.
     */
    async sendRoomMessage(credentials, roomId, body, contentType = 'text/plain', referenceMid = null) {
        const payload = { body, content_type: contentType };
        if (referenceMid) payload.reference_mid = referenceMid;
        return this.request('POST', `/${credentials.ns}/rooms/${roomId}/messages`, {
            body: payload,
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

    // ==================== SUBSCRIPTION API ====================

    /**
     * Subscribe to topic changes (poll mode).
     * Blocks until an event occurs or timeout.
     * 
     * @param {object} credentials - User credentials
     * @param {object} topics - Map of topic_key -> last_seen_mid (null = never seen)
     * @param {number} timeout - Max seconds to wait (1-60)
     * @returns {Promise<{events: object, timeout: boolean}>}
     */
    async subscribePoll(credentials, topics, timeout = 30) {
        return this.request('POST', `/${credentials.ns}/subscribe`, {
            body: { topics, mode: 'poll', timeout },
            credentials,
        });
    },

    /**
     * Subscribe to topic changes (SSE stream mode).
     * Returns a fetch Response for reading SSE events.
     * 
     * @param {object} credentials - User credentials
     * @param {object} topics - Map of topic_key -> last_seen_mid (null = never seen)
     * @param {AbortSignal} signal - AbortSignal for cancellation
     * @returns {Promise<Response>} Raw fetch response for SSE parsing
     */
    async subscribeStream(credentials, topics, signal = null) {
        const headers = {
            'Content-Type': 'application/json',
            'X-Inbox-Secret': credentials.secret,
        };

        const options = {
            method: 'POST',
            headers,
            body: JSON.stringify({ topics, mode: 'stream' }),
        };
        if (signal) options.signal = signal;

        const response = await fetch(`/${credentials.ns}/subscribe`, options);
        if (!response.ok) {
            const error = await response.json().catch(() => ({ detail: response.statusText }));
            throw new Error(error.detail || 'Subscribe stream failed');
        }
        return response;
    },
};

// Export for use in other modules
window.DeadropAPI = DeadropAPI;


/**
 * SubscriptionManager: manages a persistent SSE subscription with
 * automatic reconnection, cursor tracking, and event dispatch.
 */
class SubscriptionManager {
    constructor(credentials) {
        this.credentials = credentials;
        this.cursors = this._loadCursors();
        this.abortController = null;
        this.running = false;
        this.reconnectDelay = 1000;  // Start at 1s, exponential backoff
        this.maxReconnectDelay = 30000;
        this.onEvent = null;  // Callback: (topic, latestMid) => void
        this.onStatusChange = null;  // Callback: (status) => void
    }

    /**
     * Get localStorage key for cursors.
     */
    _cursorKey() {
        return `deadrop_cursors_${this.credentials.ns}_${this.credentials.id}`;
    }

    /**
     * Load cursors from localStorage.
     */
    _loadCursors() {
        try {
            const stored = localStorage.getItem(this._cursorKey());
            return stored ? JSON.parse(stored) : {};
        } catch (e) {
            return {};
        }
    }

    /**
     * Save cursors to localStorage.
     */
    _saveCursors() {
        try {
            localStorage.setItem(this._cursorKey(), JSON.stringify(this.cursors));
        } catch (e) {
            console.warn('Failed to save cursors:', e);
        }
    }

    /**
     * Update cursor for a topic.
     */
    updateCursor(topic, mid) {
        if (!this.cursors[topic] || mid > this.cursors[topic]) {
            this.cursors[topic] = mid;
            this._saveCursors();
        }
    }

    /**
     * Build the topics map for subscription from current state.
     * @param {string[]} roomIds - Room IDs to subscribe to
     * @param {boolean} includeInbox - Whether to include own inbox
     */
    buildTopics(roomIds = [], includeInbox = true) {
        const topics = {};
        if (includeInbox) {
            const inboxTopic = `inbox:${this.credentials.id}`;
            topics[inboxTopic] = this.cursors[inboxTopic] || null;
        }
        for (const roomId of roomIds) {
            const roomTopic = `room:${roomId}`;
            topics[roomTopic] = this.cursors[roomTopic] || null;
        }
        return topics;
    }

    /**
     * Start the SSE subscription loop with automatic reconnection.
     * Falls back to poll mode if SSE fails.
     * 
     * @param {object} topics - Initial topics map
     */
    async start(topics) {
        if (this.running) this.stop();
        this.running = true;
        this.reconnectDelay = 1000;

        // Try SSE first, fall back to poll
        while (this.running) {
            try {
                if (this.onStatusChange) this.onStatusChange('connecting');
                await this._runSSE(topics);
            } catch (e) {
                if (!this.running) break;
                console.warn('SSE failed, trying poll fallback:', e.message);
                try {
                    await this._runPollLoop(topics);
                } catch (pollErr) {
                    if (!this.running) break;
                    console.error('Poll also failed:', pollErr.message);
                }
            }

            if (!this.running) break;

            // Reconnect with backoff
            if (this.onStatusChange) this.onStatusChange('reconnecting');
            await new Promise(r => setTimeout(r, this.reconnectDelay));
            this.reconnectDelay = Math.min(this.reconnectDelay * 2, this.maxReconnectDelay);

            // Refresh topics with latest cursors
            topics = this._refreshTopics(topics);
        }
    }

    /**
     * Refresh topic cursors from our stored state.
     */
    _refreshTopics(topics) {
        const refreshed = {};
        for (const key of Object.keys(topics)) {
            refreshed[key] = this.cursors[key] || null;
        }
        return refreshed;
    }

    /**
     * Run an SSE stream until disconnect or error.
     */
    async _runSSE(topics) {
        this.abortController = new AbortController();
        const response = await DeadropAPI.subscribeStream(
            this.credentials, topics, this.abortController.signal
        );

        if (this.onStatusChange) this.onStatusChange('connected');
        this.reconnectDelay = 1000;  // Reset backoff on successful connect

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        try {
            while (this.running) {
                const { done, value } = await reader.read();
                if (done) break;

                buffer += decoder.decode(value, { stream: true });
                const events = this._parseSSE(buffer);
                buffer = events.remaining;

                for (const event of events.parsed) {
                    if (event.type === 'change' && event.data) {
                        try {
                            const data = JSON.parse(event.data);
                            if (data.topic && data.latest_mid) {
                                this.updateCursor(data.topic, data.latest_mid);
                                if (this.onEvent) this.onEvent(data.topic, data.latest_mid);
                            }
                        } catch (e) {
                            console.warn('Failed to parse SSE event data:', e);
                        }
                    }
                }
            }
        } finally {
            reader.releaseLock();
        }
    }

    /**
     * Parse SSE events from a buffer.
     * Returns {parsed: [{type, data}], remaining: string}
     */
    _parseSSE(buffer) {
        const parsed = [];
        const blocks = buffer.split('\n\n');
        const remaining = blocks.pop();  // Last incomplete block

        for (const block of blocks) {
            if (!block.trim()) continue;
            const event = { type: 'message', data: '' };
            for (const line of block.split('\n')) {
                if (line.startsWith('event: ')) {
                    event.type = line.substring(7).trim();
                } else if (line.startsWith('data: ')) {
                    event.data = line.substring(6);
                }
            }
            parsed.push(event);
        }

        return { parsed, remaining };
    }

    /**
     * Run a poll loop as fallback.
     */
    async _runPollLoop(topics) {
        if (this.onStatusChange) this.onStatusChange('polling');
        this.reconnectDelay = 1000;

        while (this.running) {
            try {
                const currentTopics = this._refreshTopics(topics);
                const result = await DeadropAPI.subscribePoll(
                    this.credentials, currentTopics, 30
                );

                if (!this.running) break;

                if (result.events && !result.timeout) {
                    for (const [topic, mid] of Object.entries(result.events)) {
                        this.updateCursor(topic, mid);
                        if (this.onEvent) this.onEvent(topic, mid);
                    }
                }
            } catch (e) {
                if (!this.running) break;
                throw e;  // Let outer loop handle reconnection
            }
        }
    }

    /**
     * Stop the subscription.
     */
    stop() {
        this.running = false;
        if (this.abortController) {
            this.abortController.abort();
            this.abortController = null;
        }
        if (this.onStatusChange) this.onStatusChange('disconnected');
    }
}

window.SubscriptionManager = SubscriptionManager;
