/**
 * Credential storage manager for Deadrop web app.
 * Stores namespace and identity credentials in localStorage.
 */

const STORAGE_KEY = 'deadrop_credentials';
const STORAGE_VERSION = 1;

const CredentialStore = {
    /**
     * Get all stored credential data.
     */
    getAll() {
        const data = localStorage.getItem(STORAGE_KEY);
        if (!data) {
            return { version: STORAGE_VERSION, namespaces: {} };
        }
        try {
            const parsed = JSON.parse(data);
            // Handle version upgrades if needed
            if (parsed.version !== STORAGE_VERSION) {
                // Future: handle migrations
            }
            return parsed;
        } catch (e) {
            console.error('Failed to parse credentials:', e);
            return { version: STORAGE_VERSION, namespaces: {} };
        }
    },

    /**
     * Save all credential data.
     */
    save(data) {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
    },

    /**
     * Add credentials from invite redemption.
     * 
     * @param {string} ns - Namespace ID (hash)
     * @param {string} slug - Human-readable namespace slug
     * @param {string} nsDisplayName - Namespace display name
     * @param {number} ttlHours - Namespace TTL in hours (0 = persistent)
     * @param {object} identity - Identity object with id, secret, displayName
     */
    addIdentity(ns, slug, nsDisplayName, ttlHours, identity) {
        const data = this.getAll();
        
        // Use slug as key, fallback to ns if no slug
        const key = slug || ns;
        
        if (!data.namespaces[key]) {
            data.namespaces[key] = {
                ns,
                slug,
                displayName: nsDisplayName,
                ttlHours: ttlHours || 24,
                identities: {},
                activeIdentity: null,
            };
        }
        
        data.namespaces[key].identities[identity.id] = {
            id: identity.id,
            secret: identity.secret,
            displayName: identity.displayName,
            addedAt: new Date().toISOString(),
        };
        
        // Set as active if first identity
        if (!data.namespaces[key].activeIdentity) {
            data.namespaces[key].activeIdentity = identity.id;
        }
        
        this.save(data);
        return data.namespaces[key];
    },

    /**
     * Get namespace by slug.
     */
    getNamespace(slug) {
        const data = this.getAll();
        return data.namespaces[slug] || null;
    },

    /**
     * List all namespaces.
     */
    listNamespaces() {
        const data = this.getAll();
        return Object.values(data.namespaces).map(ns => ({
            ns: ns.ns,
            slug: ns.slug,
            displayName: ns.displayName,
            ttlHours: ns.ttlHours,
            identityCount: Object.keys(ns.identities).length,
            activeIdentity: ns.identities[ns.activeIdentity] || null,
        }));
    },

    /**
     * Get credentials for API calls.
     * 
     * @param {string} slug - Namespace slug
     * @param {string} identityId - Optional specific identity ID
     * @returns {object|null} Credentials object with ns, id, secret
     */
    getCredentials(slug, identityId = null) {
        const data = this.getAll();
        const ns = data.namespaces[slug];
        if (!ns) return null;
        
        const id = identityId || ns.activeIdentity;
        const identity = id ? ns.identities[id] : Object.values(ns.identities)[0];
        
        if (!identity) return null;
        
        return {
            ns: ns.ns,
            slug: ns.slug,
            ttlHours: ns.ttlHours,
            id: identity.id,
            secret: identity.secret,
            displayName: identity.displayName,
        };
    },

    /**
     * Set active identity for a namespace.
     */
    setActiveIdentity(slug, identityId) {
        const data = this.getAll();
        if (data.namespaces[slug] && data.namespaces[slug].identities[identityId]) {
            data.namespaces[slug].activeIdentity = identityId;
            this.save(data);
            return true;
        }
        return false;
    },

    /**
     * Remove an identity from a namespace.
     */
    removeIdentity(slug, identityId) {
        const data = this.getAll();
        const ns = data.namespaces[slug];
        if (!ns || !ns.identities[identityId]) return false;
        
        delete ns.identities[identityId];
        
        // Update active identity if needed
        if (ns.activeIdentity === identityId) {
            const remaining = Object.keys(ns.identities);
            ns.activeIdentity = remaining.length > 0 ? remaining[0] : null;
        }
        
        // Remove namespace if no identities left
        if (Object.keys(ns.identities).length === 0) {
            delete data.namespaces[slug];
        }
        
        this.save(data);
        return true;
    },

    /**
     * Remove entire namespace and all identities.
     */
    removeNamespace(slug) {
        const data = this.getAll();
        if (data.namespaces[slug]) {
            delete data.namespaces[slug];
            this.save(data);
            return true;
        }
        return false;
    },

    /**
     * Check if we have any stored credentials.
     */
    hasCredentials() {
        const data = this.getAll();
        return Object.keys(data.namespaces).length > 0;
    },

    /**
     * Clear all stored credentials.
     */
    clear() {
        localStorage.removeItem(STORAGE_KEY);
    },
};

// Export for use in other modules
window.CredentialStore = CredentialStore;
