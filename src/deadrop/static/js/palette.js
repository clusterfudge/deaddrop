/**
 * Command palette and keyboard shortcuts for the web app.
 *
 * Everything here is inert unless the pointer is a fine one with hover
 * (`(hover: hover) and (pointer: fine)`), so a touch device never sees a
 * key handler. The check runs per event rather than once at load, so a
 * device that gains or loses a mouse is handled without a reload.
 *
 * Actions are built from the state the app already holds — `rooms`,
 * `peers`, `CredentialStore` — and invoke the same entry points the click
 * handlers use (`openRoom`, `openConversation`, `openNamespace`). No new
 * endpoints, no second copy of navigation logic.
 */
(function () {
    'use strict';

    const DESKTOP_QUERY = '(hover: hover) and (pointer: fine)';
    const SEQUENCE_MS = 800;

    function isDesktopInput() {
        return window.matchMedia(DESKTOP_QUERY).matches;
    }

    function isTextEntry(el) {
        if (!el) return false;
        if (el.isContentEditable) return true;
        const tag = el.tagName;
        return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT';
    }

    function esc(text) {
        const d = document.createElement('div');
        d.textContent = text == null ? '' : String(text);
        return d.innerHTML;
    }

    // ==================== FUZZY MATCHING ====================

    /**
     * Subsequence match of `query` against `text`.
     *
     * Returns null when a character is missing, otherwise a score and the
     * matched character offsets. Adjacent matches and matches at a word
     * boundary score higher; longer labels are nudged down so an exact
     * short label outranks a long one containing the same run.
     */
    function fuzzyMatch(text, query) {
        const hay = String(text).toLowerCase();
        const needle = String(query).toLowerCase().replace(/\s+/g, '');
        if (!needle) return { score: 0, hits: [] };

        let from = 0;
        let prev = -2;
        let score = 0;
        const hits = [];
        for (const ch of needle) {
            const idx = hay.indexOf(ch, from);
            if (idx === -1) return null;
            score += idx === prev + 1 ? 4 : 1;
            if (idx === 0 || /[\s\-_/:.]/.test(hay[idx - 1])) score += 3;
            hits.push(idx);
            prev = idx;
            from = idx + 1;
        }
        return { score: score - hay.length * 0.01, hits };
    }

    function highlight(text, hits) {
        const set = new Set(hits);
        return String(text)
            .split('')
            .map((ch, i) => (set.has(i) ? '<mark>' + esc(ch) + '</mark>' : esc(ch)))
            .join('');
    }

    // ==================== ACTIONS ====================

    /** Build the action list from state already in memory. */
    function buildActions() {
        const actions = [];
        const creds = credentials;
        const slug = currentSlug;

        (rooms || []).forEach(function (room) {
            actions.push({
                group: 'Rooms',
                icon: '💬',
                label: room.display_name || 'Unnamed Room',
                hint: (room.member_count || '?') + ' members',
                run: function () { openRoom(room.room_id); },
            });
        });

        (peers || [])
            .filter(function (p) { return !creds || p.id !== creds.id; })
            .forEach(function (peer) {
                actions.push({
                    group: 'People',
                    icon: '👤',
                    label: peer.metadata?.display_name || peer.id.substring(0, 8),
                    hint: 'Open conversation',
                    run: function () { openConversation(peer.id); },
                });
            });

        (CredentialStore.listNamespaces() || [])
            .filter(function (ns) { return (ns.slug || ns.ns) !== slug; })
            .forEach(function (ns) {
                actions.push({
                    group: 'Namespaces',
                    icon: '📬',
                    label: ns.displayName || ns.slug || ns.ns.substring(0, 8),
                    hint: 'Switch namespace',
                    run: function () { openNamespace(ns.slug || ns.ns); },
                });
            });

        if (slug && creds) {
            actions.push({
                group: 'Commands',
                icon: '✏️',
                label: 'Compose new message',
                hint: 'c',
                run: function () { showCompose(); },
            });
            actions.push({
                group: 'Commands',
                icon: '📥',
                label: 'Go to inbox',
                hint: 'g then i',
                run: function () { openNamespace(slug); },
            });
            actions.push({
                group: 'Commands',
                icon: '📦',
                label: 'Go to archived messages',
                run: function () { document.getElementById('archived-link').click(); },
            });
        }
        actions.push({
            group: 'Commands',
            icon: '🏠',
            label: 'Go to namespace list',
            hint: 'g then h',
            run: goHome,
        });
        actions.push({
            group: 'Commands',
            icon: '🎨',
            label: 'Toggle theme',
            run: function () { cycleTheme(); },
        });
        actions.push({
            group: 'Commands',
            icon: '⌨️',
            label: 'Keyboard shortcuts',
            hint: '?',
            run: openHelp,
        });
        return actions;
    }

    function goHome() {
        navigate('/app');
        window.dispatchEvent(new PopStateEvent('popstate'));
    }

    // ==================== PALETTE ====================

    let allActions = [];
    let results = [];
    let cursor = 0;

    function paletteEl() { return document.getElementById('command-palette'); }
    function isPaletteOpen() { return !paletteEl().classList.contains('hidden'); }

    function openPalette() {
        if (!isDesktopInput()) return;
        allActions = buildActions();
        const el = paletteEl();
        el.classList.remove('hidden');
        el.setAttribute('aria-hidden', 'false');
        const input = document.getElementById('palette-input');
        input.value = '';
        renderResults('');
        input.focus();
    }

    function closePalette() {
        const el = paletteEl();
        el.classList.add('hidden');
        el.setAttribute('aria-hidden', 'true');
        document.getElementById('palette-input').blur();
    }

    function renderResults(query) {
        results = allActions
            .map(function (a) {
                const m = fuzzyMatch(a.label + ' ' + a.group, query);
                return m === null ? null : { action: a, score: m.score, hits: fuzzyMatch(a.label, query)?.hits || [] };
            })
            .filter(Boolean);
        if (query) results.sort(function (a, b) { return b.score - a.score; });
        cursor = 0;

        const list = document.getElementById('palette-results');
        if (results.length === 0) {
            list.innerHTML = '<li class="palette-empty">No matching actions</li>';
            return;
        }
        list.innerHTML = results
            .map(function (r, i) {
                return (
                    '<li class="palette-item' + (i === cursor ? ' selected' : '') + '"' +
                    ' role="option" data-index="' + i + '" aria-selected="' + (i === cursor) + '">' +
                    '<span class="palette-icon">' + esc(r.action.icon || '') + '</span>' +
                    '<span class="palette-label">' + highlight(r.action.label, r.hits) + '</span>' +
                    '<span class="palette-group">' + esc(r.action.group) + '</span>' +
                    (r.action.hint ? '<span class="palette-hint">' + esc(r.action.hint) + '</span>' : '') +
                    '</li>'
                );
            })
            .join('');
    }

    function moveCursor(delta) {
        if (results.length === 0) return;
        cursor = (cursor + delta + results.length) % results.length;
        const items = document.querySelectorAll('#palette-results .palette-item');
        items.forEach(function (el, i) {
            el.classList.toggle('selected', i === cursor);
            el.setAttribute('aria-selected', String(i === cursor));
        });
        items[cursor]?.scrollIntoView({ block: 'nearest' });
    }

    function runSelected() {
        const chosen = results[cursor];
        if (!chosen) return;
        closePalette();
        chosen.action.run();
    }

    // ==================== HELP OVERLAY ====================

    function helpEl() { return document.getElementById('shortcuts-help'); }
    function isHelpOpen() { return !helpEl().classList.contains('hidden'); }

    function openHelp() {
        if (!isDesktopInput()) return;
        helpEl().classList.remove('hidden');
        helpEl().setAttribute('aria-hidden', 'false');
    }

    function closeHelp() {
        helpEl().classList.add('hidden');
        helpEl().setAttribute('aria-hidden', 'true');
    }

    // ==================== LIST NAVIGATION ====================

    const LIST_SELECTORS = {
        'view-inbox': '#thread-list .thread-item',
        'view-namespaces': '#namespace-list .card-clickable',
    };

    /** Items of the visible list view, or [] when the view has no list. */
    function navItems() {
        for (const [viewId, selector] of Object.entries(LIST_SELECTORS)) {
            const view = document.getElementById(viewId);
            if (view && !view.classList.contains('hidden')) {
                return Array.from(document.querySelectorAll(selector));
            }
        }
        return [];
    }

    function moveSelection(delta) {
        const items = navItems();
        if (items.length === 0) return;
        let idx = items.findIndex(function (el) { return el.classList.contains('kbd-selected'); });
        idx = idx === -1 ? (delta > 0 ? 0 : items.length - 1) : (idx + delta + items.length) % items.length;
        items.forEach(function (el) { el.classList.remove('kbd-selected'); });
        items[idx].classList.add('kbd-selected');
        items[idx].scrollIntoView({ block: 'nearest' });
    }

    function openSelection() {
        const selected = navItems().find(function (el) { return el.classList.contains('kbd-selected'); });
        if (selected) selected.click();
    }

    // ==================== ESCAPE STACK ====================

    /** Close the topmost open overlay. Returns true when something closed. */
    function closeTopmost() {
        if (isPaletteOpen()) { closePalette(); return true; }
        if (isHelpOpen()) { closeHelp(); return true; }
        const lightbox = document.getElementById('image-lightbox');
        if (lightbox && !lightbox.classList.contains('hidden')) { closeLightbox(); return true; }
        const paste = document.getElementById('paste-attach-modal');
        if (paste && !paste.classList.contains('hidden')) { closePasteAttachDialog(); return true; }
        const compose = document.getElementById('compose-modal');
        if (compose && !compose.classList.contains('hidden')) { hideCompose(); return true; }
        const replyPreview = document.getElementById('room-reply-preview');
        if (replyPreview && !replyPreview.classList.contains('hidden')) { cancelReply(); return true; }
        return false;
    }

    // ==================== KEY HANDLING ====================

    let pendingSequence = null;
    let pendingTimer = null;

    function armSequence(key) {
        pendingSequence = key;
        clearTimeout(pendingTimer);
        pendingTimer = setTimeout(function () { pendingSequence = null; }, SEQUENCE_MS);
    }

    function clearSequence() {
        pendingSequence = null;
        clearTimeout(pendingTimer);
    }

    function onKeyDown(e) {
        if (!isDesktopInput()) return;

        // The palette hotkey is the one binding that works from a composer.
        if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
            e.preventDefault();
            isPaletteOpen() ? closePalette() : openPalette();
            return;
        }

        if (isPaletteOpen()) {
            if (e.key === 'Escape') { e.preventDefault(); closePalette(); }
            else if (e.key === 'ArrowDown') { e.preventDefault(); moveCursor(1); }
            else if (e.key === 'ArrowUp') { e.preventDefault(); moveCursor(-1); }
            else if (e.key === 'Enter') { e.preventDefault(); runSelected(); }
            return;
        }

        if (e.key === 'Escape') {
            if (closeTopmost()) { e.preventDefault(); return; }
            if (isTextEntry(document.activeElement)) document.activeElement.blur();
            return;
        }

        if (e.altKey || e.ctrlKey || e.metaKey) return;
        if (isTextEntry(document.activeElement)) return;

        if (pendingSequence === 'g') {
            clearSequence();
            if (e.key === 'i') { e.preventDefault(); const s = currentSlug; if (s) openNamespace(s); return; }
            if (e.key === 'h') { e.preventDefault(); goHome(); return; }
            return;
        }

        switch (e.key) {
            case '?':
                e.preventDefault();
                isHelpOpen() ? closeHelp() : openHelp();
                break;
            case 'g':
                armSequence('g');
                break;
            case 'j':
            case 'ArrowDown':
                if (navItems().length) { e.preventDefault(); moveSelection(1); }
                break;
            case 'k':
            case 'ArrowUp':
                if (navItems().length) { e.preventDefault(); moveSelection(-1); }
                break;
            case 'Enter':
                openSelection();
                break;
            case 'c': {
                const s = currentSlug;
                if (s && credentials) { e.preventDefault(); showCompose(); }
                break;
            }
        }
    }

    // ==================== WIRING ====================

    document.addEventListener('keydown', onKeyDown);

    document.addEventListener('DOMContentLoaded', function () {
        document.getElementById('palette-input').addEventListener('input', function (e) {
            renderResults(e.target.value);
        });
        document.getElementById('palette-results').addEventListener('click', function (e) {
            const item = e.target.closest('.palette-item');
            if (!item) return;
            cursor = Number(item.dataset.index);
            runSelected();
        });
        paletteEl().addEventListener('click', function (e) {
            if (e.target === paletteEl()) closePalette();
        });
        document.getElementById('shortcuts-close').addEventListener('click', closeHelp);
        helpEl().addEventListener('click', function (e) {
            if (e.target === helpEl()) closeHelp();
        });
    });

    window.DeadropPalette = {
        open: openPalette,
        close: closePalette,
        isOpen: isPaletteOpen,
        openHelp: openHelp,
        closeHelp: closeHelp,
        isHelpOpen: isHelpOpen,
        isDesktopInput: isDesktopInput,
        fuzzyMatch: fuzzyMatch,
        buildActions: buildActions,
        results: function () { return results.map(function (r) { return r.action.label; }); },
    };
})();
