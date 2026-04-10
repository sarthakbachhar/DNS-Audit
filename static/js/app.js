/**
 * ISO 27001 Audit App — Frontend JavaScript
 * Handles: theme toggle, flash auto-dismiss, check card expansion, result filtering
 */

document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initThemeToggle();
    initFilterTabs();
    initFlashAutoDismiss();
});

/* ============================================================
   THEME — Light / Dark
   ============================================================ */
function initTheme() {
    const saved = localStorage.getItem('isoaudit-theme') || 'dark';
    document.documentElement.setAttribute('data-theme', saved);
}

function initThemeToggle() {
    const btn = document.getElementById('themeToggle');
    if (!btn) return;

    btn.addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme') || 'dark';
        const next = current === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('isoaudit-theme', next);
    });
}

/* ============================================================
   FILTER TABS (Results Page)
   ============================================================ */
function initFilterTabs() {
    const tabs = document.querySelectorAll('#filterTabs .filter-tab');
    if (!tabs.length) return;

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            const filter = tab.dataset.filter;
            const cards = document.querySelectorAll('.check-card');

            cards.forEach(card => {
                card.style.display =
                    (filter === 'all' || card.dataset.status === filter) ? '' : 'none';
            });

            // Hide control groups where all cards are hidden
            document.querySelectorAll('.control-group').forEach(group => {
                const visible = group.querySelectorAll('.check-card:not([style*="display: none"])');
                group.style.display = visible.length ? '' : 'none';
            });
        });
    });
}

/* ============================================================
   CHECK CARD TOGGLE (Results Page)
   ============================================================ */
function toggleCheck(header) {
    header.closest('.check-card').classList.toggle('expanded');
}

/* ============================================================
   FLASH AUTO-DISMISS
   ============================================================ */
function initFlashAutoDismiss() {
    document.querySelectorAll('.flash-message').forEach(flash => {
        setTimeout(() => dismissFlash(flash), 6000);
    });
}

function dismissFlash(el) {
    el.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
    el.style.opacity = '0';
    el.style.transform = 'translateX(10px)';
    setTimeout(() => el.remove(), 320);
}

/* ============================================================
   FLASH HELPER (for dynamic flash creation)
   ============================================================ */
function showFlash(message, category = 'info') {
    let container = document.querySelector('.flash-container');
    if (!container) {
        container = document.createElement('div');
        container.className = 'flash-container';
        document.body.appendChild(container);
    }

    const iconMap = {
        error:   '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
        success: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20,6 9,17 4,12"/></svg>',
        info:    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
        warning: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    };

    const flash = document.createElement('div');
    flash.className = `flash-message flash-${category}`;
    flash.innerHTML = `
        <span class="flash-icon">${iconMap[category] || iconMap.info}</span>
        <span class="flash-text">${escapeHtml(message)}</span>
        <button class="flash-close" onclick="this.closest('.flash-message').remove()">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
    `;
    container.appendChild(flash);
    setTimeout(() => dismissFlash(flash), 6000);
}

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}
