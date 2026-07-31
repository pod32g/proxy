// The proxy's API base. Served by cmd/webserver at /config.js so this page can
// point at a proxy running elsewhere; falls back to same-origin.
const API = (window.PROXY_API_BASE || '').replace(/\/$/, '');
const api = path => API + path;

// Every value below — header names, header values, hostnames — is attacker- or
// operator-supplied and reaches this page unescaped from a JSON API. Rows are
// therefore built as DOM nodes with textContent rather than concatenated into
// innerHTML, which would turn a stored `<img onerror=...>` into script.
function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
}

function replace(id, ...children) {
    const host = document.getElementById(id);
    if (!host) return;
    host.replaceChildren(...children);
}

document.addEventListener('DOMContentLoaded', () => {
    loadHeaders();
    loadLogLevel();
    loadStats();

    document.getElementById('addHeader').addEventListener('submit', e => {
        e.preventDefault();
        const data = Object.fromEntries(new FormData(e.target).entries());
        fetch(api('/api/headers'), {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        }).then(() => { e.target.reset(); loadHeaders(); });
    });

    document.getElementById('loglevel').addEventListener('change', e => {
        fetch(api('/api/loglevel'), {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({level: e.target.value})
        });
    });
});

function loadHeaders() {
    fetch(api('/api/headers')).then(r => r.json()).then(data => {
        const table = el('table', undefined, 'table');
        const head = el('thead');
        const headRow = el('tr');
        headRow.append(el('th', 'Name'), el('th', 'Value'));
        head.appendChild(headRow);
        const body = el('tbody');
        for (const [k, v] of Object.entries(data.global || {})) {
            const row = el('tr');
            row.append(el('td', k), el('td', v));
            body.appendChild(row);
        }
        table.append(head, body);
        replace('headers', table);
    }).catch(() => replace('headers', el('p', 'Could not reach the proxy API.')));
}

function loadLogLevel() {
    fetch(api('/api/loglevel')).then(r => r.json()).then(data => {
        const sel = document.getElementById('loglevel');
        sel.replaceChildren(...['DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL'].map(l => {
            const opt = el('option', l);
            opt.selected = l === data.level;
            return opt;
        }));
    }).catch(() => {});
}

function loadStats() {
    fetch(api('/api/stats')).then(r => r.json()).then(data => {
        if (!data.enabled || !data.top) return;
        const list = el('ul', undefined, 'list-group');
        for (const s of data.top) {
            const item = el('li', undefined, 'list-group-item d-flex justify-content-between');
            item.append(el('span', s.Host), el('span', s.Count));
            list.appendChild(item);
        }
        replace('stats', el('h2', 'Top Hosts'), list);
    }).catch(() => {});
}
