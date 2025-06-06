document.addEventListener('DOMContentLoaded', () => {
    loadHeaders();
    loadLogLevel();
    loadStats();

    document.getElementById('addHeader').addEventListener('submit', e => {
        e.preventDefault();
        const data = Object.fromEntries(new FormData(e.target).entries());
        fetch('/api/headers', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        }).then(() => { e.target.reset(); loadHeaders(); });
    });

    document.getElementById('loglevel').addEventListener('change', e => {
        fetch('/api/loglevel', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({level: e.target.value})
        });
    });
});

function loadHeaders() {
    fetch('/api/headers').then(r => r.json()).then(data => {
        let html = '<table class="table"><thead><tr><th>Name</th><th>Value</th></tr></thead><tbody>';
        for (const [k,v] of Object.entries(data.global)) {
            html += `<tr><td>${k}</td><td>${v}</td></tr>`;
        }
        html += '</tbody></table>';
        document.getElementById('headers').innerHTML = html;
    });
}

function loadLogLevel() {
    fetch('/api/loglevel').then(r => r.json()).then(data => {
        const sel = document.getElementById('loglevel');
        const levels = ['DEBUG','INFO','WARN','ERROR','FATAL'];
        sel.innerHTML = levels.map(l => `<option${l===data.level?' selected':''}>${l}</option>`).join('');
    });
}

function loadStats() {
    fetch('/api/stats').then(r => r.json()).then(data => {
        if (!data.enabled || !data.top) return;
        let html = '<h2>Top Hosts</h2><ul class="list-group">';
        for (const s of data.top) {
            html += `<li class="list-group-item d-flex justify-content-between"><span>${s.Host}</span><span>${s.Count}</span></li>`;
        }
        html += '</ul>';
        document.getElementById('stats').innerHTML = html;
    });
}
