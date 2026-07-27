let currentView = 'overview';
let currentModalCallback = null;

async function api(path) {
  const resp = await fetch(path);
  return resp.json();
}

function escapeHtml(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function formatTime(iso) {
  if (!iso) return '—';
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

function truncate(s, n) {
  if (!s) return '';
  return s.length > n ? s.substring(0, n) + '...' : s;
}

// ── Navigation ────────────────────────────────────────────────────────

function showView(view) {
  currentView = view;
  document.querySelectorAll('.nav a').forEach(a =>
    a.classList.toggle('active', a.dataset.view === view));
  ['overview', 'incidents', 'snapshots'].forEach(v => {
    document.getElementById(v + '-view').style.display = v === view ? 'block' : 'none';
  });
  if (view === 'overview') renderOverview();
  if (view === 'incidents') renderIncidents();
  if (view === 'snapshots') renderSnapshots();
}

// ── Modal ─────────────────────────────────────────────────────────────

function openModal(title, content) {
  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-body').innerHTML = content;
  document.getElementById('modal-overlay').classList.add('open');
}

function closeModal() {
  document.getElementById('modal-overlay').classList.remove('open');
}

// ── Overview ──────────────────────────────────────────────────────────

async function renderOverview() {
  const el = document.getElementById('overview-content');
  el.innerHTML = '<div class="loading">Loading...</div>';
  try {
    const stats = await api('/api/stats');
    const verdictHtml = Object.entries(stats.verdict_summary || {})
      .map(([k,v]) => `<span class="status-badge status-${k === 'FAIL' ? 'fail' : k === 'WARNING' ? 'warning' : 'pass'}" style="margin-right:4px">${k}: ${v}</span>`)
      .join('') || '<span style="color:var(--text-dim)">None</span>';

    el.innerHTML = `
      <div class="cards">
        <div class="card">
          <div class="label">Total Incidents</div>
          <div class="value">${stats.total_incidents || 0}</div>
        </div>
        <div class="card">
          <div class="label">Snapshots</div>
          <div class="value">${stats.total_snapshots || 0}</div>
        </div>
        <div class="card">
          <div class="label">Daemon</div>
          <div class="value daemon-badge">
            <span class="daemon-dot ${stats.daemon_running ? 'daemon-active' : 'daemon-stopped'}"></span>
            ${stats.daemon_running ? 'Running' : 'Stopped'}
          </div>
        </div>
        <div class="card">
          <div class="label">Verdicts</div>
          <div class="value" style="font-size:14px">${verdictHtml}</div>
        </div>
      </div>
      <div class="section"><h2>Recent Incidents</h2><div id="recent-incidents"></div></div>
    `;
    const data = await api('/api/incidents');
    const incidents = (data.incidents || []).slice(0, 10);
    document.getElementById('recent-incidents').innerHTML = incidents.length
      ? buildIncidentTable(incidents)
      : '<div class="detail-panel"><p style="color:var(--text-dim)">No incidents recorded yet.</p></div>';
  } catch (e) {
    el.innerHTML = `<div class="detail-panel"><p style="color:var(--red)">Error: ${escapeHtml(e.message)}</p></div>`;
  }
}

// ── Incidents View ────────────────────────────────────────────────────

async function renderIncidents() {
  const el = document.getElementById('incidents-content');
  el.innerHTML = '<div class="loading">Loading...</div>';
  try {
    const data = await api('/api/incidents');
    el.innerHTML = (data.incidents || []).length
      ? buildIncidentTable(data.incidents)
      : '<div class="empty-state">No incidents recorded yet.</div>';
  } catch (e) {
    el.innerHTML = `<p style="color:var(--red)">Error: ${escapeHtml(e.message)}</p>`;
  }
}

function buildIncidentTable(incidents) {
  let table = `<table><thead><tr>
    <th>ID</th><th>Time</th><th>Verdict</th><th>Severity</th><th>Summary</th>
  </tr></thead><tbody>`;
  for (const inc of incidents) {
    const sv = inc.verdict || '';
    const badgeClass = sv.startsWith('FAIL') ? 'fail' : sv.startsWith('WARNING') ? 'warning' : 'pass';
    const sevParts = [];
    const sc = inc.severity_counts || {};
    if (sc.critical) sevParts.push(`<span class="severity-dot dot-critical"></span>${sc.critical}`);
    if (sc.suspicious) sevParts.push(`<span class="severity-dot dot-suspicious"></span>${sc.suspicious}`);
    if (sc.info) sevParts.push(`<span class="severity-dot dot-info"></span>${sc.info}`);
    table += `<tr onclick="showIncidentDetail('${escapeHtml(inc.id)}')" style="cursor:pointer">
      <td><strong>${escapeHtml(inc.id || '?')}</strong></td>
      <td>${formatTime(inc.timestamp)}</td>
      <td><span class="status-badge status-${badgeClass}">${truncate(sv, 30)}</span></td>
      <td>${sevParts.join(' ') || '—'}</td>
      <td>${escapeHtml(truncate(inc.summary, 60))}</td>
    </tr>`;
  }
  table += '</tbody></table>';
  return table;
}

async function showIncidentDetail(id) {
  try {
    const data = await api('/api/incidents');
    const inc = (data.incidents || []).find(i => i.id === id);
    if (!inc) { openModal('Incident ' + id, '<p>Not found</p>'); return; }

    const sc = inc.severity_counts || {};
    let html = `<table><tr><th>Field</th><th>Value</th></tr>
      <tr><td>ID</td><td><strong>${escapeHtml(inc.id)}</strong></td></tr>
      <tr><td>Time</td><td>${formatTime(inc.timestamp)}</td></tr>
      <tr><td>Verdict</td><td>${escapeHtml(inc.verdict)}</td></tr>
      <tr><td>Critical</td><td>${sc.critical || 0}</td></tr>
      <tr><td>Suspicious</td><td>${sc.suspicious || 0}</td></tr>
      <tr><td>Info</td><td>${sc.info || 0}</td></tr>
      <tr><td>Findings</td><td>${inc.findings_count || 0}</td></tr>
      <tr><td>Command</td><td style="font-family:monospace;font-size:12px">${escapeHtml(inc.command || '—')}</td></tr>
      <tr><td>Summary</td><td>${escapeHtml(inc.summary || '')}</td></tr>
      <tr><td>Pre Snapshot</td><td style="font-size:12px;word-break:break-all">${escapeHtml(inc.pre_snapshot || '')}</td></tr>
      <tr><td>Post Snapshot</td><td style="font-size:12px;word-break:break-all">${escapeHtml(inc.post_snapshot || '')}</td></tr>
    </table>`;
    if (inc.model_dirs && inc.model_dirs.length) {
      html += `<h3 style="margin-top:12px">Model Dirs</h3><p style="font-size:13px">${inc.model_dirs.join(', ')}</p>`;
    }
    openModal('Incident ' + inc.id, html);
  } catch (e) {
    openModal('Error', `<p style="color:var(--red)">${escapeHtml(e.message)}</p>`);
  }
}

// ── Snapshots View ────────────────────────────────────────────────────

async function renderSnapshots() {
  const el = document.getElementById('snapshots-content');
  el.innerHTML = '<div class="loading">Loading...</div>';
  try {
    const data = await api('/api/snapshots');
    const snaps = data.snapshots || [];
    if (!snaps.length) {
      el.innerHTML = '<div class="empty-state">No snapshots yet. Run <code>sentinel snapshot</code> to create one.</div>';
      return;
    }
    let table = `<table><thead><tr>
      <th>Label</th><th>Timestamp</th><th>Files</th><th>Processes</th><th>Hash</th><th>Path</th>
    </tr></thead><tbody>`;
    for (const s of snaps) {
      table += `<tr onclick="showSnapshotDetail('${escapeHtml(s.path)}')" style="cursor:pointer">
        <td>${escapeHtml(s.label || '—')}</td>
        <td>${formatTime(s.timestamp)}</td>
        <td>${s.file_count || 0}</td>
        <td>${s.process_count || 0}</td>
        <td style="font-family:monospace;font-size:11px">${escapeHtml(s.manifest_hash || '')}</td>
        <td style="font-size:11px;color:var(--text-dim)">${escapeHtml(truncate(s.path, 50))}</td>
      </tr>`;
    }
    table += '</tbody></table>';
    el.innerHTML = table;
  } catch (e) {
    el.innerHTML = `<p style="color:var(--red)">Error: ${escapeHtml(e.message)}</p>`;
  }
}

async function showSnapshotDetail(path) {
  try {
    const data = await api('/api/snapshot/' + encodeURIComponent(path));
    const snap = data.snapshot;
    if (!snap) { openModal('Snapshot', '<p>Not found</p>'); return; }

    const meta = snap.meta || {};
    const files = snap.files || {};
    const totalFiles = Object.values(files).reduce((a, v) => a + (typeof v === 'object' ? Object.keys(v).length : 0), 0);

    let html = `<table><tr><th>Field</th><th>Value</th></tr>
      <tr><td>Label</td><td>${escapeHtml(meta.label || '')}</td></tr>
      <tr><td>Timestamp</td><td>${formatTime(meta.timestamp)}</td></tr>
      <tr><td>Hostname</td><td>${escapeHtml(meta.hostname || '')}</td></tr>
      <tr><td>Manifest Hash</td><td style="font-family:monospace;font-size:11px">${escapeHtml(meta.manifest_hash || '')}</td></tr>
      <tr><td>Files Tracked</td><td>${totalFiles}</td></tr>
      <tr><td>Processes</td><td>${Object.keys(snap.processes || {}).length}</td></tr>
      <tr><td>Services</td><td>${Object.keys(snap.services || {}).length}</td></tr>
    </table>`;

    // Show file categories
    const categories = ['critical', 'suspicious', 'user_config', 'extra'];
    let fileHtml = '<h3 style="margin-top:12px">File Categories</h3><table><tr><th>Category</th><th>Count</th></tr>';
    for (const cat of categories) {
      const count = files[cat] ? Object.keys(files[cat]).length : 0;
      if (count > 0) fileHtml += `<tr><td>${escapeHtml(cat)}</td><td>${count}</td></tr>`;
    }
    fileHtml += '</table>';
    html += fileHtml;

    // Show signature info if present
    if (meta.signature) {
      html += `<h3 style="margin-top:12px">Signature</h3>
        <p style="font-size:13px">Type: ${escapeHtml(meta.signature.type || '')}<br>
        Key ID: ${escapeHtml(meta.signature.key_id || '')}<br>
        File: ${escapeHtml(meta.signature.file || '')}</p>`;
    }

    openModal('Snapshot: ' + (meta.label || path.split('/').pop()), html);
  } catch (e) {
    openModal('Error', `<p style="color:var(--red)">${escapeHtml(e.message)}</p>`);
  }
}

// ── Init ──────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('modal-overlay').addEventListener('click', (e) => {
    if (e.target === document.getElementById('modal-overlay')) closeModal();
  });
  renderOverview();
});
