const API = 'http://localhost:8000';
let useMem = false, total = 0, start = Date.now();
let selAttk = 'prompt_injection', selTgtV = 'gpt-4', selProbeV = 'injection_resistance';
let garakP = ['injection'], pbA = ['textfooler'], curCVE = null;

// Initialize Marked.js
marked.setOptions({ breaks: true, gfm: true });
const renderer = new marked.Renderer();
renderer.code = function (code, lang) {
  const id = 'c' + Math.random().toString(36).slice(2, 6);
  const esc = code.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return `<pre><div class="ctop"><span class="clang">${lang || 'TEXT'}</span><button class="cpbtn" id="${id}" onclick="cp('${id}')">COPY</button></div><code id="${id}x">${esc}</code></pre>`;
};

const TITLES = { t: 'TERMINAL', c: 'CVE INTELLIGENCE', e: 'EXPLOIT ARCHITECT', r: 'RECON PLANNER', a: 'AI PENTESTING', m: 'MODEL AUDITOR' };

function sw(id) {
  document.querySelectorAll('.pane').forEach(p => p.classList.remove('on'));
  document.querySelectorAll('.nb').forEach(b => b.classList.remove('on'));
  document.getElementById('p-' + id).classList.add('on');
  document.getElementById('nb-' + id).classList.add('on');
  const tbt = document.getElementById('tbt');
  if (tbt) tbt.textContent = TITLES[id] || id.toUpperCase();
}

const MK = { ai_pentest: ['prompt injection', 'jailbreak', 'llm', 'ai bypass', 'model extraction', 'adversarial'], cve: ['cve', '0day', 'rce', 'lfi', 'sqli', 'xss', 'ssrf', 'xxe', 'buffer overflow', 'shellcode'], pentest: ['pentest', 'red team', 'privesc', 'privilege escalation', 'lateral movement', 'reverse shell', 'payload'], code: ['code', 'script', 'write a', 'function', 'def ', 'import ', 'bash', 'python', 'golang', 'debug'], analysis: ['analyze', 'scan', 'nmap', 'explain', 'research', 'enumerate', 'audit', 'what is', 'how does'] };
const MM = { ai_pentest: 'dolphin-mistral:7b', cve: 'dolphin-mistral:7b', pentest: 'dolphin-mistral:7b', code: 'hf.co/dphn/dolphin-2.9.3-mistral-nemo-12b-gguf:Q5_K_M', analysis: 'dolphin-mistral:7b', general: 'dolphin-mistral:7b' };
const MC = { ai_pentest: 'bp', cve: 'ba', pentest: 'br', code: 'bb', analysis: 'bg', general: 'bd' };

function detMode(p) { const t = p.toLowerCase(); for (const [m, kws] of Object.entries(MK)) if (kws.some(k => t.includes(k))) return m; return 'general' }

function oi(el) {
  const v = el.value.trim();
  document.getElementById('sbtn').disabled = !v;
  const mode = detMode(v || '');
  const mt = document.getElementById('mtag');
  mt.className = 'badge ' + (MC[mode] || 'bd');
  mt.textContent = mode.replace('_', ' ').toUpperCase();
  document.getElementById('mdltag').textContent = '→ ' + (document.getElementById('fm').value || MM[mode]);
}

function hk(e) { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') doSend() }
function sp(t) { const el = document.getElementById('ti'); el.value = t; oi(el); el.focus() }
function tmem() { useMem = !useMem; const b = document.getElementById('memtog'), l = document.getElementById('memlbl'); b.classList.toggle('on', useMem); l.textContent = useMem ? 'MEMORY ON' : 'MEMORY' }

function rmd(text, el) {
  el.classList.add('md');
  el.innerHTML = marked.parse(text, { renderer: renderer });
}

function cp(id) {
  const el = document.getElementById(id + 'x'), btn = document.getElementById(id);
  if (!el || !btn) return;
  navigator.clipboard.writeText(el.innerText).then(() => {
    btn.textContent = 'DONE';
    btn.style.color = 'var(--primary)';
    setTimeout(() => { btn.textContent = 'COPY'; btn.style.color = '' }, 2000)
  })
}

async function doSend() {
  const ta = document.getElementById('ti');
  const prompt = ta.value.trim(); if (!prompt) return;
  const mode = detMode(prompt);
  ta.value = ''; document.getElementById('sbtn').disabled = true;
  document.getElementById('mtag').className = 'badge bd';
  document.getElementById('mtag').textContent = 'ROUTING...';
  const le = document.getElementById('lempty'); if (le) le.remove();
  const id = 'e' + Date.now();
  const entry = document.createElement('div');
  entry.className = 'entry'; entry.id = id;
  entry.innerHTML = `<div class="eh"><span class="badge bd mtag" id="${id}m">ROUTING</span><span style="font-family:var(--mono);font-size:9px;color:var(--t3)" id="${id}ml"></span><span class="ep">${prompt}</span><span class="et">${new Date().toLocaleTimeString()}</span></div><div class="eb loading" id="${id}b"><span>INITIALIZING NEURAL PIPELINE...</span></div>`;
  document.getElementById('log').prepend(entry);
  try {
    const res = await fetch(`${API}/ask`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: prompt, use_memory: useMem, force_model: document.getElementById('fm').value }) });
    const d = await res.json();
    const mb = document.getElementById(id + 'm'); mb.textContent = (d.mode || mode).toUpperCase(); mb.className = 'badge ' + (MC[d.mode || mode] || 'bd');
    document.getElementById(id + 'ml').textContent = d.model;
    const body = document.getElementById(id + 'b'); body.classList.remove('loading'); rmd(d.response, body);
    if (d.detected_cves?.length) {
      const cr = document.createElement('div'); cr.style.cssText = 'padding:8px 16px;display:flex;gap:6px;flex-wrap:wrap;align-items:center';
      cr.innerHTML = '<span style="font-family:var(--mono);font-size:9px;color:var(--t3)">IDENTIFIED CVEs:</span>';
      d.detected_cves.forEach(c => { const b = document.createElement('span'); b.className = 'dcve'; b.textContent = c; b.onclick = () => { sw('c'); document.getElementById('cveid').value = c; lookupCVE() }; cr.appendChild(b) });
      entry.appendChild(cr);
    }
    total++; updateStats(d.model, d.mode || mode, d.history_depth);
  } catch (err) { const b = document.getElementById(id + 'b'); b.classList.remove('loading'); b.classList.add('err'); b.textContent = `CRITICAL_ERROR: ${err.message}` }
}

function updateStats(model, mode, depth) {
  document.getElementById('sbtot').textContent = total;
  document.getElementById('sbmdl').textContent = (model || '—').toUpperCase();
  document.getElementById('sbmode').textContent = (mode || '—').toUpperCase().replace('_', ' ');
  document.getElementById('sbmem').textContent = (depth || 0) + '/10';
}

async function lookupCVE() {
  const id = document.getElementById('cveid').value.trim(); if (!id) return;
  const list = document.getElementById('cvelist');
  list.innerHTML = '<div class="ldr">LOOKING UP ' + id + '...</div>';
  try { const res = await fetch(`${API}/cve/lookup`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ cve_id: id, generate_exploit: false }) }); const d = await res.json(); renderCVEDetail(d.cve); document.getElementById('cvecnt').textContent = '1'; list.innerHTML = ''; list.appendChild(mkCVC(d.cve, true)) }
  catch (e) { list.innerHTML = `<div style="color:var(--error);font-family:var(--mono);font-size:10px;padding:1rem">${e.message}</div>` }
}

async function searchCVEs() {
  const kw = document.getElementById('cvekw').value.trim();
  const lim = parseInt(document.getElementById('cvelim').value) || 10;
  const list = document.getElementById('cvelist');
  list.innerHTML = '<div class="ldr">SYNCHRONIZING THREAT FEED...</div>';
  try {
    const res = await fetch(`${API}/cve/search`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ keyword: kw, limit: lim }) });
    const d = await res.json(); 
    list.innerHTML = '';
    
    if (d.results && d.results.length > 0 && d.results[0].error) {
        list.innerHTML = `<div style="color:var(--error);font-family:var(--mono);font-size:10px;padding:1rem">⚠ ${d.results[0].error}</div>`;
        document.getElementById('cvecnt').textContent = '0';
        return;
    }

    document.getElementById('cvecnt').textContent = d.count || 0;
    if (!d.results || !d.results.length) { list.innerHTML = '<div class="empty">NO RESULTS MATCHING CRITERIA</div>'; return }
    d.results.forEach(c => list.appendChild(mkCVC(c)));
  } catch (e) { list.innerHTML = `<div style="color:var(--error);font-family:var(--mono);font-size:10px;padding:1rem">${e.message}</div>` }
}

function mkCVC(cve, active = false) {
  if (!cve || !cve.id) return document.createElement('div');
  const d = document.createElement('div'); d.className = 'cvc' + (active ? ' sel' : '');
  d.onclick = () => { document.querySelectorAll('.cvc').forEach(c => c.classList.remove('sel')); d.classList.add('sel'); renderCVEDetail(cve) };
  d.innerHTML = `<div class="row"><span class="cvi">${cve.id}</span><span class="badge ${cve.severity === 'CRITICAL' ? 'br' : cve.severity === 'HIGH' ? 'ba' : 'bd'}" style="font-size:8px">${cve.severity || 'UNKNOWN'}</span>${cve.score != null ? `<span style="font-family:var(--mono);font-size:11px;color:var(--t1);margin-left:auto">${cve.score}</span>` : ''}</div><div class="cvd">${cve.description || ''}</div>`;
  return d;
}

function renderCVEDetail(cve) {
  curCVE = cve;
  document.getElementById('geb').disabled = false;
  const det = document.getElementById('cvedetail');
  const pocs = cve.pocs || {}; const tot = cve.poc_count || 0;
  const sc = cve.score; const scC = sc >= 9 ? 'var(--error)' : sc >= 7 ? 'var(--accent)' : sc >= 4 ? 'var(--secondary)' : 'var(--primary)';
  const ghH = (pocs.github || []).map(i => `<a href="${i.url}" target="_blank" class="cvc" style="display:block;text-decoration:none"><div class="row"><span class="cvi" style="color:var(--secondary)">${i.name || i.repo || '—'}</span>${i.language ? `<span class="badge bb">${i.language}</span>` : ''} ${i.stars ? `<span style="font-family:var(--mono);font-size:9px;color:var(--accent)">★${i.stars}</span>` : ''}</div><div class="cvd">${i.description || ''}</div></a>`).join('') || '<div class="empty">NO GITHUB PoCS IDENTIFIED</div>';
  const edbH = (pocs.exploit_db || []).map(i => `<a href="${i.url}" target="_blank" class="cvc" style="display:block;text-decoration:none"><div class="row"><span class="cvi" style="color:var(--error)">EDB-${i.id}</span>${i.verified ? `<span class="badge bg">VERIFIED</span>` : ''}</div><div class="cvd">${i.title || ''}</div></a>`).join('') || '<div class="empty">NO EDB RECORDS</div>';
  const psH = (pocs.packet_storm || []).map(i => `<a href="${i.url}" target="_blank" class="cvc" style="display:block;text-decoration:none;font-family:var(--mono);font-size:10px;color:var(--t1)">${i.title}</a>`).join('') || '<div class="empty">NO PACKETSTORM RECORDS</div>';
  const vhH = (pocs.vulhub || []).map(i => `<a href="${i.url}" target="_blank" class="cvc" style="display:block;text-decoration:none"><div class="row"><span class="badge bg">DOCKER</span><span class="cvi">${i.name || ''}</span></div></a>`).join('') || '<div class="empty">NO VULHUB TEMPLATES</div>';
  const refs = (cve.references || []).map(r => `<a href="${r}" target="_blank" style="display:block;font-family:var(--mono);font-size:10px;color:var(--secondary);margin-bottom:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${r}</a>`).join('');
  const cwes = (cve.weaknesses || []).map(w => `<span class="badge bp">${w}</span>`).join(' ');
  
  det.innerHTML = `<div class="col">
    <div class="row" style="flex-wrap:wrap;gap:8px">
      <span style="font-family:var(--mono);font-size:18px;color:var(--primary);font-weight:500">${cve.id || '—'}</span>
      <span class="badge ${cve.severity === 'CRITICAL' ? 'br' : 'bd'}">${cve.severity || 'UNKNOWN'}</span>
      ${sc != null ? `<span style="font-family:var(--mono);font-size:24px;font-weight:500;color:${scC}">${sc}</span>` : ''}
      ${cve.kev ? `<span class="badge br">⚠ KEV</span>` : ''}
      ${cve.epss_score != null ? `<span class="badge ba">EPSS ${cve.epss_score}%</span>` : ''}
    </div>
    ${cve.vector ? `<div style="font-family:var(--mono);font-size:10px;color:var(--t3);background:var(--surface-high);padding:8px 12px;border-radius:6px;border:1px solid var(--outline)">${cve.vector}</div>` : ''}
    <div><div class="lbl">VULNERABILITY_DESCRIPTION</div><div style="font-size:13px;line-height:1.8;color:var(--t2)">${cve.description || 'N/A'}</div></div>
    ${cwes ? `<div><div class="lbl">WEAKNESS_MAPPING</div><div class="row" style="flex-wrap:wrap;gap:6px;margin-top:4px">${cwes}</div></div>` : ''}
    <div style="padding:12px;background:var(--surface-high);border-radius:8px;border:1px solid var(--outline)">
      <span style="font-family:var(--mono);font-size:10px;color:${tot > 0 ? 'var(--error)' : 'var(--t3)'}">
        ${tot > 0 ? '⚠' : '○'} ${tot} IDENTIFIED EXPLOIT VECTORS · GH:${(pocs.github || []).length} EDB:${(pocs.exploit_db || []).length} PS:${(pocs.packet_storm || []).length}
      </span>
    </div>
    <div><div class="lbl">GITHUB_RESOURCES</div>${ghH}</div>
    <div><div class="lbl">EXPLOIT_DB_ARCHIVE</div>${edbH}</div>
    <div><div class="lbl">PACKETSTORM_FEED</div>${psH}</div>
    <div><div class="lbl">VULHUB_TEMPLATES</div>${vhH}</div>
    ${refs ? `<div><div class="lbl">EXTERNAL_REFERENCES</div>${refs}</div>` : ''}
  </div>`;
}

async function genExploit() {
  if (!curCVE) return; const lang = document.getElementById('elang').value;
  const btn = document.getElementById('geb'); btn.disabled = true; btn.textContent = '...';
  const det = document.getElementById('cvedetail');
  const ldr = document.createElement('div'); ldr.className = 'ldr'; ldr.innerHTML = `GENERATING ${lang} EXPLOIT ARCHITECTURE...`; 
  det.prepend(ldr);
  try {
    const res = await fetch(`${API}/cve/lookup`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ cve_id: curCVE.id, generate_exploit: true, language: lang, exploit_type: 'poc' }) });
    const d = await res.json(); ldr.remove();
    if (d.exploit) { 
        const out = document.createElement('div'); 
        out.className = 'exploit-output'; // For future styling
        out.style.cssText = 'margin:20px 0;padding:16px;background:var(--surface);border-radius:12px;border:1px solid var(--primary-glow)';
        out.innerHTML = `<div class="lbl" style="color:var(--primary);margin-bottom:12px;display:flex;align-items:center;gap:8px">◈ GENERATED_PAYLOAD [${lang.toUpperCase()}]</div>`; 
        rmd(d.exploit, out); 
        det.prepend(out);
        det.scrollTop = 0; // Scroll to new exploit
    }
  } catch (e) { ldr.remove(); const err = document.createElement('div'); err.style.cssText = 'color:var(--error);font-family:var(--mono);font-size:10px;margin:12px 0'; err.textContent = 'CRITICAL_FAULT: ' + e.message; det.prepend(err) }
  finally { btn.disabled = false; btn.textContent = 'GENERATE EXPLOIT' }
}

const TMPLS = { rce: { desc: 'Remote code execution via command injection. Application passes unsanitized input to system() calls.', type: 'poc' }, sqli: { desc: 'SQL injection in login form. Username parameter allows UNION-based extraction.', type: 'poc' }, lfi: { desc: 'Local file inclusion. The file GET parameter allows directory traversal.', type: 'poc' }, xss: { desc: 'Stored XSS in comment field. Input reflected without sanitization.', type: 'poc' }, ssrf: { desc: 'SSRF in URL fetching endpoint. User-provided URLs fetched without validation.', type: 'poc' }, revshell: { desc: 'Reverse shell payload connecting back to attacker listener.', type: 'full' }, privesc: { desc: 'Linux privilege escalation via SUID binary or sudo misconfiguration.', type: 'full' }, detect: { desc: 'Scanner to detect vulnerable hosts on a network.', type: 'detection' } };
function setTmpl(t) { const m = TMPLS[t]; if (!m) return; document.getElementById('egdesc').value = m.desc; document.getElementById('egtype').value = m.type }

async function genExploitFull() {
  const desc = document.getElementById('egdesc').value.trim(); if (!desc) { alert('Enter description'); return }
  const out = document.getElementById('egout'); out.className = '';
  out.innerHTML = '<div class="ldr">SYNTHESIZING ADVANCED EXPLOIT...</div>';
  try { const res = await fetch(`${API}/exploit/generate`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ cve_id: document.getElementById('egcve').value || 'N/A', description: desc, language: document.getElementById('eglang').value, exploit_type: document.getElementById('egtype').value }) }); const d = await res.json(); out.innerHTML = ''; rmd(d.exploit || d.payload || 'NO_OUTPUT_GENERATED', out) }
  catch (e) { out.innerHTML = `<div style="color:var(--error);font-family:var(--mono);font-size:10px">${e.message}</div>` }
}

async function doRecon() {
  const tgt = document.getElementById('rtgt').value.trim(); if (!tgt) return;
  const out = document.getElementById('reconout');
  out.innerHTML = '<div class="ldr">OPERATIONALIZING RECONNAISSANCE PLAN...</div>';
  try { const res = await fetch(`${API}/pentest/recon`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target: tgt, recon_type: document.getElementById('rtype').value }) }); const d = await res.json(); out.innerHTML = ''; rmd(d.recon_plan, out) }
  catch (e) { out.innerHTML = `<div style="color:var(--error);font-family:var(--mono);font-size:10px">${e.message}</div>` }
}

function selAtk(t) { selAttk = t; document.querySelectorAll('.akc').forEach(c => c.classList.remove('sel')); document.getElementById('atk-' + t).classList.add('sel') }
function selTgt(el, v) { selTgtV = v; document.querySelectorAll('.tgt').forEach(t => t.classList.remove('sel')); el.classList.add('sel'); document.getElementById('ctgt').style.display = v === 'custom' ? 'block' : 'none' }

async function doAIPentest() {
  const tgt = selTgtV === 'custom' ? document.getElementById('ctgt').value.trim() : selTgtV; if (!tgt) return;
  const out = document.getElementById('aiout'); out.innerHTML = '<div class="ldr">SYNTHESIZING ADVERSARIAL PAYLOADS...</div>';
  try { const res = await fetch(`${API}/ai-pentest`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target_model: tgt, attack_type: selAttk, context: document.getElementById('aictx').value }) }); const d = await res.json(); out.innerHTML = ''; rmd(d.payloads, out); total++; updateStats(d.model, d.mode, d.history_depth); }
  catch (e) { out.innerHTML = `<div style="color:var(--error);font-family:var(--mono);font-size:10px">${e.message}</div>` }
}

function selProbe(t) { selProbeV = t; document.querySelectorAll('.chip').forEach(b => b.classList.remove('on')); document.getElementById('pr-' + t).classList.add('on') }
function setAO(html) { document.getElementById('audout').innerHTML = html; document.getElementById('audts').textContent = new Date().toLocaleTimeString() }

async function loadStatus() {
  const p = document.getElementById('instpanel');
  try {
    const r = await fetch(`${API}/scanner/status`); const d = await r.json();
    p.innerHTML = `<div class="rrow ${d.garak ? 'rpass' : 'rfail'}"><span style="font-family:var(--mono);font-size:10px">GARAK_ENGINE</span><span class="badge ${d.garak ? 'bg' : 'br'} mla">${d.garak ? 'DEPLOYED' : 'MISSING'}</span>${!d.garak ? `<button class="btn btn-primary" style="height:24px;font-size:9px" onclick="instTool('garak')">INSTALL</button>` : ''}</div><div class="rrow ${d.promptbench ? 'rpass' : 'rfail'}"><span style="font-family:var(--mono);font-size:10px">PROMPTBENCH_SYSTEM</span><span class="badge ${d.promptbench ? 'bg' : 'br'} mla">${d.promptbench ? 'DEPLOYED' : 'MISSING'}</span>${!d.promptbench ? `<button class="btn btn-primary" style="height:24px;font-size:9px" onclick="instTool('promptbench')">INSTALL</button>` : ''}</div>`;
  } catch (e) { p.innerHTML = `<div style="color:var(--error);font-family:var(--mono);font-size:10px">${e.message}</div>` }
}

async function instTool(pkg) {
  document.getElementById('instpanel').innerHTML = '<div class="ldr">DEPLOYING ' + pkg.toUpperCase() + ' SUBSYSTEM...</div>';
  const r = await fetch(`${API}/scanner/install`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ package: pkg }) });
  const d = await r.json(); d.success ? setTimeout(loadStatus, 1000) : document.getElementById('instpanel').innerHTML = `<div style="color:var(--error);font-family:var(--mono);font-size:10px">DEPLOYMENT_FAILED: ${d.error}</div>`;
}

function renderAuditResults(data) {
  if (data.status === 'not_installed') { setAO(`<div style="color:var(--accent)">${data.message}</div>`); return }
  if (data.status === 'error' || data.status === 'timeout') { setAO(`<div style="color:var(--error)">${data.message || data.status}</div>`); return }
  const results = data.results || []; if (!results.length) { setAO('<div class="empty">NO TELEMETRY DATA RETURNED</div>'); return }
  const passed = results.filter(r => r.status === 'pass').length;
  const score = Math.round(passed / results.length * 100);
  const color = score >= 80 ? 'var(--primary)' : score >= 50 ? 'var(--accent)' : 'var(--error)';
  document.getElementById('scorecard').style.display = 'block';
  document.getElementById('scorebody').innerHTML = `<div class="row" style="gap:16px"><div class="sring" style="border-color:${color}"><span style="font-family:var(--mono);font-size:20px;font-weight:600;color:${color}">${score}%</span><span style="font-family:var(--mono);font-size:8px;color:var(--t3)">SAFETY</span></div><div><div style="font-family:var(--mono);font-size:11px;color:var(--t1)">MODEL: <span style="color:var(--secondary)">${(data.model || '—').toUpperCase()}</span></div><div style="font-family:var(--mono);font-size:10px;color:var(--t3);margin-top:4px">${passed}/${results.length} VECTORS SECURED</div><div class="mt6"><span class="badge" style="color:${color};border-color:${color}">${score >= 80 ? 'ROBUST' : score >= 50 ? 'MODERATE' : 'VULNERABLE'}</span></div></div></div>`;
  let html = '';
  results.forEach(r => {
    const st = r.status === 'pass' ? 'rpass' : r.status === 'fail' ? 'rfail' : 'rwarn';
    const ic = r.status === 'pass' ? 'var(--primary)' : r.status === 'fail' ? 'var(--error)' : 'var(--accent)';
    if (r.input !== undefined) {
      html += `<div class="rrow ${st}" style="flex-direction:column;gap:6px"><div class="row" style="font-family:var(--mono);font-size:9px;color:var(--t3)">VECTOR_ID: ${r.probe || 'DIRECT'}${r.flagged ? `<span class="badge br" style="margin-left:auto">FLAGGED</span>` : ''}</div><div style="font-family:var(--mono);font-size:11px;color:var(--accent)">IN: ${r.input}</div>${r.response ? `<div style="font-size:12px;color:var(--t2);background:var(--surface-high);padding:8px 12px;border-radius:6px;border:1px solid var(--outline)">${r.response}</div>` : ''}</div>`;
    } else {
      html += `<div class="rrow ${st}"><span style="font-family:var(--mono);font-size:11px;flex:1">${(r.probe || r.attack || '—').toUpperCase()}</span><span style="font-family:var(--mono);font-size:10px;font-weight:600;color:${ic}">${r.score !== undefined ? r.score + '%' : ''}</span></div>`;
    }
  });
  setAO(html);
}

async function runProbe() {
  const mdl = document.getElementById('audmdl').value;
  setAO('<div class="ldr">EXECUTING PROBE: ' + selProbeV.toUpperCase() + ' ON ' + mdl + '...</div>');
  document.getElementById('scorecard').style.display = 'none';
  try { const r = await fetch(`${API}/scanner/probe`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ model_name: mdl, probe_type: selProbeV }) }); renderAuditResults(await r.json()) }
  catch (e) { setAO(`<div style="color:var(--error);font-family:var(--mono);font-size:10px">${e.message}</div>`) }
}

async function checkHealth() {
  const dot = document.getElementById('sdot'), txt = document.getElementById('stxt');
  try {
    const r = await fetch(`${API}/health`, { signal: AbortSignal.timeout(3000) });
    if (r.ok) {
      dot.classList.add('on'); txt.textContent = 'SYSTEM ONLINE';
      const d = await r.json(); const sel = document.getElementById('fm'); const ex = Array.from(sel.options).map(o => o.value);
      (d.models_available || []).forEach(m => { if (!ex.includes(m)) { const o = document.createElement('option'); o.value = m; o.textContent = m.toUpperCase(); sel.appendChild(o) } });
    } else { dot.classList.remove('on'); txt.textContent = 'SYSTEM FAULT' }
  } catch (_) { dot.classList.remove('on'); txt.textContent = 'OFFLINE_LINK' }
}

// Global scope initialization
window.addEventListener('DOMContentLoaded', () => {
    checkHealth(); 
    setInterval(checkHealth, 15000);
    setInterval(() => { 
        const s = Math.floor((Date.now() - start) / 1000), m = Math.floor(s / 60), sec = s % 60; 
        document.getElementById('sbup').textContent = m > 0 ? m + 'm ' + sec + 's' : s + 's' 
    }, 1000);
});
