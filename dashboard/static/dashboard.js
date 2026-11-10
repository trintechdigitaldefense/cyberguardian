function toast(msg){ const t=document.getElementById('toast'); t.textContent=msg; t.classList.add('visible'); setTimeout(()=>t.classList.remove('visible'),2500); }
function esc(s){ return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;').replace(/'/g,'&#39;'); }
async function setClientMode(on){
  const r=await cgFetch('/ops/client-mode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client_mode:!!on})});
  const d=await r.json();
  document.getElementById('cm-status').innerHTML='Saved: <strong>'+(d.client_mode?'ON':'OFF')+'</strong>';
  document.getElementById('stat-cm').textContent=d.client_mode?'ON':'OFF';
  document.getElementById('stat-cm').className='value '+(d.client_mode?'good':'warn');
  toast(d.client_mode?'Client Mode ON':'Client Mode OFF'); loadScorecard();
}
async function loadIssues(){ const el=document.getElementById('issues-out'); el.textContent='Loading…'; try{ el.textContent=JSON.stringify(await (await cgFetch('/ops/issues')).json(),null,2);}catch(e){el.textContent='Failed: '+e;} }
async function loadFleet(){
  try{
    const d=await (await cgFetch('/ops/fleet')).json(); const box=document.getElementById('fleet-table'); const items=d.items||[];
    if(!items.length){ box.innerHTML='<p class="hint">No agents registered yet.</p>'; return; }
    let html='<table><thead><tr><th>Asset</th><th>Host</th><th>Status</th><th>Agent</th><th>Actions</th></tr></thead><tbody>';
    for(const a of items){ const cls=a.status==='online'?'good':'bad';
      html+=`<tr><td><code>${esc(a.asset_id)}</code></td><td>${esc(a.hostname||'—')}</td><td class="${cls}">${esc(a.status)}</td><td>${esc(a.agent_version||'—')}</td><td><button type="button" class="ghost" data-action="rollback" data-asset-id="${esc(a.asset_id)}">Undo isolate</button></td></tr>`; }
    html+='</tbody></table>'; box.innerHTML=html;
    if(d.online!=null) document.getElementById('stat-online').textContent=d.online;
    if(d.total!=null) document.getElementById('stat-assets').textContent=d.total;
  }catch(e){ toast('Fleet refresh failed'); }
}
function evidenceHtml(a){ const p=a.parameters||{}; const ev=p.evidence||{}; if(!ev.summary&&p.risk_score==null) return '';
  const risk=p.risk_score!=null?p.risk_score:(ev.risk_score!=null?ev.risk_score:'—');
  return `<div class="evidence">Why: ${esc(ev.summary||'staged for approval')} · risk ${esc(risk)}</div>`; }
async function loadGate(){
  try{
    const d=await (await cgFetch('/ops/gate')).json(); const pending=d.pending||[];
    document.getElementById('stat-pending').textContent=d.pending_count!=null?d.pending_count:pending.length;
    const box=document.getElementById('gate-list');
    if(!pending.length){ box.innerHTML='<p class="hint">No pending actions.</p>'; return; }
    box.innerHTML=pending.map(a=>`
      <div class="pending-item" data-id="${esc(a.id)}">
        <strong>${esc(a.action)}</strong> → <code>${esc(a.target||'')}</code>
        <div class="meta">${esc(a.reason||'')}</div>${evidenceHtml(a)}
        <div class="row" style="margin-top:.4rem">
          <button type="button" class="ok" data-action="gate" data-id="${esc(a.id)}" data-verb="approve">Approve</button>
          <button type="button" class="danger" data-action="gate" data-id="${esc(a.id)}" data-verb="reject">Reject</button>
          <button type="button" class="ghost" data-action="mark-benign" data-id="${esc(a.id)}" data-asset-id="${esc((a.parameters&&a.parameters.asset_id)||a.target||'')}" data-title="${esc((a.action||'')+': '+(a.reason||'')).slice(0,80)}">Mark benign</button>
        </div></div>`).join('');
  }catch(e){ toast('Gate refresh failed'); }
}
async function gateAct(id,action){
  try{ const r=await cgFetch('/ops/gate/'+action+'/'+id,{method:'POST'}); const d=await r.json();
    toast(action==='approve'&&d.execution&&d.execution.command_id?'Approved — queued for agent':(action==='approve'?'Approved':'Rejected'));
    await loadGate(); loadAudit();
  }catch(e){ toast('Action failed'); }
}
async function markBenignFromGate(pendingId, assetId, titleHint){
  const title=(titleHint||'marked benign').replace(/\[staged.*$/,'')||'marked benign';
  try{ const r=await cgFetch('/ops/feedback/benign',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({title:title.slice(0,120),asset_id:assetId,pending_action_id:pendingId,suppress_days:14,note:'operator marked benign'})});
    const d=await r.json(); toast(d.status==='ok'?'Marked benign (14d suppress)':'Failed'); await loadGate(); loadAudit();
  }catch(e){ toast('Benign mark failed'); }
}
async function rollbackAsset(assetId){
  if(!confirm('Queue network restore on '+assetId+'?')) return;
  try{ const r=await cgFetch('/ops/rollback/'+encodeURIComponent(assetId),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({reason:'operator undo isolate'})});
    const d=await r.json(); toast(d.status==='queued'?'Rollback queued for agent':'Rollback failed'); loadAudit();
  }catch(e){ toast('Rollback failed'); }
}
async function loadAudit(){
  const box=document.getElementById('audit-table'); box.innerHTML='<p class="hint">Loading…</p>';
  try{ const d=await (await cgFetch('/ops/audit')).json(); const items=d.items||[];
    if(!items.length){ box.innerHTML='<p class="hint">No audit events yet.</p>'; return; }
    let html='<table><thead><tr><th>When</th><th>Event</th><th>Action</th><th>Target</th><th>Asset</th><th>Actor</th><th>Detail</th></tr></thead><tbody>';
    for(const a of items){ const when=a.created_at?new Date(a.created_at*1000).toISOString().replace('T',' ').slice(0,19):'—';
      html+=`<tr><td class="meta">${esc(when)}</td><td>${esc(a.event)}</td><td>${esc(a.action||'')}</td><td><code>${esc(a.target||'')}</code></td><td>${esc(a.asset_id||'')}</td><td>${esc(a.actor||'')}</td><td class="meta">${esc(a.detail||'')}</td></tr>`; }
    html+='</tbody></table>'; box.innerHTML=html;
  }catch(e){ box.innerHTML='<p class="hint">Failed to load audit.</p>'; }
}
async function loadScorecard(){
  try{ const d=await (await cgFetch('/ops/scorecard')).json();
    const st=document.getElementById('score-status'); st.textContent=`Status: ${(d.status||'').toUpperCase()} (${d.score||''})`; st.className='meta score-'+(d.status||'yellow');
    const checks=d.checks||[]; document.getElementById('score-list').innerHTML='<table><thead><tr><th>Check</th><th>OK</th><th>Detail</th></tr></thead><tbody>'+
      checks.map(c=>`<tr><td>${esc(c.label)}</td><td class="${c.ok?'check-ok':'check-bad'}">${c.ok?'✓':'✗'}</td><td class="meta">${esc(c.detail||'')}</td></tr>`).join('')+'</tbody></table>';
  }catch(e){ toast('Scorecard failed'); }
}
async function loadWeekly(){ const el=document.getElementById('weekly-out'); el.textContent='Loading…'; try{ el.textContent=await (await cgFetch('/ops/weekly')).text(); }catch(e){ el.textContent='Failed: '+e; } }
async function loadInventory(){ const el=document.getElementById('inv-out'); el.textContent='Loading…'; try{ el.textContent=await (await cgFetch('/ops/inventory')).text(); }catch(e){ el.textContent='Failed: '+e; } }
async function refreshAll(){ await Promise.all([loadIssues(),loadFleet(),loadGate(),loadAudit(),loadScorecard(),pingStatus()]); try{ const d=await (await cgFetch('/ops/risk')).json(); if(d.total_assets!=null) document.getElementById('stat-assets').textContent=d.total_assets; if(d.online!=null) document.getElementById('stat-online').textContent=d.online; if(d.open_detections!=null) document.getElementById('stat-det').textContent=d.open_detections; }catch(_){ } toast('Refreshed'); }
async function pingStatus(){ try{ const d=await (await cgFetch('/ops/status')).json(); const b=document.getElementById('conn-badge'); b.textContent=d.api?'API online':'API offline'; b.className='badge '+(d.api?'status-online':'status-offline'); }catch(_){ const b=document.getElementById('conn-badge'); b.textContent='API offline'; b.className='badge status-offline'; } }
pingStatus(); loadScorecard(); loadGate();

async function cgFetch(url, options={}) {
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
  const headers = new Headers(options.headers || {});
  headers.set('X-CSRF-Token', csrf);
  return fetch(url, {...options, headers, credentials:'same-origin'});
}
async function logoutDashboard() {
  try {
    const response = await cgFetch('/logout', {method:'POST'});
    if (response.redirected) { window.location.href = response.url; return; }
    window.location.href = '/login';
  } catch (_) { toast('Sign out failed'); }
}

document.addEventListener('click', (event) => {
  const button = event.target.closest('[data-action]');
  if (!button) return;
  const action = button.dataset.action;
  if (action === 'logout') logoutDashboard();
  else if (action === 'load-scorecard') loadScorecard();
  else if (action === 'client-mode') setClientMode(button.dataset.enabled === 'true');
  else if (action === 'refresh-all') refreshAll();
  else if (action === 'load-audit') loadAudit();
  else if (action === 'load-issues') loadIssues();
  else if (action === 'load-fleet') loadFleet();
  else if (action === 'load-weekly') loadWeekly();
  else if (action === 'load-inventory') loadInventory();
  else if (action === 'download-client-report') downloadClientReport();
  else if (action === 'rollback') rollbackAsset(button.dataset.assetId);
  else if (action === 'gate') gateAct(button.dataset.id, button.dataset.verb);
  else if (action === 'mark-benign') markBenignFromGate(button.dataset.id, button.dataset.assetId, button.dataset.title);
});

function toLocalDateTimeValue(date){
  const local=new Date(date.getTime()-date.getTimezoneOffset()*60000);
  return local.toISOString().slice(0,16);
}
function initializeReportWindow(){
  const start=document.getElementById('report-start');
  const end=document.getElementById('report-end');
  if(!start||!end) return;
  const now=new Date();
  end.value=toLocalDateTimeValue(now);
  start.value=toLocalDateTimeValue(new Date(now.getTime()-7*24*60*60*1000));
}
initializeReportWindow();

async function downloadClientReport(){
  const status=document.getElementById('client-report-status');
  const button=document.querySelector('[data-action="download-client-report"]');
  if(button) button.disabled=true;
  if(status) status.textContent='Collecting monitoring information and preparing the PDF…';
  try{
    const startValue=document.getElementById('report-start')?.value||'';
    const endValue=document.getElementById('report-end')?.value||'';
    const startDate=new Date(startValue);
    const endDate=new Date(endValue);
    if(!startValue||!endValue||Number.isNaN(startDate.getTime())||Number.isNaN(endDate.getTime())||endDate<=startDate){
      throw new Error('Choose a valid reporting period. The end must be later than the start.');
    }
    const query=new URLSearchParams({start:startDate.toISOString(),end:endDate.toISOString()});
    const response=await cgFetch('/ops/reports/client.pdf?'+query.toString());
    if(!response.ok){
      let message='Report generation failed (HTTP '+response.status+').';
      try{ const body=await response.json(); if(body.error) message=body.error; }catch(_){}
      throw new Error(message);
    }
    const blob=await response.blob();
    if(blob.type!=='application/pdf') throw new Error('The server did not return a PDF file.');
    const url=URL.createObjectURL(blob);
    const link=document.createElement('a');
    link.href=url;
    link.download='CyberGuardian_Client_Report_'+new Date().toISOString().slice(0,10).replaceAll('-','')+'.pdf';
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(()=>URL.revokeObjectURL(url),1000);
    if(status) status.textContent='Report generated. Check your downloads.';
    toast('Client PDF report generated');
  }catch(error){
    if(status) status.textContent=String(error.message||error);
    toast('Client report could not be generated');
  }finally{
    if(button) button.disabled=false;
  }
}
