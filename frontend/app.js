const api = '/api';
const $ = (id) => document.getElementById(id);

for (const nav of document.querySelectorAll('.nav')) {
  nav.addEventListener('click', () => {
    document.querySelectorAll('.nav').forEach(n => n.classList.remove('active'));
    nav.classList.add('active');
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active-page'));
    $(nav.dataset.page).classList.add('active-page');
    if (nav.dataset.page === 'overview') refreshOverview();
    if (nav.dataset.page === 'parsers') loadParsers();
    if (nav.dataset.page === 'mutation') loadMutation();
    if (nav.dataset.page === 'onboarding') loadOnboarding();
    if (nav.dataset.page === 'airouting') loadAIRouting();
    if (nav.dataset.page === 'aimodel') loadGPTOSS();
    if (nav.dataset.page === 'evolutioncc') loadEvolutionCC();
  });
}

async function get(path, opts={}) {
  const r = await fetch(api + path, opts);
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

async function refreshOverview(){
  const m = await get('/metrics');
  try { const a = await get('/ai/status'); $('aiStatus').textContent = `AI: ${a.model.toUpperCase()} · ${a.mode.toUpperCase()}`; $('aiModeCaption').textContent = a.mode === 'heuristic' ? 'Heuristic local fallback active.' : `Local model adapter: ${a.model}`; } catch {}
  const cards = [
    ['Events', m.total_events, ''],
    ['Trusted', m.trusted_events, 'accent'],
    ['Review', m.review_events, ''],
    ['Lossless', `${(m.lossless_rate*100).toFixed(1)}%`, 'accent'],
    ['Parsers', m.parser_count, ''],
    ['Air-gapped', m.air_gapped ? 'ON' : 'OFF', 'accent']
  ];
  $('metrics').innerHTML = cards.map(c=>`<div class="metric"><div class="metric-label">${c[0]}</div><div class="metric-value ${c[2]}">${c[1]}</div></div>`).join('');
  await loadEvents();
}

async function loadEvents(){
  const items = await get('/events?limit=20');
  if (!items.length){ $('events').innerHTML='<div class="empty">No events yet. Open Ingest Logs and feed the pipeline.</div>'; return; }
  $('events').innerHTML = items.map(e=>`<div class="event" onclick='showEvent(${JSON.stringify(e)})'><div class="event-row"><div class="event-main"><div class="event-id">${e.event_id}</div><div class="event-raw">${escapeHtml(e.raw)}</div></div><span class="badge ${e.status==='trusted'?'good':'warn'}">${e.status.toUpperCase()}</span></div><div class="event-raw">${e.vendor} · ${e.format} · ${e.parser_id} · SHA ${e.raw_sha256.slice(0,16)}…</div></div>`).join('');
}

function showEvent(e){
  const page = $('lineage');
  document.querySelectorAll('.nav').forEach(n=>n.classList.toggle('active', n.dataset.page==='lineage'));
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active-page')); page.classList.add('active-page');
  $('lineagePanel').innerHTML = `<div class="line"><strong>RAW EVENT</strong><div>${escapeHtml(e.raw)}<br>SHA-256: ${e.raw_sha256}</div></div><div class="line"><strong>LOG DNA</strong><div>${e.log_dna.id} · ${e.log_dna.format} · entropy ${e.log_dna.entropy}</div></div><div class="line"><strong>PARSER</strong><div>${e.parser_id} · confidence ${(e.parser_confidence*100).toFixed(1)}%</div></div><div class="line"><strong>NORMALIZATION</strong><div>${JSON.stringify(e.normalized, null, 2)}</div></div><div class="line"><strong>LOSSLESS PROOF</strong><div>raw preserved = ${e.lossless} · unmapped fields = ${e.unmapped_field_count} · schema = ${e.lineage.schema_version}</div></div>`;
}

async function ingest(){
  const raw = $('rawLog').value.trim();
  const source = $('source').value.trim() || 'unknown';
  if (!raw) return;
  const e = await get('/ingest',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source,raw})});
  $('ingestResult').innerHTML = `<div class="result">${escapeHtml(JSON.stringify({status:e.status, log_dna:e.log_dna.id, parser:e.parser_id, parser_confidence:e.parser_confidence, lossless:e.lossless, raw_sha256:e.raw_sha256, normalized:e.normalized},null,2))}</div>`;
  renderDNA(e);
  showEvent(e);
  await refreshOverview();
}

function renderDNA(e){
  const d=e.log_dna;
  $('dnaPanel').innerHTML = [
    ['DNA ID',d.id,'accent'],['FORMAT',`${d.format}`,''],['LENGTH',d.length,''],['TOKENS',d.token_count,''],['IP SIGNAL',d.ipv4_count,'accent'],['PORT SIGNAL',d.port_signal,''],['TIMESTAMP',d.timestamp_signal?'DETECTED':'NONE',''],['ENTROPY',d.entropy,'']
  ].map(x=>`<div class="dna-card"><div class="dna-k">${x[0]}</div><div class="dna-v ${x[2]}">${x[1]}</div></div>`).join('');
}

async function loadParsers(){
  const ps = await get('/parsers');
  $('parsersPanel').innerHTML = ps.map(p=>`<div class="parser"><div class="event-row"><div><h3>${escapeHtml(p.id)}</h3><small>${String(p.status).toUpperCase()} · schema ${p.schema_version} · coverage ${(p.coverage*100).toFixed(1)}%</small></div>${p.status==='candidate'?`<button class="ghost" onclick="promoteParser('${encodeURIComponent(p.id)}')">SANDBOX + PROMOTE</button>`:''}</div><div class="parser-map">${Object.entries(p.mapping).map(([a,b])=>`<div class="map-line"><span>${escapeHtml(a)}</span><span>→ ${escapeHtml(b)}</span></div>`).join('')}</div></div>`).join('');
}

async function promoteParser(id){
  const samples=($('candidateSamples')?.value || 'src=10.1.1.2 dst=10.1.1.3 dport=443 action=accept proto=tcp').split(/\n+/).map(s=>s.trim()).filter(Boolean);
  try{ const r=await get('/parsers/'+decodeURIComponent(id)+'/promote',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({parser_id:decodeURIComponent(id),samples})}); alert('Promoted '+r.candidate.id+' v'+r.candidate.version); await loadParsers(); }
  catch(e){ alert('Promotion blocked: '+e.message); }
}

async function promoteParser(id){
  const samples=($('candidateSamples')?.value || 'src=10.1.1.2 dst=10.1.1.3 dport=443 action=accept proto=tcp').split(/\n+/).map(s=>s.trim()).filter(Boolean);
  try{const r=await get('/parsers/'+decodeURIComponent(id)+'/promote',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({parser_id:decodeURIComponent(id),samples})}); alert(`Promoted ${r.candidate.id} v${r.candidate.version}`); await loadParsers();}catch(e){alert('Promotion blocked: '+e.message)}
}

async function runSandbox(){
  const samples = $('sandboxLogs').value.split(/\n+/).map(s=>s.trim()).filter(Boolean);
  const r = await get('/sandbox/replay',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({samples})});
  $('sandboxResult').innerHTML = `<div class="result">${escapeHtml(JSON.stringify(r,null,2))}</div>`;
}

async function loadMutation(){
  const r = await get('/mutation');
  const tone = r.severity==='critical' ? 'warn' : (r.severity==='warning' ? 'warn' : 'accent');
  $('mutationPanel').innerHTML = `<div class="dna-card"><div class="dna-k">STATUS</div><div class="dna-v ${tone}">${String(r.status||'').toUpperCase()}</div></div><div class="dna-card"><div class="dna-k">SEVERITY</div><div class="dna-v ${tone}">${String(r.severity||'—').toUpperCase()}</div></div><div class="dna-card"><div class="dna-k">SIMILARITY</div><div class="dna-v">${r.similarity_score ?? '—'}</div></div><div class="empty">${escapeHtml(r.recommendation||r.message||'')}</div>`;
  if(r.changed_dimensions?.length){
    $('mutationDetails').innerHTML=`<div class="line"><strong>STRUCTURAL CHANGES</strong><div>${r.changed_dimensions.map(d=>`<div class="event-raw">${escapeHtml(d.dimension)} · baseline ${escapeHtml(JSON.stringify(d.baseline))} → current ${escapeHtml(JSON.stringify(d.current))}</div>`).join('')}</div></div><div class="line"><strong>RELEASE DECISION</strong><div>${escapeHtml(r.decision)}</div></div>`;
  } else $('mutationDetails').innerHTML='';
} 


function escapeHtml(s){return String(s).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#039;')}

refreshOverview();


async function runMapper(){
  const raw=$('mapLog').value.trim();
  if(!raw)return;
  const r=await get('/ai/map',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({raw})});
  $('mapperResult').innerHTML=`<div class="result">${escapeHtml(JSON.stringify(r,null,2))}</div>`;
}

async function createCandidate(){
  const name=$('candidateName').value.trim() || 'local-candidate';
  const samples=$('candidateSamples').value.split(/\n+/).map(s=>s.trim()).filter(Boolean);
  if(!samples.length)return;
  const r=await get('/parsers/candidates',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,raw_samples:samples})});
  $('candidateResult').innerHTML=`<div class="result">Candidate ${escapeHtml(r.id)} created. Coverage ${(r.coverage*100).toFixed(1)}%. Mapping confidence ${((r.genome?.mapping_confidence||0)*100).toFixed(1)}%.</div>`;
  await loadParsers();
}

async function approveParser(id){ const r=await get('/parsers/'+decodeURIComponent(id)+'/approve',{method:'POST'}); alert('Approved '+r.id); await loadParsers(); }

async function loadEvolution(){
  const s = await get('/evolution/summary');
  $('evolutionMetrics').innerHTML = [['Sources',s.sources_registered],['Trusted',s.sources_trusted],['Candidates',s.candidates],['Approved',s.approved_parsers]].map(([k,v])=>`<div class="metric"><div class="metric-label">${k}</div><div class="metric-value">${v}</div></div>`).join('');
  await loadSources();
}
async function loadSources(){
  const rows=await get('/sources');
  $('sourcesPanel').innerHTML=rows.length?rows.map(r=>`<div class="source-row"><div><div class="source-name">${escapeHtml(r.source)}</div><div class="source-meta">${escapeHtml(r.vendor)} · parser ${escapeHtml(r.parser_id)} · ${r.event_count} events</div></div><div class="source-status">${escapeHtml(r.status)}</div></div>`).join(''):'<div class="empty">No sources registered yet.</div>';
}
document.querySelectorAll('.nav').forEach(n=>n.addEventListener('click',()=>{ if(n.dataset.page==='evolution') loadEvolution(); }));


async function analyzeOnboarding(){
  const source=$('onboardSource').value.trim() || 'unknown-source';
  const vendor=$('onboardVendor').value.trim() || null;
  const samples=$('onboardSamples').value.split(/\n+/).map(s=>s.trim()).filter(Boolean);
  if(!samples.length)return;
  const r=await get('/onboarding/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source,samples,expected_vendor:vendor})});
  const best=r.matching?.best;
  $('onboardingResult').innerHTML=`<div class="result">${escapeHtml(JSON.stringify({session_id:r.session_id,status:r.status,recommendation:r.recommendation,dna:r.dna.id,best_match:best},null,2))}<br><br><button class="primary" onclick="promoteOnboarding('${r.session_id}')">${r.recommendation==='bind-existing-parser'?'BIND MATCHED PARSER':'CREATE CANDIDATE'}</button></div>`;
  await loadOnboarding();
}

async function promoteOnboarding(sessionId){
  const name=$('onboardSource').value.trim()+'-parser';
  const r=await get('/onboarding/'+encodeURIComponent(sessionId)+'/promote',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session_id:sessionId,candidate_name:name})});
  $('onboardingResult').innerHTML=`<div class="result">${escapeHtml(JSON.stringify(r,null,2))}</div>`;
  await loadOnboarding();
}

async function loadOnboarding(){
  const rows=await get('/onboarding');
  $('onboardingQueue').innerHTML=rows.length?rows.map(r=>{const b=r.matching?.best;return `<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(r.source)}</div><div class="event-raw">${escapeHtml(r.status)} · ${escapeHtml(r.recommendation)} · DNA ${escapeHtml(r.dna.id)}</div></div><span class="badge ${r.status==='matched'?'good':'warn'}">${escapeHtml(r.status.toUpperCase())}</span></div><div class="event-raw">Best parser: ${escapeHtml(b?.parser_id||'none')} · score ${(b?.score*100||0).toFixed(1)}%</div></div>`}).join(''):'<div class="empty">No discovery sessions yet.</div>';
}


async function analyzeSemantic(){
  const raw=$('semanticLog').value.trim();
  if(!raw)return;
  const r=await get('/semantic/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({raw})});
  const status=r.quarantined?'QUARANTINE':'SAFE TO NORMALIZE';
  $('semanticResult').innerHTML=`<div class="result"><b>${escapeHtml(status)}</b>\n\n${escapeHtml(JSON.stringify(r,null,2))}</div>`;
  await loadSemanticGraph(); await loadSemanticConflicts();
}

async function loadSemanticGraph(){
  try{
    const r=await get('/semantic/graph?limit=60');
    $('semanticGraph').innerHTML=r.edges.length?r.edges.map(e=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(e.source_id.replace(/^alias:/,''))} → ${escapeHtml(e.target_id.replace(/^canonical:/,''))}</div><div class="event-raw">${e.evidence_count} observations · confidence ${(e.confidence*100).toFixed(1)}%</div></div><span class="badge good">${escapeHtml(e.relation.toUpperCase())}</span></div><div class="event-raw">${escapeHtml(JSON.stringify(e.evidence))}</div></div>`).join(''):'<div class="empty">No semantic observations yet.</div>';
  }catch(e){ $('semanticGraph').innerHTML='<div class="empty">Semantic graph unavailable.</div>'; }
}

async function loadSemanticConflicts(){
  try{
    const rows=await get('/semantic/conflicts?limit=30');
    $('semanticConflicts').innerHTML=rows.length?rows.map(r=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(r.raw_key)} · ${escapeHtml(r.value_shape)}</div><div class="event-raw">${escapeHtml(r.reason)}</div></div><span class="badge warn">QUARANTINED</span></div><div class="event-raw">confidence ${(r.confidence*100).toFixed(1)}% · candidate ${escapeHtml(r.candidate_target||'none')}</div></div>`).join(''):'<div class="empty">No quarantined semantic conflicts recorded.</div>';
  }catch(e){ $('semanticConflicts').innerHTML='<div class="empty">Conflict history unavailable.</div>'; }
}

document.querySelectorAll('.nav').forEach(n=>n.addEventListener('click',()=>{
  if(n.dataset.page==='semantic'){ loadSemanticGraph(); loadSemanticConflicts(); }
}));


async function processPipeline(){
  const source=$('pipelineSource').value.trim() || 'unknown';
  const raw=$('pipelineLog').value.trim();
  const key=$('pipelineKey').value.trim() || null;
  if(!raw)return;
  const r=await get('/pipeline/process',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source,raw,idempotency_key:key})});
  $('pipelineResult').innerHTML=`<div class="result">${escapeHtml(JSON.stringify({replayed:r.replayed||false,event_id:r.event_id,status:r.status,parser:r.parser_id,processing_path:r.normalization?.processing_path,lossless:r.lossless,sha256:r.raw_sha256},null,2))}</div>`;
  if(r.status==='quarantine') await loadQuarantine();
  await loadPipelineRuns(); await refreshOverview();
}

async function loadQuarantine(){
  const rows=await get('/quarantine?status=open');
  $('quarantinePanel').innerHTML=rows.length?rows.map(r=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(r.event_id)}</div><div class="event-raw">${escapeHtml(r.severity)} · ${escapeHtml(r.reason)}</div></div><span class="badge warn">OPEN</span></div><div class="event-raw"><button class="ghost" onclick="reviewQuarantine('${r.event_id}','release')">RELEASE</button> <button class="ghost" onclick="reviewQuarantine('${r.event_id}','reject')">REJECT</button></div></div>`).join(''):'<div class="empty">Quarantine queue is clear.</div>';
}

async function reviewQuarantine(id,decision){
  const r=await get('/quarantine/'+encodeURIComponent(id)+'/review',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({decision,reviewer:'SIH analyst',notes:'Reviewed in ULPF Nexus control plane'})});
  await loadQuarantine(); await refreshOverview();
  alert(`${r.event_id}: ${r.status}`);
}

async function loadPipelineRuns(){
  const rows=await get('/pipeline/runs?limit=30');
  $('pipelineRuns').innerHTML=rows.length?rows.map(r=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(r.stage)} · ${escapeHtml(r.status)}</div><div class="event-raw">event ${escapeHtml(r.event_id)} · ${r.duration_ms} ms</div></div><span class="badge good">AUDIT</span></div><div class="event-raw">${escapeHtml(JSON.stringify(r.details))}</div></div>`).join(''):'<div class="empty">No pipeline runs recorded yet.</div>';
}

document.querySelectorAll('.nav').forEach(n=>n.addEventListener('click',()=>{ if(n.dataset.page==='pipeline'){ loadQuarantine(); loadPipelineRuns(); } }));


async function loadQueueMetrics(){
  try{
    const r=await fetch('/api/queue/metrics');
    const q=await r.json();
    const set=(id,v)=>{const el=document.getElementById(id); if(el) el.textContent=v};
    set('q-depth',q.depth); set('q-workers',q.workers); set('q-processed',q.processed); set('q-dlq',q.dead_letter);
    set('q-status', q.backpressure_active ? 'BACKPRESSURE ACTIVE — ingestion is being rate limited.' : `Queue healthy · avg ${q.avg_processing_ms} ms/job · ${q.retry} retries waiting`);
  }catch(e){setTimeout(loadQueueMetrics,3000)}
}
loadQueueMetrics();
setInterval(loadQueueMetrics,5000);

async function loadStreamTelemetry(){try{const r=await fetch('/api/stream/metrics?stream=ulpf-events');const d=await r.json();const set=(id,v)=>{const e=document.getElementById(id);if(e)e.textContent=v};set('s-partitions',d.partition_count);set('s-total',d.total);set('s-available',d.available);set('s-processed',d.processed);const box=document.getElementById('streamPartitionPanel');if(box)box.innerHTML=d.partitions.map(p=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">PARTITION ${p.partition_id}</div><div class="event-raw">${p.count} events · seq ${p.min_sequence??'—'} → ${p.max_sequence??'—'}</div></div><span class="badge good">ORDERED</span></div></div>`).join('')}catch(e){}}
loadStreamTelemetry();
setInterval(loadStreamTelemetry,5000);


async function loadConnectors(){
  const box=document.getElementById('connectorList'); if(!box)return;
  try{
    const d=await get('/connectors/health');
    box.innerHTML=d.connectors.length?d.connectors.map(c=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(c.name)}</div><div class="event-raw">${escapeHtml(c.connector_type)} · source ${escapeHtml(c.source)} · ${c.events_received} events · ${c.bytes_received} bytes</div></div><span class="badge ${c.status==='healthy'?'good':c.status==='disabled'?'warn':'warn'}">${escapeHtml(c.status.toUpperCase())}</span></div><div class="event-raw">${escapeHtml(c.connector_id)} · ${escapeHtml(c.probe?.mode||'—')} · ${escapeHtml(c.probe?.error||'ready')}</div></div>`).join(''):'<div class="empty">No connectors registered yet.</div>';
  }catch(e){box.innerHTML='<div class="empty">Connector plane unavailable.</div>'}
}

async function createConnector(){
  const name=document.getElementById('connName').value.trim();
  const type=document.getElementById('connType').value;
  const source=document.getElementById('connSource').value.trim();
  let config={};
  try{config=JSON.parse(document.getElementById('connConfig').value||'{}')}catch(e){document.getElementById('connectorResult').innerHTML='<div class="result">Invalid configuration JSON.</div>';return;}
  const r=await get('/connectors',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,connector_type:type,source,config,enabled:true})});
  document.getElementById('connectorResult').innerHTML=`<div class="result">Registered ${escapeHtml(r.connector_id)}
Status: ${escapeHtml(r.status)}
Adapter: ${escapeHtml(r.connector_type)}</div>`;
  await loadConnectors();
}

async function receiveConnectorSample(id, raw){
  return get('/connectors/'+encodeURIComponent(id)+'/receive',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({raw,process:true})});
}

document.querySelectorAll('.nav').forEach(n=>n.addEventListener('click',()=>{ if(n.dataset.page==='connectors') loadConnectors(); }));


async function startConnector(id){ const r=await fetch(`/api/connectors/${id}/start`,{method:'POST'}); const j=await r.json(); alert(r.ok?`Runtime started: ${j.type}`:(j.detail||'Failed')); loadConnectors(); }
async function stopConnector(id){ const r=await fetch(`/api/connectors/${id}/stop`,{method:'POST'}); const j=await r.json(); alert(r.ok?'Runtime stopped':(j.detail||'Failed')); loadConnectors(); }

async function loadObservability(){
  try{
    const d=await get('/observability?window_seconds=60');
    const metric=(label,value,accent=false)=>`<div class="metric"><div class="metric-label">${label}</div><div class="metric-value ${accent?'accent':''}">${value}</div></div>`;
    $('obsMetrics').innerHTML=[
      metric('Events / sec',d.events_per_sec,true),
      metric('Avg latency',`${d.avg_latency_ms.toFixed(1)} ms`),
      metric('Trusted rate',`${(d.trust_rate*100).toFixed(1)}%`,true),
      metric('Quarantine',`${(d.quarantine_rate*100).toFixed(1)}%`),
      metric('Active queue',d.queue.active),
      metric('Connectors',`${d.connectors.healthy}/${d.connectors.total}`,true)
    ].join('');
    $('obsHeartbeat').textContent=`LOCAL · ${new Date(d.generated_at).toLocaleTimeString()}`;
    $('obsHealth').innerHTML=[
      ['RECENT EVENTS',d.recent_events],['PROCESSING RUNS',d.processing_runs],['MAX LATENCY',`${d.max_latency_ms.toFixed(1)} ms`],['DLQ',d.queue.dead_letter],['STREAM EVENTS',d.stream.events],['CONNECTOR ERRORS',d.connectors.errors]
    ].map(([k,v])=>`<div class="obs-cell"><span>${k}</span><strong>${v}</strong></div>`).join('');
    const maxStatus=Math.max(1,...d.event_status.map(x=>x.count));
    $('obsStatusBars').innerHTML=d.event_status.map(x=>`<div class="status-bar"><div class="event-row"><span>${escapeHtml(String(x.status).toUpperCase())}</span><b>${x.count}</b></div><div class="bar"><i style="width:${(x.count/maxStatus*100).toFixed(1)}%"></i></div></div>`).join('');
    $('obsStages').innerHTML=d.stage_breakdown.length?d.stage_breakdown.map(x=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(x.stage.toUpperCase())}</div><div class="event-raw">${x.count} runs</div></div><span class="badge good">${x.avg_ms.toFixed(2)} ms</span></div></div>`).join(''):'<div class="empty">No recent processing telemetry.</div>';
    $('obsParsers').innerHTML=d.parser_confidence.length?d.parser_confidence.map(x=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(x.parser_id)}</div><div class="event-raw">${x.events} events</div></div><span class="badge ${x.confidence>=.9?'good':'warn'}">${(x.confidence*100).toFixed(1)}%</span></div></div>`).join(''):'<div class="empty">No parser telemetry.</div>';
  }catch(e){
    const h=$('obsHeartbeat'); if(h) h.textContent='TELEMETRY UNAVAILABLE';
  }
}

document.querySelectorAll('.nav').forEach(n=>n.addEventListener('click',()=>{ if(n.dataset.page==='observability') loadObservability(); }));


async function loadStorage(){
  try {
    const [a,r,ad]=await Promise.all([get('/storage/analytics?window_hours=24'),get('/storage/retention'),get('/storage/adapters')]);
    $('storageMetrics').innerHTML=[
      ['24H EVENTS',a.total],['TRUSTED',a.trusted],['REVIEW',a.review],['QUARANTINE',a.quarantine],
      ['ARCHIVED',a.archived_events],['DB SIZE',`${(a.sqlite_bytes/1024/1024).toFixed(2)} MB`]
    ].map((x,i)=>`<div class="metric"><div class="metric-label">${x[0]}</div><div class="metric-value ${i===1?'accent':''}">${x[1]}</div></div>`).join('');
    $('storageBreakdown').innerHTML=[
      `<div class="event"><div class="event-id">AVERAGE PARSER CONFIDENCE</div><div class="event-raw">${(a.parser_confidence_avg*100).toFixed(1)}%</div></div>`,
      `<div class="event"><div class="event-id">BY SOURCE</div>${a.by_source.map(x=>`<div class="event-raw">${escapeHtml(x.source)} · ${x.count}</div>`).join('')||'<div class="event-raw">No events in window.</div>'}</div>`,
      `<div class="event"><div class="event-id">BY FORMAT</div>${a.by_format.map(x=>`<div class="event-raw">${escapeHtml(x.format)} · ${x.count}</div>`).join('')||'<div class="event-raw">No formats yet.</div>'}</div>`
    ].join('');
    $('retentionPanel').innerHTML=r.policies.map(p=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(p.name)}</div><div class="event-raw">Hot storage ${p.hot_days} days · archive-before-delete ${p.archive_before_delete?'ON':'OFF'}</div></div><span class="badge good">${p.enabled?'ENABLED':'DISABLED'}</span></div></div>`).join('')+
      `<div class="event"><div class="event-raw">Hot events: ${r.stats.hot_events} · Archived: ${r.stats.archived_events}</div></div>`;
    $('storageAdapters').innerHTML=ad.adapters.map(x=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(x.name)}</div><div class="event-raw">${escapeHtml(x.mode)}</div></div><span class="badge ${x.status==='active'?'good':'warn'}">${escapeHtml(x.status.toUpperCase())}</span></div></div>`).join('');
  } catch(e) {
    $('storageBreakdown').innerHTML='<div class="empty">Storage telemetry unavailable.</div>';
  }
}

async function searchStorage(){
  const payload={q:$('storageQ').value.trim()||null,source:$('storageSource').value.trim()||null,status:$('storageStatus').value||null,limit:100};
  const r=await get('/storage/events/search',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  $('storageResult').innerHTML=r.length?r.map(e=>`<div class="event" onclick='showEvent(${JSON.stringify(e)})'><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(e.event_id)}</div><div class="event-raw">${escapeHtml(e.source)} · ${escapeHtml(e.vendor)} · ${escapeHtml(e.format)} · ${escapeHtml(e.parser_id)}</div></div><span class="badge ${e.status==='trusted'?'good':'warn'}">${escapeHtml(e.status.toUpperCase())}</span></div><div class="event-raw">${escapeHtml(e.raw)}</div></div>`).join(''):'<div class="empty">No matching events.</div>';
}

async function applyRetention(dryRun){
  const r=await get(`/storage/retention/apply?dry_run=${dryRun?'true':'false'}`,{method:'POST'});
  $('retentionPanel').innerHTML += `<div class="event"><div class="event-id">RETENTION ${dryRun?'DRY RUN':'APPLIED'}</div><div class="event-raw">${r.affected} events eligible · cutoff ${escapeHtml(r.cutoff)}</div></div>`;
  await loadStorage();
}

document.querySelectorAll('.nav').forEach(n=>n.addEventListener('click',()=>{ if(n.dataset.page==='storage') loadStorage(); }));


async function loadAIRouting(){
  try{
    const [m, rows]=await Promise.all([get('/ai/metrics?window_hours=24'),get('/ai/decisions?limit=30')]);
    $('aiRouteMetrics').innerHTML=[
      ['DECISIONS',m.total_decisions],
      ['AVG CONFIDENCE',(m.average_route_confidence*100).toFixed(1)+'%'],
      ...(m.by_route||[]).slice(0,4).map(x=>[String(x.route).toUpperCase(),x.count])
    ].map((x,i)=>`<div class="metric"><div class="metric-label">${x[0]}</div><div class="metric-value ${i===1?'accent':''}">${x[1]}</div></div>`).join('');
    $('aiDecisionList').innerHTML=rows.length?rows.map(r=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(r.route.toUpperCase())} · ${escapeHtml(r.model)}</div><div class="event-raw">${escapeHtml(r.raw_sha256.slice(0,20))}… · ${escapeHtml(r.source)} · ${escapeHtml(r.status)}</div></div><span class="badge ${r.route==='quarantine'?'warn':'good'}">${(r.confidence*100).toFixed(1)}%</span></div><div class="event-raw">${escapeHtml((r.reasons||[]).join(' · '))}</div></div>`).join(''):'<div class="empty">No routing decisions yet.</div>';
  }catch(e){$('aiDecisionList').innerHTML='<div class="empty">AI routing telemetry unavailable.</div>'}
}

async function testAIRouting(){
  const raw=$('aiRouteLog').value.trim(); if(!raw)return;
  const r=await get('/ai/route',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({raw})});
  $('aiRouteResult').innerHTML=`<div class="result">${escapeHtml(JSON.stringify(r,null,2))}</div>`;
  await loadAIRouting();
}

async function loadForensics(){
  const el=document.getElementById('forensicEvents'); if(!el) return;
  try{
    const rows=await get('/forensics/events?limit=40');
    el.innerHTML=rows.length?rows.map(e=>`<div class="event-row" onclick="selectForensic('${e.event_id}')"><div><b>${escapeHtml(e.event_id.slice(0,12))}…</b><small>${escapeHtml(e.source)} · ${escapeHtml(e.vendor)} · ${escapeHtml(e.status)}</small></div><span class="badge ${e.status==='trusted'?'good':e.status==='quarantine'?'bad':'warn'}">${escapeHtml(e.format)}</span></div>`).join(''):'<div class="empty">No events yet.</div>';
  }catch(err){el.innerHTML=`<div class="empty">${escapeHtml(err.message)}</div>`;}
}
function selectForensic(id){ const input=document.getElementById('forensicEventId'); if(input){input.value=id; inspectForensic();} }
async function inspectForensic(){
  const id=document.getElementById('forensicEventId')?.value?.trim(); const el=document.getElementById('forensicTrace'); if(!id||!el) return;
  try{
    const ev=await get('/forensics/events/'+encodeURIComponent(id));
    const tl=ev.forensic_trace?.timeline||[];
    el.innerHTML=`<div class="timeline">${tl.map((x,i)=>`<div class="timeline-item"><div class="timeline-dot">${i+1}</div><div><b>${escapeHtml(x.stage)}</b><small>${escapeHtml(x.status)} · ${escapeHtml(x.detail||'')}</small></div></div>`).join('')}</div><div class="proof-box"><b>RAW SHA-256</b><code>${escapeHtml(ev.raw_sha256)}</code><b>Parser</b><span>${escapeHtml(ev.parser_id)}</span><b>Lossless</b><span>${ev.lossless?'VERIFIED':'CHECK'}</span></div><details><summary>Raw Event</summary><pre>${escapeHtml(ev.raw)}</pre></details>`;
  }catch(err){el.innerHTML=`<div class="empty">${escapeHtml(err.message)}</div>`;}
}


document.querySelectorAll('.nav').forEach(n=>n.addEventListener('click',()=>{ if(n.dataset.page==='forensics') loadForensics(); }));


async function runEvolution(){
  const source=$('evoSource').value.trim()||'unknown-source';
  const vendor=$('evoVendor').value.trim()||null;
  const candidate=$('evoCandidate').value.trim()||null;
  const samples=$('evoSamples').value.split(/\n+/).map(x=>x.trim()).filter(Boolean);
  if(!samples.length)return;
  const r=await get('/evolution/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source,expected_vendor:vendor,candidate_name:candidate,samples})});
  $('evoRunResult').innerHTML=`<div class="result">FINAL STATE: ${escapeHtml(r.final_state.toUpperCase())}\n\nRun: ${escapeHtml(r.run_id)}\nDNA: ${escapeHtml(r.dna.id)}\nMutation: ${escapeHtml(r.mutation.severity)} · ${escapeHtml(r.mutation.decision)} · similarity ${((r.mutation.similarity||1)*100).toFixed(1)}%\nAI route: ${escapeHtml(r.ai.route)} · ${(r.ai.confidence*100).toFixed(1)}%\nSandbox: ${escapeHtml(r.sandbox?.decision||'not-run')}\nRegression: ${escapeHtml(r.regression)}\n\n${escapeHtml(JSON.stringify(r.reason,null,2))}</div>`;
  await loadEvolutionCC();
}

async function loadEvolutionCC(){
  try{
    const d=await get('/evolution/control-center');
    const stateMap=Object.fromEntries(d.states.map(x=>[x.final_state,x.c]));
    const total=d.states.reduce((a,x)=>a+x.c,0);
    $('evoCCMetrics').innerHTML=[['Runs',total,''],['Trusted',stateMap.trusted||0,'accent'],['Candidate Ready',stateMap['candidate-ready']||0,''],['Review',stateMap.review||0,''],['Quarantine',stateMap.quarantine||0,'']].map(c=>`<div class="metric"><div class="metric-label">${c[0]}</div><div class="metric-value ${c[2]}" style="padding:0 2px">${c[1]}</div></div>`).join('');
    $('evoCCRecent').innerHTML=d.recent.length?d.recent.map(r=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(r.run_id)} · ${escapeHtml(r.source)}</div><div class="event-raw">${escapeHtml(r.final_state)} · AI ${escapeHtml(r.ai_route)} · mutation ${escapeHtml(r.mutation_severity)} · regression ${escapeHtml(r.regression_status)}</div></div><span class="badge ${r.final_state==='trusted'||r.final_state==='candidate-ready'?'good':'warn'}">${escapeHtml(r.final_state.toUpperCase())}</span></div><div class="event-raw">${escapeHtml(r.decision_reason)}</div></div>`).join(''):'<div class="empty">No evolution runs yet.</div>';
  }catch(e){$('evoCCRecent').innerHTML='<div class="empty">Evolution command center unavailable.</div>'}
}


async function loadGPTOSS(){
  try{
    const [d, rows]=await Promise.all([get('/ai/gpt-oss/diagnostics'),get('/ai/mappings?limit=20')]);
    $('gptMetrics').innerHTML=[
      ['MODE',d.enabled?'ENABLED':'DISABLED',d.enabled?'accent':''],
      ['MODEL',d.model||'—',''],
      ['STATUS',(d.available?'AVAILABLE':(d.provider_status||'NOT READY')).toUpperCase(),d.available?'accent':''],
      ['LATENCY',d.latency_ms!=null?`${d.latency_ms} ms`:'—','']
    ].map(x=>`<div class="metric"><div class="metric-label">${x[0]}</div><div class="metric-value ${x[2]}">${escapeHtml(x[1])}</div></div>`).join('');
    $('gptEvidence').innerHTML=rows.length?rows.map(r=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(r.mapping_id)} · ${escapeHtml(r.model)}</div><div class="event-raw">${escapeHtml(r.status)} · ${(Number(r.mapping_confidence)*100).toFixed(1)}% · ${escapeHtml(r.raw_sha256.slice(0,20))}…</div></div><span class="badge ${r.conflicts?.length?'warn':'good'}">${r.conflicts?.length?'REVIEW':'MAPPED'}</span></div><div class="event-raw">Fields: ${Object.keys(r.candidate_mappings||{}).join(', ')||'none'} · Unknown: ${(r.unknown_fields||[]).join(', ')||'none'}</div></div>`).join(''):'<div class="empty">No AI mapping evidence recorded yet.</div>';
  }catch(e){$('gptEvidence').innerHTML='<div class="empty">Local GPT-OSS diagnostics unavailable.</div>'}
}

async function runGPTOSSMap(){
  const raw=$('gptLog').value.trim(); if(!raw)return;
  try{ const r=await get('/ai/gpt-oss/map',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({raw})}); $('gptResult').innerHTML=`<div class="result">${escapeHtml(JSON.stringify(r,null,2))}</div>`; await loadGPTOSS(); }
  catch(e){ $('gptResult').innerHTML=`<div class="result">${escapeHtml(e.message)}</div>`; }
}


async function loadAIContextStatus(){
  try{
    const [st, rows]=await Promise.all([get('/ai/embeddings/status'), get('/ai/retrievals?limit=12')]);
    $('contextMetrics').innerHTML=[
      ['PROVIDER',st.provider || '—',''],
      ['MODEL',st.configured_model || '—',''],
      ['DIMENSION',st.dimension || '—',''],
      ['LOCAL MODEL',st.model_loaded?'LOADED':'FALLBACK',st.model_loaded?'accent':'']
    ].map(x=>`<div class="metric"><div class="metric-label">${escapeHtml(x[0])}</div><div class="metric-value ${x[2]||''}">${escapeHtml(String(x[1]))}</div></div>`).join('');
    $('retrievalHistory').innerHTML=rows.length?rows.map(r=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(r.retrieval_id)} · ${escapeHtml(r.embedding_model)}</div><div class="event-raw">${escapeHtml(r.query_text.slice(0,140))}</div></div><span class="badge good">TOP ${r.top_k}</span></div><div class="event-raw">${r.results?.slice(0,3).map(x=>`${escapeHtml(x.title)} ${(Number(x.score)*100).toFixed(1)}%`).join(' · ')||'no matches'}</div></div>`).join(''):'<div class="empty">No retrievals recorded yet.</div>';
  }catch(e){ $('retrievalHistory').innerHTML='<div class="empty">Local retrieval telemetry unavailable.</div>'; }
}

async function runContextMap(){
  const raw=$('contextLog').value.trim(); if(!raw)return;
  try{
    const r=await get('/ai/context-map',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({raw,source:'context-lab'})});
    const hits=r.retrieved_context?.semantic_results||[];
    $('contextEvidence').innerHTML=hits.length?hits.map(x=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(x.title)} → ${escapeHtml(x.canonical_field||'—')}</div><div class="event-raw">${escapeHtml(x.doc_type)} · score ${(Number(x.score)*100).toFixed(1)}%</div></div><span class="badge good">LOCAL</span></div><div class="event-raw">${escapeHtml(x.content)}</div></div>`).join(''):'<div class="empty">No semantic retrievals.</div>';
    $('contextResult').innerHTML=`<div class="result">${escapeHtml(JSON.stringify({mapping:r.candidate_mappings,unknown:r.unknown_fields,conflicts:r.conflicts,embedding:r.retrieved_context?.embedding},null,2))}</div>`;
    await loadAIContextStatus();
  }catch(e){ $('contextResult').innerHTML=`<div class="result">${escapeHtml(e.message)}</div>`; }
}

document.querySelectorAll('.nav').forEach(n=>n.addEventListener('click',()=>{ if(n.dataset.page==='contextai') loadAIContextStatus(); }));

async function compileContract(){
  const samples=$('contractSamples').value.split('\n').map(x=>x.trim()).filter(Boolean);
  const payload={raw_samples:samples,source:$('contractSource').value.trim()||'unknown-source',name:$('contractName').value.trim()||'compiled-parser',compile_candidate:true};
  const r=await get('/parsers/compile-contract',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const c=r.contract, fields=Object.entries(c.field_mapping||{});
  $('contractResult').innerHTML=`<div class="result">Contract ${escapeHtml(r.contract_id)} · Parser ${escapeHtml(r.parser_id)} · hash ${escapeHtml(c.contract_hash.slice(0,20))}…</div>`;
  $('contractPanel').innerHTML=`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(c.contract_type)} v${c.contract_version}</div><div class="event-raw">Format ${escapeHtml(c.detection.format)} · ${fields.length} mapped fields · ${c.unknown_fields.length} unknown fields</div></div><span class="badge good">SANDBOX GATED</span></div>`+
    `<div class="event-raw">${fields.map(([k,v])=>`${escapeHtml(k)} → ${escapeHtml(v.target)} · ${(v.confidence*100).toFixed(1)}% · ${escapeHtml(v.type)}`).join('<br>')}</div>`+
    `<div class="event-raw">Unknown preserved: ${c.unknown_fields.map(escapeHtml).join(', ')||'none'}</div></div>`;
  await loadContracts();
}

async function loadContracts(){
  const box=$('contractHistory'); if(!box)return;
  try{const rows=await get('/parsers/contracts?limit=30');box.innerHTML=rows.length?rows.map(x=>{const p=x.payload||{};return `<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(x.contract_id)}</div><div class="event-raw">${escapeHtml(x.parser_id)} · v${x.contract_version} · ${escapeHtml(x.status)}</div></div><span class="badge ${x.status==='approved'?'good':'warn'}">${escapeHtml(x.status.toUpperCase())}</span></div><div class="event-raw">${escapeHtml(p.source||'unknown')} · ${escapeHtml(p.contract_hash||'')}</div></div>`}).join(''):'<div class="empty">No contracts yet.</div>';}catch(e){box.innerHTML='<div class="empty">Contract registry unavailable.</div>'}
}

document.querySelectorAll('.nav').forEach(n=>n.addEventListener('click',()=>{ if(n.dataset.page==='contract') loadContracts(); }));


async function executeContract(){
  const contractId=$('execContractId').value.trim(); const raw=$('execContractRaw').value.trim();
  if(!contractId||!raw)return;
  try{
    const r=await get('/contracts/execute',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({contract_id:contractId,raw})});
    $('contractExecResult').innerHTML=`<div class="result">${escapeHtml(JSON.stringify({run_id:r.run_id,status:r.status,coverage:r.coverage,normalized:r.normalized,extensions:r.extensions,validation_errors:r.validation_errors,raw_sha256:r.raw_sha256},null,2))}</div>`;
  }catch(e){$('contractExecResult').innerHTML=`<div class="result">${escapeHtml(e.message)}</div>`;}
}

async function compareContracts(){
  const parserId=$('compareParserId').value.trim(); const versionA=Number($('compareVersionA').value); const versionB=Number($('compareVersionB').value);
  const samples=$('compareSamples').value.split('\n').map(x=>x.trim()).filter(Boolean); if(!parserId||!samples.length)return;
  try{
    const r=await get('/contracts/compare',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({parser_id:parserId,version_a:versionA,version_b:versionB,samples})});
    const badge=r.regression?'warn':'good';
    $('compareResult').innerHTML=`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">v${r.version_a} → v${r.version_b}</div><div class="event-raw">Coverage ${(r.avg_coverage_a*100).toFixed(1)}% → ${(r.avg_coverage_b*100).toFixed(1)}% · Δ ${(r.coverage_delta*100).toFixed(1)}%</div></div><span class="badge ${badge}">${escapeHtml(r.release_decision.toUpperCase())}</span></div><div class="event-raw">${escapeHtml(JSON.stringify(r.results,null,2))}</div></div>`;
  }catch(e){$('compareResult').innerHTML=`<div class="result">${escapeHtml(e.message)}</div>`;}
}

async function loadUnifiedModel(){
  const list=document.getElementById('artifactList'); if(!list)return;
  try{
    const r=await get('/model/artifacts?limit=30');
    list.innerHTML=r.length?r.map(a=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(a.artifact_id)}</div><div class="event-raw">${escapeHtml(a.parser_id)} v${a.parser_version} · ${escapeHtml(a.schema_id)} v${a.schema_version} · contract ${escapeHtml(a.contract_id||'none')} v${a.contract_version??'—'}</div></div><span class="badge good">${escapeHtml(a.status.toUpperCase())}</span></div><div class="event-raw">hash ${escapeHtml(a.artifact_hash)}</div></div>`).join(''):'<div class="empty">No translation artifacts yet. Process an event to create one.</div>';
    const reg=await get('/model/registry?limit=20');
    document.getElementById('modelRegistry').textContent=JSON.stringify(reg,null,2);
  }catch(e){list.innerHTML='<div class="empty">Unified model registry unavailable.</div>'}
}
document.querySelectorAll('.nav').forEach(n=>n.addEventListener('click',()=>{ if(n.dataset.page==='model') loadUnifiedModel(); }));

async function loadInvestigationSearch(){
  const q=($('investigationQ')?.value||'').trim();
  const status=($('investigationStatus')?.value||'').trim();
  const source=($('investigationSource')?.value||'').trim();
  const params=new URLSearchParams(); if(q)params.set('q',q); if(status)params.set('status',status); if(source)params.set('source',source); params.set('limit','40');
  const box=$('investigationResults'); if(!box)return;
  try{
    const rows=await get('/investigation/search?'+params.toString());
    box.innerHTML=rows.length?rows.map(r=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(r.event_id)}</div><div class="event-raw">${escapeHtml(r.source)} · ${escapeHtml(r.vendor)} · ${escapeHtml(r.format)} · ${escapeHtml(r.status)}</div></div><span class="badge ${r.status==='trusted'?'good':r.status==='quarantine'?'warn':'warn'}">${escapeHtml(r.status.toUpperCase())}</span></div><div class="event-raw">${escapeHtml(r.raw_sha256)} · ${escapeHtml(r.parser_id)} · schema ${escapeHtml(String(r.schema_version??'—'))} · artifact ${escapeHtml(r.artifact_id||'—')}</div><button class="ghost" onclick="selectInvestigation('${escapeHtml(r.event_id)}')">OPEN</button></div>`).join(''):'<div class="empty">No matching events.</div>';
  }catch(e){box.innerHTML=`<div class="empty">${escapeHtml(e.message)}</div>`;}
}
function selectInvestigation(id){ $('investigationEventId').value=id; inspectInvestigation(); }
async function inspectInvestigation(){
  const id=($('investigationEventId')?.value||'').trim(); if(!id)return;
  try{
    const r=await get('/investigation/'+encodeURIComponent(id));
    const e=r.event||{}; const proof=r.forensic_trace?.proof||{};
    $('investigationBundle').innerHTML=`<div class="result"><b>${escapeHtml(e.event_id||id)}</b> · ${escapeHtml(e.status||'—')}<br>Raw SHA-256: ${escapeHtml(r.integrity?.raw_sha256||e.raw_sha256||'—')}<br>Parser: ${escapeHtml(e.parser_id||'—')} · Schema: ${escapeHtml(r.model_ref?.schema_id||'—')} v${escapeHtml(String(r.model_ref?.schema_version??'—'))} · Artifact: ${escapeHtml(r.model_ref?.artifact_id||'—')}</div>`+
      `<div class="event"><div class="event-id">RAW EVENT</div><pre class="code-block">${escapeHtml(e.raw||'')}</pre></div>`+
      `<div class="event"><div class="event-id">NORMALIZED EVENT</div><pre class="code-block">${escapeHtml(JSON.stringify(e.normalized||{},null,2))}</pre></div>`+
      `<div class="event"><div class="event-id">FORENSIC TIMELINE</div><div class="event-raw">${(r.forensic_trace?.timeline||[]).map(t=>`${escapeHtml(t.stage)}: ${escapeHtml(t.status)}${t.detail?' · '+escapeHtml(t.detail):''}`).join('<br>')||'—'}</div></div>`+
      `<div class="event"><div class="event-id">AI EVIDENCE</div><pre class="code-block">${escapeHtml(JSON.stringify({mappings:r.ai_mapping_evidence,decisions:r.ai_decisions},null,2))}</pre></div>`+
      `<div class="event"><div class="event-id">MUTATION / EVOLUTION</div><pre class="code-block">${escapeHtml(JSON.stringify({mutation_history:r.mutation_history,evolution_history:r.evolution_history},null,2))}</pre></div>`+
      `<div class="event"><div class="event-id">INTEGRITY</div><div class="event-raw">Raw verified: ${r.integrity?.raw_sha256_matches?'YES':'NO'} · Information loss: ${proof.information_loss?'YES':'NO'}</div></div>`;
  }catch(e){$('investigationBundle').innerHTML=`<div class="result">${escapeHtml(e.message)}</div>`;}
}
async function verifyInvestigation(){
  const id=($('investigationEventId')?.value||'').trim(); if(!id)return;
  try{ const r=await get('/investigation/'+encodeURIComponent(id)+'/verify',{method:'POST'}); $('investigationBundle').innerHTML=`<div class="result"><b>INTEGRITY CHECK</b><br>Raw SHA-256: ${r.raw_integrity?'PASS':'FAIL'}<br>Normalized SHA-256: ${r.normalized_hash_matches?'PASS':'FAIL'}<br>Lossless: ${r.lossless?'YES':'NO'}<br><br>${escapeHtml(JSON.stringify(r,null,2))}</div>`; }catch(e){$('investigationBundle').innerHTML=`<div class="result">${escapeHtml(e.message)}</div>`;}
}
document.querySelectorAll('.nav').forEach(n=>n.addEventListener('click',()=>{if(n.dataset.page==='investigation') loadInvestigationSearch();}));


// -------------------- v2.7 threat hunting --------------------
async function loadThreatSummary(){
  try{
    const r=await get('/threat-hunt/summary?limit=2000');
    const vals=[['EVENTS',r.total],['ACTIONS',Object.keys(r.actions||{}).length],['SOURCES',Object.keys(r.sources||{}).length],['PROTOCOLS',Object.keys(r.protocols||{}).length]];
    $('huntSummary').innerHTML=vals.map(x=>`<div class="metric"><div class="metric-label">${escapeHtml(x[0])}</div><div class="metric-value">${escapeHtml(String(x[1]))}</div></div>`).join('');
    $('huntEdges').innerHTML=Object.entries(r.actions||{}).slice(0,8).map(([k,v])=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">ACTION ${escapeHtml(k)}</div><div class="event-raw">${v} events</div></div><span class="badge good">LOCAL</span></div></div>`).join('') || '<div class="empty">No events available for hunting.</div>';
    await loadThreatCorrelation();
    await loadThreatTimeline();
  }catch(e){ $('huntSummary').innerHTML='<div class="empty">Threat hunting telemetry unavailable.</div>'; }
}
async function runThreatHunt(){
  const body={source:$('huntSource').value.trim()||null,src_ip:$('huntSrcIp').value.trim()||null,dst_ip:$('huntDstIp').value.trim()||null,action:$('huntAction').value.trim()||null,text:$('huntText').value.trim()||null,limit:200};
  try{
    const r=await get('/threat-hunt/search',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    $('huntResult').innerHTML=`<div class="result"><b>${r.count} matching events</b><br>${escapeHtml(JSON.stringify(r.summary,null,2))}</div>`;
    $('huntTimeline').innerHTML=(r.events||[]).map(e=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(e.event_id||'')}</div><div class="event-raw">${escapeHtml(e.ingested_at||'')} · ${escapeHtml(e.source||'')} · ${escapeHtml(e.status||'')}</div></div><span class="badge ${e.status==='trusted'?'good':'warn'}">${escapeHtml((e.status||'').toUpperCase())}</span></div><div class="event-raw">${escapeHtml(String(e.normalized?.['source.ip']||'—'))} → ${escapeHtml(String(e.normalized?.['destination.ip']||'—'))} · ${escapeHtml(String(e.normalized?.['event.action']||'—'))}</div></div>`).join('') || '<div class="empty">No matching events.</div>';
  }catch(e){ $('huntResult').innerHTML=`<div class="result">${escapeHtml(e.message)}</div>`; }
}
async function loadThreatCorrelation(){
  try{
    const r=await get('/threat-hunt/correlation?window_seconds=300&limit=1000');
    $('huntCorrelation').innerHTML=(r.top_edges||[]).map(x=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(x.relationship)}</div><div class="event-raw">${x.count} correlated events</div></div><span class="badge good">FLOW</span></div></div>`).join('') + ((r.bursts||[]).length?`<div class="result" style="margin-top:10px"><b>BURST SIGNALS</b><br>${r.bursts.map(b=>`${escapeHtml(b.source_ip)} → ${escapeHtml(b.destination_ip)} · ${b.events_in_window} events / ${b.window_seconds}s`).join('<br>')}</div>`:'');
  }catch(e){ $('huntCorrelation').innerHTML='<div class="empty">Correlation unavailable.</div>'; }
}
async function loadThreatTimeline(){
  try{
    const r=await get('/threat-hunt/timeline?limit=80');
    $('huntTimeline').innerHTML=(r.timeline||[]).slice(-40).reverse().map(e=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(e.event_id||'')}</div><div class="event-raw">${escapeHtml(e.timestamp||'')} · ${escapeHtml(e.source||'')}</div></div><span class="badge ${e.status==='trusted'?'good':'warn'}">${escapeHtml((e.action||'EVENT').toUpperCase())}</span></div><div class="event-raw">${escapeHtml(String(e.src_ip||'—'))} → ${escapeHtml(String(e.dst_ip||'—'))}</div></div>`).join('') || '<div class="empty">No timeline events.</div>';
  }catch(e){ $('huntTimeline').innerHTML='<div class="empty">Timeline unavailable.</div>'; }
}
document.querySelectorAll('.nav').forEach(n=>n.addEventListener('click',()=>{if(n.dataset.page==='threathunt') loadThreatSummary();}));


// -------------------- v2.8 detection & alerts --------------------
async function loadDetectionCenter(){
  try{
    const [s,r,a]=await Promise.all([get('/detections/summary'),get('/detections/rules'),get('/detections/alerts?limit=50')]);
    const open=(s.alerts_by_status||{}).open||0;
    $('detectionMetrics').innerHTML=[['RULES',s.rules?.enabled||0],['OPEN ALERTS',open],['HIGH/CRITICAL',Object.entries(s.alerts_by_severity||{}).filter(([k])=>k==='high'||k==='critical').reduce((n,[,v])=>n+v,0)],['TOTAL ALERTS',Object.values(s.alerts_by_status||{}).reduce((n,v)=>n+v,0)]].map(x=>`<div class="metric"><div class="metric-label">${x[0]}</div><div class="metric-value">${x[1]}</div></div>`).join('');
    $('ruleList').innerHTML=(r.rules||[]).map(x=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(x.rule_id)} · v${x.version}</div><div class="event-raw">${escapeHtml(x.name)} · ${escapeHtml(x.severity)} · threshold ${x.threshold}/${x.window_seconds}s</div></div><span class="badge ${x.enabled?'good':'warn'}">${x.enabled?'ENABLED':'DISABLED'}</span></div><div class="event-raw">${escapeHtml((x.conditions||[]).map(c=>`${c.field} ${c.operator} ${c.value??''}`).join(' AND '))}</div></div>`).join('')||'<div class="empty">No detection rules yet.</div>';
    renderAlerts(a.alerts||[]);
  }catch(e){$('ruleList').innerHTML=`<div class="empty">${escapeHtml(e.message)}</div>`;}
}
function renderAlerts(alerts){
  $('alertList').innerHTML=(alerts||[]).map(x=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(x.alert_id)}</div><div class="event-raw">${escapeHtml(x.title)} · ${escapeHtml(x.severity.toUpperCase())} · ${escapeHtml(x.status)}</div></div><span class="badge ${x.severity==='critical'||x.severity==='high'?'bad':x.status==='open'?'warn':'good'}">${escapeHtml(x.status.toUpperCase())}</span></div><div class="event-raw">${escapeHtml(x.description||'')} · score ${x.score}<br>Events: ${(x.event_ids||[]).map(escapeHtml).join(', ')||'—'}</div><div class="button-row" style="margin-top:8px"><button class="ghost" onclick="updateAlert('${x.alert_id}','acknowledged')">ACK</button><button class="ghost" onclick="updateAlert('${x.alert_id}','resolved')">RESOLVE</button><button class="ghost" onclick="updateAlert('${x.alert_id}','dismissed')">DISMISS</button></div></div>`).join('')||'<div class="empty">No alerts.</div>';
}
async function createDetectionRule(){
  const body={name:$('ruleName').value.trim(),severity:$('ruleSeverity').value,threshold:Number($('ruleThreshold').value||1),window_seconds:Number($('ruleWindow').value||300),conditions:[{field:$('ruleField').value,operator:$('ruleOperator').value,value:$('ruleValue').value}]};
  try{const r=await get('/detections/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});$('ruleResult').innerHTML=`<div class="result">Created <b>${escapeHtml(r.rule_id)}</b> v${r.version}</div>`;await loadDetectionCenter();}catch(e){$('ruleResult').innerHTML=`<div class="result">${escapeHtml(e.message)}</div>`;}
}
async function runDetectionEngine(){try{const r=await get('/detections/run?limit=5000',{method:'POST'});$('ruleResult').innerHTML=`<div class="result"><b>${r.fired} alert(s) fired</b><br>${escapeHtml(JSON.stringify(r.alerts||[],null,2))}</div>`;await loadDetectionCenter();}catch(e){$('ruleResult').innerHTML=`<div class="result">${escapeHtml(e.message)}</div>`;}}
async function updateAlert(id,status){try{await get('/detections/alerts/'+encodeURIComponent(id),{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({status})});await loadDetectionCenter();}catch(e){alert(e.message)}}
document.querySelectorAll('.nav').forEach(n=>n.addEventListener('click',()=>{if(n.dataset.page==='detections') loadDetectionCenter();}));

// -------------------- v2.9 multi-event correlation --------------------
async function loadCorrelationCenter(){
  try{
    const [s,r,i]=await Promise.all([get('/correlations/summary'),get('/correlations/rules'),get('/correlations/incidents?limit=50')]);
    const open=(s.incidents_by_status||{}).open||0;
    $('corrMetrics').innerHTML=[['RULES',s.rules?.enabled||0],['OPEN INCIDENTS',open],['HIGH/CRITICAL',Object.entries(s.incidents_by_severity||{}).filter(([k])=>k==='high'||k==='critical').reduce((n,[,v])=>n+v,0)],['TOTAL INCIDENTS',Object.values(s.incidents_by_status||{}).reduce((n,v)=>n+v,0)]].map(x=>`<div class="metric"><div class="metric-label">${x[0]}</div><div class="metric-value">${x[1]}</div></div>`).join('');
    $('corrRules').innerHTML=(r.rules||[]).map(x=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(x.rule_id)} · v${x.version}</div><div class="event-raw">${escapeHtml(x.name)} · ${escapeHtml(x.severity)} · ${x.window_seconds}s · group ${escapeHtml(x.group_by||'none')}</div></div><span class="badge ${x.enabled?'good':'warn'}">${x.enabled?'ENABLED':'DISABLED'}</span></div><div class="event-raw">${(x.steps||[]).map((st,i)=>`${i+1}. ${escapeHtml(st.name)} — ${(st.conditions||[]).map(c=>escapeHtml(`${c.field} ${c.operator} ${c.value??''}`)).join(' AND ')}`).join('<br>')}</div></div>`).join('')||'<div class="empty">No correlation rules yet.</div>';
    renderCorrelationIncidents(i.incidents||[]);
  }catch(e){$('corrRules').innerHTML=`<div class="empty">${escapeHtml(e.message)}</div>`;}
}
function renderCorrelationIncidents(items){
  $('corrIncidents').innerHTML=(items||[]).map(x=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(x.incident_id)}</div><div class="event-raw">${escapeHtml(x.title)} · ${escapeHtml(x.severity.toUpperCase())} · ${escapeHtml(x.status)} · score ${x.score}</div></div><span class="badge ${x.severity==='critical'||x.severity==='high'?'bad':x.status==='open'?'warn':'good'}">${escapeHtml(x.status.toUpperCase())}</span></div><div class="event-raw">${escapeHtml(x.description||'')}<br><b>Sequence:</b> ${(x.step_matches||[]).map(st=>`${escapeHtml(st.name)} → ${escapeHtml(st.event_id||'')}`).join(' · ')}<br><b>Elapsed:</b> ${escapeHtml(String(x.evidence?.elapsed_seconds??'—'))}s</div><div class="button-row" style="margin-top:8px"><button class="ghost" onclick="updateCorrelationIncident('${x.incident_id}','acknowledged')">ACK</button><button class="ghost" onclick="updateCorrelationIncident('${x.incident_id}','resolved')">RESOLVE</button><button class="ghost" onclick="updateCorrelationIncident('${x.incident_id}','dismissed')">DISMISS</button></div></div>`).join('')||'<div class="empty">No correlated incidents.</div>';
}
async function createCorrelationRule(){
  const body={name:$('corrName').value.trim(),description:'Ordered sequence detected within a bounded local window.',severity:$('corrSeverity').value,window_seconds:Number($('corrWindow').value||900),group_by:$('corrGroup').value||null,steps:[{name:'FAILED LOGIN',conditions:[{field:'event.action',operator:'eq',value:$('corrStep1').value.trim()}]},{name:'SUCCESSFUL LOGIN',conditions:[{field:'event.action',operator:'eq',value:$('corrStep2').value.trim()}]},{name:'SENSITIVE ACCESS',conditions:[{field:'destination.port',operator:'eq',value:$('corrStep3').value.trim()}]}]};
  try{const r=await get('/correlations/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});$('corrResult').innerHTML=`<div class="result">Created <b>${escapeHtml(r.rule_id)}</b> v${r.version}</div>`;await loadCorrelationCenter();}catch(e){$('corrResult').innerHTML=`<div class="result">${escapeHtml(e.message)}</div>`;}
}
async function runCorrelationEngine(){try{const r=await get('/correlations/run?limit=10000',{method:'POST'});$('corrResult').innerHTML=`<div class="result"><b>${r.created} incident(s) created</b><br>${escapeHtml(JSON.stringify(r.incidents||[],null,2))}</div>`;await loadCorrelationCenter();}catch(e){$('corrResult').innerHTML=`<div class="result">${escapeHtml(e.message)}</div>`;}}
async function updateCorrelationIncident(id,status){try{await get('/correlations/incidents/'+encodeURIComponent(id),{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({status})});await loadCorrelationCenter();}catch(e){alert(e.message)}}
document.querySelectorAll('.nav').forEach(n=>n.addEventListener('click',()=>{if(n.dataset.page==='correlation') loadCorrelationCenter();}));

async function loadInvestigationGraph(){
  try{
    const g=await get('/investigation-graph');
    const m=document.getElementById('graphMetrics');
    if(m)m.innerHTML=`<div class="metric"><span>Nodes</span><strong>${g.node_count}</strong></div><div class="metric"><span>Edges</span><strong>${g.edge_count}</strong></div><div class="metric"><span>Incident</span><strong>${escapeHtml(g.incident?.incident_id||'—')}</strong></div><div class="metric"><span>Status</span><strong>${escapeHtml(g.incident?.status||'—')}</strong></div>`;
    const c=document.getElementById('graphCanvas');
    if(!c)return;
    if(!g.nodes?.length){c.innerHTML='<div class="empty">No correlated incident exists yet. Create/run a correlation rule first.</div>';return;}
    const byId={}; (g.nodes||[]).forEach(n=>byId[n.id]=n);
    c.innerHTML=(g.nodes||[]).map(n=>{
      const cls=n.type==='incident'?'graph-node incident':n.type==='event'?'graph-node event':n.type==='entity'?'graph-node entity':n.type==='ai_evidence'?'graph-node ai':n.type==='dna'?'graph-node dna':n.type==='parser'?'graph-node parser':n.type==='alert'?'graph-node alert':'graph-node';
      return `<div class="${cls}" data-node="${escapeHtml(n.id)}"><span class="graph-type">${escapeHtml(n.type)}</span><b>${escapeHtml(n.label)}</b><small>${escapeHtml(Object.entries(n.data||{}).filter(([k])=>['source','action','source_ip','destination_ip','severity','status'].includes(k)).map(([k,v])=>`${k}: ${v}`).join(' · '))}</small></div>`;
    }).join('')+`<div class="graph-edges">`+(g.edges||[]).map(e=>`<div class="graph-edge"><b>${escapeHtml(byId[e.source]?.label||e.source)}</b> <span>→ ${escapeHtml(e.relation)} →</span> <b>${escapeHtml(byId[e.target]?.label||e.target)}</b></div>`).join('')+'</div>';
    const details=document.getElementById('graphDetails'); if(details)details.textContent=JSON.stringify(g.incident,null,2);
  }catch(e){const c=document.getElementById('graphCanvas'); if(c)c.innerHTML='<div class="empty">Investigation graph unavailable.</div>'}
}
document.querySelectorAll('.nav').forEach(n=>n.addEventListener('click',()=>{ if(n.dataset.page==='graph') loadInvestigationGraph(); }));


// -------------------- v3.1 risk intelligence --------------------
async function loadRiskCenter(){
  try{
    const s=await get('/risk/summary');
    const box=document.getElementById('riskSummary');
    if(box){box.innerHTML=[['LOW',s.bands?.low?.count||0],['MEDIUM',s.bands?.medium?.count||0],['HIGH',s.bands?.high?.count||0],['CRITICAL',s.bands?.critical?.count||0]].map(([k,v])=>`<div class="metric"><span>${k}</span><strong>${v}</strong></div>`).join('');}
    const r=await get('/risk/latest?limit=20');
    const list=document.getElementById('riskRecent');
    if(list) list.innerHTML=(r.assessments||[]).map(a=>`<div class="event"><div><b>${escapeHtml(a.band.toUpperCase())} · ${escapeHtml(a.entity_id)}</b><span>${Number(a.score).toFixed(1)}/100 · confidence ${Math.round(Number(a.confidence)*100)}%</span></div><small>${escapeHtml(a.summary||'')}</small><button class="ghost" onclick='showRisk(${JSON.stringify(a)})'>VIEW EVIDENCE</button></div>`).join('') || '<div class="empty">No risk assessments yet.</div>';
  }catch(e){const b=document.getElementById('riskRecent');if(b)b.innerHTML=`<div class="empty">${escapeHtml(e.message)}</div>`;}
}
async function assessIncidentRisk(){
  const id=(document.getElementById('riskIncidentId')?.value||'').trim(); if(!id)return;
  try{const r=await fetch('/api/risk/incident/'+encodeURIComponent(id),{method:'POST'}); const data=await r.json(); if(!r.ok)throw new Error(data.detail||'Risk assessment failed'); document.getElementById('riskResult').innerHTML=`<div class="result"><b>${escapeHtml(data.band.toUpperCase())} · ${Number(data.score).toFixed(1)}/100</b><br/>Confidence: ${Math.round(Number(data.confidence)*100)}%<br/>${escapeHtml(data.summary||'')}<br/><br/>${escapeHtml(data.factors.map(f=>`${f.name}: ${f.contribution}`).join(' · '))}</div>`; loadRiskCenter();}catch(e){document.getElementById('riskResult').innerHTML=`<div class="result">${escapeHtml(e.message)}</div>`;}
}
function showRisk(a){const box=document.getElementById('riskResult'); if(!box)return; box.innerHTML=`<div class="result"><b>${escapeHtml(a.risk_id)}</b><br/>${escapeHtml(a.entity_type)}: ${escapeHtml(a.entity_id)}<br/><b>${Number(a.score).toFixed(1)}/100 · ${escapeHtml(a.band.toUpperCase())}</b><br/><pre class="code-block">${escapeHtml(JSON.stringify(a.factors,null,2))}</pre></div>`;}
document.querySelectorAll('.nav').forEach(n=>n.addEventListener('click',()=>{ if(n.dataset.page==='risk') loadRiskCenter(); }));


// -------------------- v3.2 automated risk propagation & analyst queue --------------------
async function loadRiskQueue(){
  try{
    const [q,s]=await Promise.all([get('/risk/queue?limit=100'),get('/risk/priority-summary')]);
    const box=document.getElementById('riskPrioritySummary');
    if(box){box.innerHTML=[['P1 CRITICAL',s.priority?.bands?.P1?.count||0],['P2 HIGH',s.priority?.bands?.P2?.count||0],['P3 MEDIUM',s.priority?.bands?.P3?.count||0],['P4 LOW',s.priority?.bands?.P4?.count||0],['OVER SLA',s.priority?.over_sla||0]].map(([k,v])=>`<div class="metric"><span>${k}</span><strong>${v}</strong></div>`).join('');}
    const list=document.getElementById('riskQueueList');
    if(list) list.innerHTML=(q.queue||[]).map(x=>`<div class="event" onclick='selectRiskQueue(${JSON.stringify(x)})'><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(x.queue_id)} · ${escapeHtml(x.entity_type)} · ${escapeHtml(x.entity_id)}</div><div class="event-raw">Risk ${Number(x.priority_score).toFixed(1)} · ${escapeHtml(x.priority_reason||'')}</div></div><span class="badge ${x.priority_band==='P1'?'warn':'good'}">${escapeHtml(x.priority_band)}</span></div><small>Status: ${escapeHtml(x.status)} · SLA: ${escapeHtml(x.sla_due_at||'—')}</small></div>`).join('') || '<div class="empty">No open risk queue items. Run propagation after generating alerts/incidents.</div>';
  }catch(e){const list=document.getElementById('riskQueueList');if(list)list.innerHTML=`<div class="empty">${escapeHtml(e.message)}</div>`;}
}
async function propagateRisk(){
  try{const r=await fetch('/api/risk/propagate',{method:'POST'});const d=await r.json();if(!r.ok)throw new Error(d.detail||'Propagation failed');const box=document.getElementById('riskQueueResult');if(box)box.innerHTML=`<div class="result">Processed alerts: ${d.processed.alerts}\nProcessed incidents: ${d.processed.incidents}\nQueue depth: ${d.queue_depth}</div>`;loadRiskQueue();}catch(e){const box=document.getElementById('riskQueueResult');if(box)box.innerHTML=`<div class="result">${escapeHtml(e.message)}</div>`;}
}
function selectRiskQueue(x){
  const id=document.getElementById('riskQueueId'); if(id)id.value=x.queue_id;
  const st=document.getElementById('riskQueueStatus'); if(st)st.value=x.status==='open'?'acknowledged':x.status;
}
async function updateRiskQueue(){
  const id=(document.getElementById('riskQueueId')?.value||'').trim(); const status=document.getElementById('riskQueueStatus')?.value||'acknowledged'; const analyst=(document.getElementById('riskQueueAnalyst')?.value||'SIH-Analyst').trim(); if(!id)return;
  try{const r=await fetch('/api/risk/queue/'+encodeURIComponent(id)+'?status='+encodeURIComponent(status)+'&analyst='+encodeURIComponent(analyst),{method:'PATCH'});const d=await r.json();if(!r.ok)throw new Error(d.detail||'Queue update failed');document.getElementById('riskQueueResult').innerHTML=`<div class="result">${escapeHtml(d.queue_id)} → ${escapeHtml(d.status)}\nAnalyst: ${escapeHtml(d.assigned_to||'—')}</div>`;loadRiskQueue();}catch(e){document.getElementById('riskQueueResult').innerHTML=`<div class="result">${escapeHtml(e.message)}</div>`;}
}
document.querySelectorAll('.nav').forEach(n=>n.addEventListener('click',()=>{ if(n.dataset.page==='riskqueue') loadRiskQueue(); }));


// -------------------- v3.3 entity intelligence & attack paths --------------------
async function loadEntityCenter(){
  try{
    const [sum,ents,paths]=await Promise.all([get('/entities/summary'),get('/entities?limit=30'),get('/attack-paths?limit=20')]);
    const metrics=[['ENTITIES',sum.entity_count ?? (sum.entities_by_type||[]).reduce((n,x)=>n+Number(x.count||0),0)],['RELATIONSHIPS',(sum.relationships_by_type||[]).reduce((n,x)=>n+Number(x.count||0),0)],['IP NODES',(sum.entities_by_type||[]).find(x=>x.entity_type==='ip')?.count||0],['ATTACK PATHS',(paths||[]).length]];
    const m=document.getElementById('entityMetrics');if(m)m.innerHTML=metrics.map(x=>`<div class="metric"><span>${x[0]}</span><strong>${x[1]}</strong></div>`).join('');
    const list=document.getElementById('entityList');if(list)list.innerHTML=(ents||[]).map(e=>`<div class="event" onclick='showEntity(${JSON.stringify(e)})'><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(e.entity_id)}</div><div class="event-raw">${escapeHtml(e.entity_type.toUpperCase())} · ${escapeHtml(e.display_name)} · ${e.observation_count} observations</div></div><span class="badge ${Number(e.risk_score)>60?'warn':'good'}">RISK ${Number(e.risk_score).toFixed(1)}</span></div><small>${escapeHtml(e.last_seen||'')}</small></div>`).join('')||'<div class="empty">No entities yet. Rebuild the graph after ingesting events.</div>';
    renderAttackPaths(paths||[]);
  }catch(e){const r=document.getElementById('entityResult');if(r)r.innerHTML=`<div class="result">${escapeHtml(e.message)}</div>`}
}
function renderAttackPaths(items){
  const box=document.getElementById('attackPathList'); if(!box)return;
  box.innerHTML=(items||[]).map(x=>`<div class="event" onclick="showAttackPath('${x.path_id}')"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(x.path_id)}</div><div class="event-raw">${escapeHtml(x.title)} · ${escapeHtml(x.severity.toUpperCase())} · score ${Number(x.score).toFixed(0)}</div></div><span class="badge ${x.severity==='critical'?'warn':'good'}">${escapeHtml(x.status.toUpperCase())}</span></div><small>${escapeHtml(String(x.event_ids?.length||0))} linked events · ${escapeHtml(String(x.evidence?.elapsed_seconds||0))}s</small></div>`).join('')||'<div class="empty">No attack-path candidates detected.</div>';
}
async function rebuildEntities(){
  try{const r=await get('/entities/rebuild',{method:'POST'});const b=document.getElementById('entityResult');if(b)b.innerHTML=`<div class="result">Scanned ${r.events_scanned} events · ${r.entity_count} entities · ${r.relationship_count} relationships.</div>`;await loadEntityCenter();}catch(e){document.getElementById('entityResult').innerHTML=`<div class="result">${escapeHtml(e.message)}</div>`;}
}
async function buildAttackPaths(){
  try{const r=await get('/attack-paths/build',{method:'POST'});const b=document.getElementById('entityResult');if(b)b.innerHTML=`<div class="result">Created ${r.created} new attack-path candidate(s).</div>`;await loadEntityCenter();}catch(e){document.getElementById('entityResult').innerHTML=`<div class="result">${escapeHtml(e.message)}</div>`;}
}
async function showEntity(e){
  try{const d=await get('/entities/'+encodeURIComponent(e.entity_id));const box=document.getElementById('entityDetail');if(box)box.textContent=JSON.stringify(d,null,2);}catch(err){document.getElementById('entityDetail').textContent=err.message;}
}
async function showAttackPath(id){
  try{const d=await get('/attack-paths/'+encodeURIComponent(id));const box=document.getElementById('entityDetail');if(box)box.textContent=JSON.stringify(d,null,2);}catch(err){document.getElementById('entityDetail').textContent=err.message;}
}
document.querySelectorAll('.nav').forEach(n=>n.addEventListener('click',()=>{if(n.dataset.page==='entities')loadEntityCenter();}));

// -------------------- v3.4 interactive attack-path graph --------------------
let attackGraphData=null;
let attackGraphTransform={x:0,y:0,k:1};
let attackGraphDrag=null;
let attackGraphPositions={};

async function loadAttackPathCatalog(){
  const select=document.getElementById('attackPathSelect'); if(!select)return;
  try{
    const paths=await get('/attack-paths?limit=100');
    const current=select.value;
    select.innerHTML='<option value="">Select a path…</option>'+(paths||[]).map(p=>`<option value="${escapeHtml(p.path_id)}">${escapeHtml(p.title)} · ${escapeHtml(p.severity.toUpperCase())} · ${Number(p.score).toFixed(0)}</option>`).join('');
    if(current && [...select.options].some(o=>o.value===current))select.value=current;
    if(!select.value && paths?.length){select.value=paths[0].path_id; await loadSelectedAttackPath();}
  }catch(e){const state=document.getElementById('attackGraphState');if(state){state.textContent='ERROR';state.className='badge warn';}}
}

async function loadSelectedAttackPath(){
  const id=document.getElementById('attackPathSelect')?.value;
  if(!id)return;
  try{
    attackGraphData=await get('/attack-paths/'+encodeURIComponent(id)+'/graph');
    renderAttackGraph();
  }catch(e){const box=document.getElementById('graphSelectedNode');if(box)box.innerHTML=`<div class="result">${escapeHtml(e.message)}</div>`;}
}

function attackNodeClass(type){
  if(type==='attack_path')return 'path';
  if(type==='event')return 'event';
  if(type==='entity')return 'entity';
  if(type==='action')return 'action';
  if(type==='risk')return 'risk';
  return 'event';
}
function graphNodeDisplay(n){
  const d=n.data||{};
  if(n.type==='event') return [n.label, d.action ? `${d.source_ip||'—'} → ${d.destination_ip||'—'} · ${d.action}` : (d.source||'event')];
  if(n.type==='entity') return [n.label, `${d.role||'entity'} · ${d.entity_type||''}`];
  if(n.type==='action') return [n.label, 'event.action'];
  if(n.type==='risk') return [n.label, `${d.band||'RISK'} · confidence ${Math.round(Number(d.confidence||0)*100)}%`];
  return [n.label, `${d.severity||''} · score ${Number(d.score||0).toFixed(0)}`];
}
function buildAttackGraphLayout(data){
  const nodes=data.nodes||[]; const pathEvents=(data.path?.event_ids||[]);
  const pos={}; const cx=480; const step=145;
  pathEvents.forEach((eid,i)=>{pos['event:'+eid]={x:cx,y:90+i*step};});
  nodes.filter(n=>n.type==='entity').forEach((n,i)=>{const eventN=nodes.find(x=>x.id.startsWith('event:') && ((x.data||{}).source_ip===n.data?.value || (x.data||{}).destination_ip===n.data?.value));pos[n.id]={x:n.data?.role==='source'?180:780,y:120+i*90};});
  nodes.filter(n=>n.type==='action').forEach((n,i)=>{pos[n.id]={x:cx+260,y:250+i*110};});
  const p=nodes.find(n=>n.type==='attack_path'); if(p)pos[p.id]={x:cx,y:30};
  const r=nodes.find(n=>n.type==='risk'); if(r)pos[r.id]={x:cx,y:Math.max(160,90+pathEvents.length*step)};
  nodes.forEach((n,i)=>{if(!pos[n.id])pos[n.id]={x:90+(i%5)*190,y:520+Math.floor(i/5)*80};});
  return pos;
}
function renderAttackGraph(){
  const svg=document.getElementById('attackGraphSvg'); if(!svg||!attackGraphData)return;
  attackGraphPositions=buildAttackGraphLayout(attackGraphData);
  const nodes=attackGraphData.nodes||[], byId=Object.fromEntries(nodes.map(n=>[n.id,n]));
  const edgeSvg=(attackGraphData.edges||[]).map(e=>{
    const a=attackGraphPositions[e.source]||{x:0,y:0},b=attackGraphPositions[e.target]||{x:0,y:0};
    const cls=e.relation==='attack-sequence'?'graph-edge-line attack-sequence':'graph-edge-line';
    const mx=(a.x+b.x)/2,my=(a.y+b.y)/2;
    return `<line class="${cls}" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" data-edge="${escapeHtml(e.id)}"></line><text class="graph-edge-label" x="${mx+6}" y="${my-5}">${escapeHtml(e.relation)}</text>`;
  }).join('');
  const nodeSvg=nodes.map(n=>{
    const p=attackGraphPositions[n.id];const [title,sub]=graphNodeDisplay(n);const c=attackNodeClass(n.type);
    return `<g class="attack-node ${c}" data-node="${escapeHtml(n.id)}" transform="translate(${p.x},${p.y})" onclick="selectAttackGraphNode('${encodeURIComponent(n.id)}')"><circle r="31"></circle><text text-anchor="middle" y="-2">${escapeHtml(title.slice(0,24))}</text><text class="node-sub" text-anchor="middle" y="16">${escapeHtml(sub.slice(0,34))}</text></g>`;
  }).join('');
  svg.innerHTML=`<defs><marker id="arrowhead" markerWidth="8" markerHeight="8" refX="7" refY="3.5" orient="auto"><polygon points="0 0, 8 3.5, 0 7" fill="#00C896"></polygon></marker></defs><g id="attackGraphLayer" transform="translate(${attackGraphTransform.x},${attackGraphTransform.y}) scale(${attackGraphTransform.k})">${edgeSvg}${nodeSvg}</g>`;
  const state=document.getElementById('attackGraphState');if(state){state.textContent=`${nodes.length} NODES`;state.className='badge good';}
  const m=document.getElementById('graphMetrics');if(m){m.innerHTML=`<div class="metric"><span>PATH</span><strong>${escapeHtml(attackGraphData.path.path_id)}</strong></div><div class="metric"><span>NODES</span><strong>${nodes.length}</strong></div><div class="metric"><span>EDGES</span><strong>${(attackGraphData.edges||[]).length}</strong></div><div class="metric"><span>RISK</span><strong>${Number(attackGraphData.path.score).toFixed(0)}/100</strong></div>`;}
  renderAttackTimeline();
  resetAttackGraphView();
  selectAttackGraphNode(encodeURIComponent('path:'+attackGraphData.path.path_id));
}
function renderAttackTimeline(){
  const box=document.getElementById('attackTimeline');if(!box||!attackGraphData)return;
  box.innerHTML=(attackGraphData.events||[]).map((e,i)=>`<div class="attack-step" onclick="selectAttackGraphNode('${encodeURIComponent('event:'+e.event_id)}')"><div class="attack-step-no">${i+1}</div><div><b>${escapeHtml(e.kind.replaceAll('_',' ').toUpperCase())}</b><small>${escapeHtml(e.created_at)}<br>${escapeHtml(String(e.normalized?.['source.ip']||'—'))} → ${escapeHtml(String(e.normalized?.['destination.ip']||'—'))} · ${escapeHtml(String(e.normalized?.['event.action']||e.label||'—'))}</small></div></div>`).join('') || '<div class="empty">No ordered events in this attack path.</div>';
}
function selectAttackGraphNode(encoded){
  if(!attackGraphData)return; const id=decodeURIComponent(encoded); const node=(attackGraphData.nodes||[]).find(n=>n.id===id);if(!node)return;
  document.querySelectorAll('#attackGraphSvg .attack-node').forEach(el=>el.classList.toggle('selected',el.dataset.node===id));
  const box=document.getElementById('graphSelectedNode');if(!box)return;
  const d=node.data||{};
  box.innerHTML=`<div class="selected-type">${escapeHtml(node.type)}</div><div class="selected-title">${escapeHtml(node.label)}</div><div class="selected-meta">${escapeHtml(Object.entries(d).filter(([k])=>!['raw_sha256'].includes(k)).map(([k,v])=>`${k}: ${typeof v==='object'?JSON.stringify(v):v}`).join(' · ')||'No additional metadata')}</div><pre class="selected-code">${escapeHtml(JSON.stringify(d,null,2))}</pre>`;
}
function fitAttackGraph(){
  attackGraphTransform={x:40,y:28,k:0.9}; const layer=document.getElementById('attackGraphLayer');if(layer)layer.setAttribute('transform',`translate(${attackGraphTransform.x},${attackGraphTransform.y}) scale(${attackGraphTransform.k})`);
}
function resetAttackGraphView(){fitAttackGraph();}
function zoomAttackGraph(factor,cx,cy){
  const next=Math.max(.45,Math.min(2.3,attackGraphTransform.k*factor));
  const ox=(cx-attackGraphTransform.x)/attackGraphTransform.k, oy=(cy-attackGraphTransform.y)/attackGraphTransform.k;
  attackGraphTransform.k=next; attackGraphTransform.x=cx-ox*next; attackGraphTransform.y=cy-oy*next;
  const layer=document.getElementById('attackGraphLayer');if(layer)layer.setAttribute('transform',`translate(${attackGraphTransform.x},${attackGraphTransform.y}) scale(${attackGraphTransform.k})`);
}
function bindAttackGraphInteractions(){
  const vp=document.getElementById('attackGraphViewport'); if(!vp||vp.dataset.bound)return; vp.dataset.bound='1';
  vp.addEventListener('wheel',e=>{e.preventDefault();const r=vp.getBoundingClientRect();zoomAttackGraph(e.deltaY<0?1.12:.89,e.clientX-r.left,e.clientY-r.top);},{passive:false});
  vp.addEventListener('pointerdown',e=>{if(e.target.closest('.attack-node'))return;attackGraphDrag={x:e.clientX,y:e.clientY,tx:attackGraphTransform.x,ty:attackGraphTransform.y};vp.classList.add('dragging');vp.setPointerCapture(e.pointerId);});
  vp.addEventListener('pointermove',e=>{if(!attackGraphDrag)return;attackGraphTransform.x=attackGraphDrag.tx+(e.clientX-attackGraphDrag.x);attackGraphTransform.y=attackGraphDrag.ty+(e.clientY-attackGraphDrag.y);const layer=document.getElementById('attackGraphLayer');if(layer)layer.setAttribute('transform',`translate(${attackGraphTransform.x},${attackGraphTransform.y}) scale(${attackGraphTransform.k})`);});
  const stop=()=>{attackGraphDrag=null;vp.classList.remove('dragging');}; vp.addEventListener('pointerup',stop); vp.addEventListener('pointercancel',stop);
}

document.addEventListener('DOMContentLoaded',()=>{bindAttackGraphInteractions();loadAttackPathCatalog();});
document.querySelectorAll('.nav').forEach(n=>n.addEventListener('click',()=>{if(n.dataset.page==='graph'){bindAttackGraphInteractions();loadAttackPathCatalog();}}));


// -------------------- v3.5 real-time reconstruction --------------------
let realtimeSource = null;
let realtimeLastSeq = 0;
let realtimeRefreshTimer = null;
async function loadRealtimeState(){
  try{ const s=await get('/realtime/state'); realtimeLastSeq=Number(s.sequence||0); const rate=document.getElementById('liveEventsRate'); if(rate)rate.textContent=s.events_last_60s; setLiveState(true); }catch{ setLiveState(false); }
}
function setLiveState(live){ const el=document.getElementById('liveAttackState'); if(!el)return; el.textContent=live?'● LIVE ATTACK FEED':'OFFLINE'; el.className='badge '+(live?'good':'bad'); }
function startRealtimeAttackFeed(){
  if(realtimeSource) realtimeSource.close();
  realtimeSource = new EventSource('/api/realtime/events?after='+encodeURIComponent(realtimeLastSeq)+'&timeout=60');
  realtimeSource.onopen=()=>setLiveState(true);
  realtimeSource.onerror=()=>{ setLiveState(false); if(realtimeSource){realtimeSource.close(); realtimeSource=null;} setTimeout(startRealtimeAttackFeed,2500); };
  realtimeSource.onmessage=(ev)=>handleRealtimeMessage(ev);
  realtimeSource.addEventListener('event.processed',handleRealtimeMessage);
  realtimeSource.addEventListener('event.ingested',handleRealtimeMessage);
}
function handleRealtimeMessage(ev){
  try{
    const d=JSON.parse(ev.data||'{}'); realtimeLastSeq=Number(d.seq||realtimeLastSeq); const rate=document.getElementById('liveEventsRate'); if(rate){ const cur=Number(rate.textContent)||0; rate.textContent=Math.max(cur,1); }
    // Keep the live graph aligned with the newest persisted attack path/incident.
    clearTimeout(realtimeRefreshTimer); realtimeRefreshTimer=setTimeout(()=>{ if(document.getElementById('graph')?.classList.contains('active-page')){ loadAttackPathCatalog(); } },350);
  }catch{}
}
setInterval(loadRealtimeState,15000);
document.querySelectorAll('.nav').forEach(n=>n.addEventListener('click',()=>{ if(n.dataset.page==='graph'){ loadRealtimeState(); startRealtimeAttackFeed(); }}));
document.addEventListener('DOMContentLoaded',()=>{ loadRealtimeState(); startRealtimeAttackFeed(); });

// -------------------- v3.6 response & containment simulation --------------------
async function loadResponseCenter(){
  try{
    const [recs,execs]=await Promise.all([get('/response/recommendations?limit=50'),get('/response/executions?limit=50')]);
    const box=document.getElementById('responseRecommendations');
    if(box) box.innerHTML=(recs.recommendations||[]).map(r=>{
      const status=r.status||'pending';
      const action=r.action_type||'—';
      const target=r.target||r.evidence?.target||'—';
      const decisionButtons=status==='pending'?`<button class="ghost" onclick="decideResponse('${encodeURIComponent(r.recommendation_id)}','approve')">APPROVE</button><button class="ghost" onclick="decideResponse('${encodeURIComponent(r.recommendation_id)}','reject')">REJECT</button>`:'';
      const execButton=status==='approved'?`<button class="primary" onclick="executeResponse('${encodeURIComponent(r.recommendation_id)}')">SIMULATE EXECUTION</button>`:'';
      return `<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(r.recommendation_id)}</div><div class="event-raw">${escapeHtml(action)} · ${escapeHtml(r.entity_type)}:${escapeHtml(r.entity_id)} · target ${escapeHtml(target)}</div></div><span class="badge ${status==='rejected'?'bad':status==='executed'?'good':status==='approved'?'good':'warn'}">${escapeHtml(status.toUpperCase())}</span></div><div class="event-raw">${escapeHtml(r.rationale||'')} · confidence ${(Number(r.confidence||0)*100).toFixed(1)}%</div><div class="button-row" style="margin-top:8px">${decisionButtons}${execButton}</div></div>`;
    }).join('')||'<div class="empty">No response recommendations yet.</div>';
    const ex=document.getElementById('responseExecutions');
    if(ex) ex.innerHTML=(execs.executions||[]).map(x=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(x.execution_id)}</div><div class="event-raw">${escapeHtml(x.action_type)} · ${escapeHtml(x.target||'—')} · ${escapeHtml(x.mode)}</div></div><span class="badge good">SIMULATED</span></div><div class="event-raw">${escapeHtml(x.result?.message||'No real control was invoked.')}</div></div>`).join('')||'<div class="empty">No simulated executions yet.</div>';
  }catch(e){ const box=document.getElementById('responseRecommendations'); if(box)box.innerHTML=`<div class="empty">${escapeHtml(e.message)}</div>`; }
}
async function generateResponseRecommendation(){
  const entity_type=document.getElementById('responseEntityType')?.value;
  const entity_id=document.getElementById('responseEntityId')?.value.trim();
  const analyst=document.getElementById('responseAnalyst')?.value.trim()||'SIH-Analyst';
  if(!entity_id)return;
  try{const r=await get('/response/recommend',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({entity_type,entity_id,analyst})});document.getElementById('responseResult').innerHTML=`<div class="result">${escapeHtml(JSON.stringify(r,null,2))}</div>`;await loadResponseCenter();}catch(e){document.getElementById('responseResult').innerHTML=`<div class="result">${escapeHtml(e.message)}</div>`;}
}
async function decideResponse(id,decision){
  const analyst=document.getElementById('responseAnalyst')?.value.trim()||'SIH-Analyst';
  try{await get('/response/recommendations/'+id+'/decision',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({analyst,decision,notes:'SIH analyst action'})});await loadResponseCenter();}catch(e){alert('Decision failed: '+e.message)}
}
async function executeResponse(id){
  const analyst=document.getElementById('responseAnalyst')?.value.trim()||'SIH-Analyst';
  try{await get('/response/recommendations/'+id+'/execute?analyst='+encodeURIComponent(analyst),{method:'POST'});await loadResponseCenter();}catch(e){alert('Execution blocked: '+e.message)}
}
document.querySelectorAll('.nav').forEach(n=>n.addEventListener('click',()=>{if(n.dataset.page==='response')loadResponseCenter();}));


// -------------------- v3.7 integrated security orchestration --------------------
let orchestratorSource = null;
let orchestratorLastSeq = 0;
function renderOrchestratorMetrics(s){
  const el=document.getElementById('orchestratorMetrics'); if(!el)return;
  el.innerHTML=[
    ['OPEN ALERTS',s.open_alerts||0],['OPEN INCIDENTS',s.open_incidents||0],['P1 QUEUE',s.p1_queue||0],['PENDING RESPONSES',s.pending_responses||0]
  ].map(x=>`<div class="metric"><span>${x[0]}</span><strong>${x[1]}</strong></div>`).join('');
}
async function loadOrchestratorState(){
  try{
    const s=await get('/security/flow'); renderOrchestratorMetrics(s);
    const live=document.getElementById('orchLive'); if(live) live.textContent=s.pending_responses?'APPROVAL QUEUE ACTIVE':'LOCAL CONTROL PLANE';
    const latest=document.getElementById('orchestratorLatest');
    if(latest) latest.innerHTML=s.latest_simulation?`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(s.latest_simulation.execution_id)}</div><div class="event-raw">${escapeHtml(s.latest_simulation.action_type)} · ${escapeHtml(s.latest_simulation.target||'—')}</div></div><span class="badge good">SIMULATED</span></div><small>${escapeHtml(s.latest_simulation.created_at||'')}</small></div>`:'<div class="empty">No simulated response execution yet.</div>';
  }catch(e){const el=document.getElementById('orchestratorLatest');if(el)el.innerHTML=`<div class="empty">${escapeHtml(e.message)}</div>`;}
}
async function runSecurityOrchestrator(){
  const analyst=document.getElementById('orchAnalyst')?.value.trim()||'SIH-Analyst';
  const detection_limit=Number(document.getElementById('orchDetectionLimit')?.value)||5000;
  const correlation_limit=Number(document.getElementById('orchCorrelationLimit')?.value)||10000;
  const attack_path_refresh=!!document.getElementById('orchAttackRefresh')?.checked;
  const auto_response=!!document.getElementById('orchAutoResponse')?.checked;
  try{
    const r=await get('/security/orchestrate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({analyst,detection_limit,correlation_limit,attack_path_refresh,auto_response})});
    const box=document.getElementById('orchestratorResult');
    if(box)box.innerHTML=`<div class="result"><b>${escapeHtml(r.orchestration_id)}</b> · ${Number(r.duration_ms).toFixed(1)}ms<br/>Alerts created: ${r.detection.fired} · Incidents created: ${r.correlation.created} · Response recommendations: ${r.response_recommendations.length}<br/>Queue depth: ${r.analyst_queue.depth} · P1: ${r.analyst_queue.p1}</div>`;
    loadOrchestratorState(); loadResponseCenter();
  }catch(e){const box=document.getElementById('orchestratorResult');if(box)box.innerHTML=`<div class="result">${escapeHtml(e.message)}</div>`;}
}
function handleOrchestratorRealtime(ev){
  try{
    const d=JSON.parse(ev.data||'{}'); orchestratorLastSeq=Math.max(orchestratorLastSeq,Number(d.seq||0));
    const feed=document.getElementById('orchestratorFeed');
    if(!feed)return;
    const row=document.createElement('div'); row.className='event'; row.innerHTML=`<div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(d.kind||'security.event')}</div><div class="event-raw">${escapeHtml(d.action_type||d.status||d.entity_type||'control-plane update')}</div></div><span class="badge good">LIVE</span></div><small>${escapeHtml(d.at||'')}</small>`;
    feed.prepend(row); while(feed.children.length>12)feed.removeChild(feed.lastChild);
  }catch{}
}
function startOrchestratorFeed(){
  if(orchestratorSource)orchestratorSource.close();
  orchestratorSource=new EventSource('/api/realtime/events?after='+encodeURIComponent(orchestratorLastSeq)+'&timeout=60');
  orchestratorSource.onopen=()=>{const x=document.getElementById('orchFeedState');if(x){x.textContent='LISTENING';x.className='badge good';}};
  orchestratorSource.onerror=()=>{const x=document.getElementById('orchFeedState');if(x){x.textContent='RECONNECTING';x.className='badge warn';} orchestratorSource?.close(); orchestratorSource=null; setTimeout(startOrchestratorFeed,2500);};
  orchestratorSource.onmessage=handleOrchestratorRealtime;
  orchestratorSource.addEventListener('security.orchestrated',handleOrchestratorRealtime);
  orchestratorSource.addEventListener('response.recommended',handleOrchestratorRealtime);
  orchestratorSource.addEventListener('response.simulated',handleOrchestratorRealtime);
}
setInterval(()=>{if(document.getElementById('orchestrator')?.classList.contains('active-page'))loadOrchestratorState();},10000);
document.querySelectorAll('.nav').forEach(n=>n.addEventListener('click',()=>{if(n.dataset.page==='orchestrator'){loadOrchestratorState();startOrchestratorFeed();}}));
document.addEventListener('DOMContentLoaded',()=>{loadOrchestratorState();startOrchestratorFeed();});

// -------------------- v3.8 system hardening --------------------
let hardToken = localStorage.getItem('ulpf_hardening_token') || '';
async function hardeningLogin(){
  const username=document.getElementById('hardUser')?.value.trim(); const password=document.getElementById('hardPass')?.value;
  try{const r=await get('/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password})}); hardToken=r.access_token; localStorage.setItem('ulpf_hardening_token',hardToken); document.getElementById('hardAuthResult').innerHTML='<div class="result">Authenticated as '+escapeHtml(r.role)+' · expires '+escapeHtml(r.expires_at)+'</div>'; await loadHardening();}catch(e){document.getElementById('hardAuthResult').innerHTML='<div class="result">'+escapeHtml(e.message)+'</div>';}
}
async function hardGet(path, opts={}){ opts.headers=Object.assign({},opts.headers||{}, hardToken?{'Authorization':'Bearer '+hardToken}:{}); return get(path,opts); }
async function loadHardening(){
  try{const h=await get('/health'); const r=await get('/ready'); const c=await get('/security/health/components');
    document.getElementById('hardeningMetrics').innerHTML=[['HEALTH',h.status],['READINESS',r.status],['AIR-GAPPED',h.checks?.air_gapped?.enabled?'TRUE':'FALSE'],['AUTH MODE',h.status==='healthy'?'READY':'DEGRADED']].map(x=>`<div class="metric"><span>${x[0]}</span><strong>${escapeHtml(x[1])}</strong></div>`).join('');
    document.getElementById('hardComponents').innerHTML=(c.components||[]).map(x=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(x.component)}</div><div class="event-raw">${escapeHtml(JSON.stringify(x.details||{}))}</div></div><span class="badge ${x.status==='healthy'?'good':'warn'}">${escapeHtml(x.status.toUpperCase())}</span></div></div>`).join('');
    if(hardToken) await loadAuditLog();
  }catch(e){document.getElementById('hardeningMetrics').innerHTML='<div class="result">'+escapeHtml(e.message)+'</div>';}
}
async function loadAuditLog(){
  try{const r=await hardGet('/security/audit?limit=40'); document.getElementById('hardAudit').innerHTML=(r.entries||[]).map(x=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(x.audit_id)}</div><div class="event-raw">${escapeHtml(x.created_at)} · ${escapeHtml(x.actor)} · ${escapeHtml(x.action)} · ${escapeHtml(x.resource)}</div></div><span class="badge good">${escapeHtml(x.role)}</span></div><div class="event-raw">request ${escapeHtml(x.request_id)} · hash ${escapeHtml(x.entry_hash.slice(0,20))}… · prev ${escapeHtml(x.prev_hash.slice(0,20))}…</div></div>`).join('')||'<div class="empty">No administrative audit entries yet.</div>';}catch(e){document.getElementById('hardAudit').innerHTML='<div class="empty">'+escapeHtml(e.message)+'</div>';}
}
async function verifyAuditChain(){
  try{const r=await hardGet('/security/audit/verify',{method:'POST'}); document.getElementById('hardAuthResult').innerHTML=`<div class="result"><b>${r.valid?'AUDIT CHAIN VALID':'AUDIT CHAIN FAILED'}</b><br/>Checked ${r.checked} entries · failures ${(r.failures||[]).length}</div>`; await loadAuditLog();}catch(e){document.getElementById('hardAuthResult').innerHTML='<div class="result">'+escapeHtml(e.message)+'</div>';}
}
document.querySelectorAll('.nav').forEach(n=>n.addEventListener('click',()=>{if(n.dataset.page==='hardening')loadHardening();}));


// -------------------- v3.9 air-gap operations --------------------
async function loadAirgap(){
  try{
    const s=await get('/airgap/status');
    document.getElementById('airgapMetrics').innerHTML=[['STATUS',s.status],['AIR-GAPPED',s.air_gapped?'TRUE':'FALSE'],['EXTERNAL AI',s.external_ai_required?'REQUIRED':'NOT REQUIRED'],['SIMULATION',s.simulation_only?'ONLY':'DISABLED']].map(x=>`<div class="metric"><span>${x[0]}</span><strong>${escapeHtml(String(x[1]))}</strong></div>`).join('');
    document.getElementById('airgapChecks').textContent=JSON.stringify(s.startup_checks,null,2);
    if(hardToken){const e=await hardGet('/airgap/environment');document.getElementById('airgapEnv').textContent=JSON.stringify(e,null,2);} 
  }catch(err){document.getElementById('airgapChecks').textContent=err.message;}
}
async function runAirgapSelfTest(){try{const r=await hardGet('/airgap/self-test',{method:'POST'});document.getElementById('airgapChecks').textContent=JSON.stringify(r,null,2);}catch(e){document.getElementById('airgapChecks').textContent=e.message;}}
async function exportAirgapConfig(){try{const r=await hardGet('/airgap/config/export');document.getElementById('airgapConfigResult').innerHTML=`<div class="result"><pre class="code-block">${escapeHtml(JSON.stringify(r,null,2))}</pre></div>`;}catch(e){document.getElementById('airgapConfigResult').innerHTML=`<div class="result">${escapeHtml(e.message)}</div>`;}}
async function importAirgapConfig(){try{const cfg=JSON.parse(document.getElementById('airgapImportJson').value||'{}');const r=await hardGet('/airgap/config/import',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({configuration:cfg})});document.getElementById('airgapConfigResult').innerHTML=`<div class="result">Imported ${r.keys.length} keys · restart required: ${r.requires_restart}</div>`;}catch(e){document.getElementById('airgapConfigResult').innerHTML=`<div class="result">${escapeHtml(e.message)}</div>`;}}
async function createAirgapBackup(){try{const r=await hardGet('/airgap/backup',{method:'POST'});document.getElementById('airgapBackupResult').innerHTML=`<div class="result"><b>BACKUP CREATED</b><br/>${escapeHtml(r.backup_path)}<br/>SHA-256: ${escapeHtml(r.sha256)}</div>`;}catch(e){document.getElementById('airgapBackupResult').innerHTML=`<div class="result">${escapeHtml(e.message)}</div>`;}}
document.querySelectorAll('.nav').forEach(n=>n.addEventListener('click',()=>{if(n.dataset.page==='airgap')loadAirgap();}));


// v4.0 Demo Command Center
async function loadDemoCenter(){
  try{
    const r=await get('/demo/command-center');
    const m=r.system_metrics||{};
    const latestSummary=r.latest_run?.summary||{};
    document.getElementById('demoMetrics').innerHTML=[
      ['Events',latestSummary.events_ingested??m.total_events??0],['Trusted',latestSummary.trusted_events??m.trusted_events??0],['Quarantine',m.quarantined_events??0],['Incident',latestSummary.incident_id?'1':'0'],['Attack Paths',latestSummary.attack_path_count??0],['Lossless',(Number(m.lossless_rate||0)*100).toFixed(0)+'%']
    ].map(([k,v])=>`<div class="metric"><div class="metric-label">${k}</div><div class="metric-value">${escapeHtml(String(v))}</div></div>`).join('');
    await loadDemoRuns();
    if(r.latest_run) renderDemoRun(r.latest_run);
  }catch(e){ document.getElementById('demoResult').textContent=e.message; }
}
async function runDemoScenario(){
  const scenario=document.getElementById('demoScenario').value;
  const analyst=document.getElementById('demoAnalyst').value.trim()||'SIH-Analyst';
  document.getElementById('demoRunStatus').textContent='RUNNING';
  document.getElementById('demoRunStatus').className='badge warn';
  document.getElementById('demoResult').textContent='Executing local scenario…';
  try{
    const r=await get('/demo/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scenario,analyst,reset_demo:true})});
    renderDemoRun({run_id:r.run_id,created_at:new Date().toISOString(),scenario:r.scenario,summary:r.summary,evidence:{steps:r.steps}});
    document.getElementById('demoRunStatus').textContent='COMPLETED';
    document.getElementById('demoRunStatus').className='badge good';
    await loadDemoCenter();
  }catch(e){
    document.getElementById('demoRunStatus').textContent='ERROR'; document.getElementById('demoRunStatus').className='badge warn'; document.getElementById('demoResult').textContent=e.message;
  }
}
function renderDemoRun(r){
  const summary=r.summary||{};
  document.getElementById('demoResult').textContent=JSON.stringify({run_id:r.run_id,scenario:r.scenario,summary},null,2);
  const steps=(r.evidence&&r.evidence.steps)||[];
  const labels={
    'ingest-1':'01 · INGEST UNKNOWN LOG','ingest-2':'02 · INGEST AUTH EVENT','ingest-3':'03 · INGEST PRIVILEGE EVENT','ingest-4':'04 · INGEST SENSITIVE ACCESS',
    'entity-rebuild':'05 · ENTITY INTELLIGENCE','attack-path-refresh':'06 · ATTACK-PATH RECONSTRUCTION','unknown-source-discovery':'07 · UNKNOWN-SOURCE DISCOVERY','ai-parser-candidate':'08 · AI PARSER CANDIDATE','sandbox-replay':'09 · SANDBOX REPLAY','security-orchestrator':'10 · DETECT → CORRELATE → RISK → RESPONSE'
  };
  document.getElementById('demoFlow').innerHTML=steps.length?steps.map((s,i)=>{const label=labels[s.step]||String(s.step||'STEP').replaceAll('-',' → ').toUpperCase(); const detail=s.event_id?`event ${s.event_id}`:(s.result?.parser_id?`parser ${s.result.parser_id}`:(s.result?.session_id?`session ${s.result.session_id}`:'')); return `<div class="timeline-item"><div class="timeline-dot">${i+1}</div><div><b>${escapeHtml(label)}</b><small><span class="badge good">${escapeHtml(s.status||'complete')}</span>${detail?` · ${escapeHtml(detail)}`:''}</small></div></div>`}).join(''):'<div class="empty">Run the scenario to populate the live flow.</div>';
}
async function loadDemoRuns(){
  const r=await get('/demo/runs?limit=10');
  document.getElementById('demoRuns').innerHTML=(r.runs||[]).map(x=>`<div class="event"><div class="event-row"><div class="event-main"><div class="event-id">${escapeHtml(x.run_id)}</div><div class="event-raw">${escapeHtml(x.scenario)} · ${escapeHtml(x.status)} · ${Number(x.duration_ms).toFixed(1)} ms</div></div><span class="badge good">DEMO</span></div><div class="event-raw">${escapeHtml(JSON.stringify(x.summary))}</div></div>`).join('')||'<div class="empty">No demo runs yet.</div>';
}
document.querySelectorAll('.nav').forEach(n=>n.addEventListener('click',()=>{if(n.dataset.page==='democc')loadDemoCenter();}));
