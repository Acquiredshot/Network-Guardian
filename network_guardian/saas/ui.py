_APP_PAGE = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Guardian Cloud</title>
<style>
:root{
  --bg:#08111b;--bg2:#102538;--panel:rgba(9,20,32,.92);--line:rgba(124,189,255,.18);
  --text:#e6f2ff;--muted:#8ba7c2;--accent:#47c0ff;--accent2:#6af0c7;--warn:#ffb84d;--danger:#ff6b6b;
}
*{box-sizing:border-box}body{margin:0;font-family:Georgia, 'Avenir Next', serif;background:
radial-gradient(circle at top left, rgba(71,192,255,.12), transparent 35%),
radial-gradient(circle at top right, rgba(106,240,199,.08), transparent 30%),
linear-gradient(180deg, var(--bg), var(--bg2));color:var(--text)}
.wrap{max-width:1200px;margin:0 auto;padding:32px 20px 56px}
.hero{display:grid;grid-template-columns:1.2fr .8fr;gap:22px;align-items:start}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:22px;box-shadow:0 20px 60px rgba(0,0,0,.25)}
.kicker{letter-spacing:.18em;text-transform:uppercase;font-size:.73rem;color:var(--accent2);margin-bottom:12px}
h1{font-size:3rem;line-height:1.02;margin:0 0 14px}.lede{color:var(--muted);font-size:1.02rem;max-width:42rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-top:22px}
.stat{padding:16px;border:1px solid var(--line);border-radius:14px;background:rgba(255,255,255,.02)}
.stat b{display:block;font-size:1.5rem;margin-bottom:6px;color:var(--accent)}
.forms{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:26px}
input,select,button,textarea{width:100%;padding:12px 14px;border-radius:12px;border:1px solid var(--line);background:#0c1a29;color:var(--text);font:inherit}
button{background:linear-gradient(135deg, var(--accent), #2497d6);color:#04101a;font-weight:700;cursor:pointer}
button.secondary{background:transparent;color:var(--text)}button.warn{background:linear-gradient(135deg, var(--warn), #ff9452)}
.actions{display:flex;gap:10px;flex-wrap:wrap}.actions button{width:auto}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px;margin-top:26px}
.card{padding:18px;border:1px solid var(--line);border-radius:16px;background:rgba(255,255,255,.025)}
.card h3{margin:0 0 10px}.price{font-size:2rem;color:var(--accent2);margin:8px 0}.tag{display:inline-block;padding:4px 10px;border-radius:999px;background:rgba(71,192,255,.12);color:var(--accent);font-size:.78rem}
.section{margin-top:28px}.toolbar{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:12px}
.table{width:100%;border-collapse:collapse}.table th,.table td{padding:12px 10px;border-bottom:1px solid var(--line);text-align:left;font-size:.94rem}.table th{color:var(--muted);font-weight:600}
.hidden{display:none}.notice{margin-top:12px;color:var(--muted)}.error{color:var(--danger)}.success{color:var(--accent2)}
code{background:rgba(255,255,255,.05);padding:2px 6px;border-radius:6px}
@media (max-width:900px){.hero,.forms{grid-template-columns:1fr}h1{font-size:2.3rem}}
</style>
</head>
<body>
<div class="wrap">
  <section class="hero">
    <div class="panel">
      <div class="kicker">Hosted Control Plane</div>
      <h1>Network Guardian Cloud</h1>
      <p class="lede">Multi-tenant fleet security for probes, incidents, reports, and subscription-managed access. This hosted dashboard sits on top of the SaaS API and keeps each organization isolated.</p>
      <div class="grid">
        <div class="stat"><b id="stat-plan">Starter</b><span>Current plan</span></div>
        <div class="stat"><b id="stat-agents">0</b><span>Registered agents</span></div>
        <div class="stat"><b id="stat-reports">0</b><span>Reports received</span></div>
      </div>
      <div class="section">
        <div class="actions">
          <button id="refreshBtn" class="secondary">Refresh Data</button>
          <button id="createKeyBtn" class="secondary">Create Fleet API Key</button>
          <button id="portalBtn" class="secondary">Open Billing Portal</button>
        </div>
        <div id="apiKeyOut" class="notice"></div>
      </div>
    </div>
    <div class="panel">
      <div class="kicker">Access</div>
      <div class="forms">
        <form id="signupForm">
          <h3>Create Organization</h3>
          <input name="organization_name" placeholder="Organization name" required>
          <input name="organization_slug" placeholder="Slug" required>
          <input name="email" type="email" placeholder="Email" required>
          <input name="password" type="password" placeholder="Password" required>
          <button type="submit">Create account</button>
        </form>
        <form id="loginForm">
          <h3>Sign In</h3>
          <input name="organization_slug" placeholder="Organization slug" required>
          <input name="email" type="email" placeholder="Email" required>
          <input name="password" type="password" placeholder="Password" required>
          <button type="submit">Log in</button>
        </form>
      </div>
      <div id="authMsg" class="notice"></div>
    </div>
  </section>

  <section class="cards">
    <article class="card"><span class="tag">Starter</span><div class="price">$29</div><p>Core fleet ingestion, API keys, hosted dashboard.</p><button data-plan="starter" class="checkoutBtn">Choose Starter</button></article>
    <article class="card"><span class="tag">Growth</span><div class="price">$99</div><p>Expanded reporting, more agents, stronger operational visibility.</p><button data-plan="growth" class="checkoutBtn warn">Upgrade to Growth</button></article>
    <article class="card"><span class="tag">Enterprise</span><div class="price">$249</div><p>High-volume fleets, enterprise support, advanced control plane operations.</p><button data-plan="enterprise" class="checkoutBtn">Contact via Checkout</button></article>
  </section>

  <section id="workspace" class="section hidden">
    <div class="panel">
      <div class="toolbar"><h3>Tenant Workspace</h3><span id="orgBadge" class="tag">Not connected</span></div>
      <div id="workspaceMsg" class="notice"></div>
      <h4>Agents</h4>
      <table class="table"><thead><tr><th>ID</th><th>Name</th><th>Platform</th><th>Status</th></tr></thead><tbody id="agentsBody"><tr><td colspan="4">No agents yet</td></tr></tbody></table>
      <h4>Reports</h4>
      <table class="table"><thead><tr><th>ID</th><th>Agent</th><th>Received</th><th>Summary</th></tr></thead><tbody id="reportsBody"><tr><td colspan="4">No reports yet</td></tr></tbody></table>
    </div>
  </section>
</div>
<script>
const state={token:localStorage.getItem('ng_saas_token')||'',org:null};
function setMsg(id,text,klass='notice'){const el=document.getElementById(id);el.className=klass;el.textContent=text;}
function authHeaders(){return state.token?{'Authorization':'Bearer '+state.token}:{}};
async function api(path, opts={}){const headers=Object.assign({'Content-Type':'application/json'},authHeaders(),opts.headers||{});const res=await fetch(path,Object.assign({},opts,{headers}));const text=await res.text();let data={};try{data=JSON.parse(text);}catch{data={raw:text}}if(!res.ok){throw new Error(data.message||('HTTP '+res.status));}return data;}
function updateWorkspace(org, usage, agents=[], reports=[]){state.org=org;document.getElementById('workspace').classList.remove('hidden');document.getElementById('orgBadge').textContent=org.name+' · '+org.slug;document.getElementById('stat-plan').textContent=org.plan;document.getElementById('stat-agents').textContent=String(usage.agents||agents.length||0);document.getElementById('stat-reports').textContent=String(usage.reports||reports.length||0);document.getElementById('workspaceMsg').textContent='Status: '+org.status;document.getElementById('agentsBody').innerHTML=agents.length?agents.map(a=>'<tr><td><code>'+a.id+'</code></td><td>'+a.name+'</td><td>'+a.platform+'</td><td>'+a.status+'</td></tr>').join(''):'<tr><td colspan="4">No agents yet</td></tr>';document.getElementById('reportsBody').innerHTML=reports.length?reports.map(r=>'<tr><td><code>'+r.id+'</code></td><td>'+r.agent_id+'</td><td>'+r.created_at+'</td><td>'+JSON.stringify(r.report).slice(0,80)+'</td></tr>').join(''):'<tr><td colspan="4">No reports yet</td></tr>';}
async function refreshData(){if(!state.token)return;const org=await api('/api/v1/org');const agents=await api('/api/v1/fleet/agents');const reports=await api('/api/v1/fleet/reports');updateWorkspace(org.organization, org.usage||{}, agents.agents||[], reports.reports||[]);}
document.getElementById('signupForm').addEventListener('submit', async (e)=>{e.preventDefault();const fd=new FormData(e.target);try{const data=await api('/api/v1/auth/signup',{method:'POST',body:JSON.stringify(Object.fromEntries(fd.entries()))});state.token=data.token;localStorage.setItem('ng_saas_token',data.token);setMsg('authMsg','Organization created. Token stored in browser.','success');await refreshData();}catch(err){setMsg('authMsg',err.message,'error');}});
document.getElementById('loginForm').addEventListener('submit', async (e)=>{e.preventDefault();const fd=new FormData(e.target);try{const data=await api('/api/v1/auth/login',{method:'POST',body:JSON.stringify(Object.fromEntries(fd.entries()))});state.token=data.token;localStorage.setItem('ng_saas_token',data.token);setMsg('authMsg','Logged in.','success');await refreshData();}catch(err){setMsg('authMsg',err.message,'error');}});
document.getElementById('refreshBtn').addEventListener('click',()=>refreshData().catch(err=>setMsg('workspaceMsg',err.message,'error')));
document.getElementById('createKeyBtn').addEventListener('click',async ()=>{try{const data=await api('/api/v1/org/api-keys',{method:'POST',body:JSON.stringify({scope:'fleet:ingest'})});setMsg('apiKeyOut','API key: '+data.api_key,'success');await refreshData();}catch(err){setMsg('apiKeyOut',err.message,'error');}});
document.getElementById('portalBtn').addEventListener('click',async ()=>{try{const data=await api('/api/v1/billing/portal-session',{method:'POST',body:JSON.stringify({})});window.location.href=data.portal_url;}catch(err){setMsg('workspaceMsg',err.message,'error');}});
for(const btn of document.querySelectorAll('.checkoutBtn')){btn.addEventListener('click',async ()=>{if(!state.token){setMsg('authMsg','Log in before starting checkout.','error');return;}try{const data=await api('/api/v1/billing/checkout-session',{method:'POST',body:JSON.stringify({plan:btn.dataset.plan})});window.location.href=data.checkout_url;}catch(err){setMsg('workspaceMsg',err.message,'error');}})}
if(state.token){refreshData().catch(()=>{});}
</script>
</body>
</html>
'''


def get_saas_app_page() -> str:
    return _APP_PAGE
