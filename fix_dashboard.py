from pathlib import Path
import re

p = Path(r'c:\Users\CodyC\Network Guardian\Network-Guardian\network_guardian\interface\dashboard.py')
text = p.read_text(encoding='utf-8')
text = text.replace('_CONTENT_TEXT = "text/plain"\n\n\n#', '_CONTENT_TEXT = "text/plain"\n_CONTENT_JSON = "application/json"\n\n\n#', 1)
pattern = r'_TMPL_INDEX\s*=\s*.*?(?=\n\n_TMPL_IDS\s*=)'
replacement = '''_TMPL_INDEX = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PakShield | Mask | Network Guardian</title>
  <style nonce="{{NONCE}}">
    :root { --bg:#02131d; --bg2:#0a2234; --card:rgba(8,21,34,.95); --border:rgba(98,214,255,.2); --text:#dff7ff; --muted:#88a9c5; --cyan:#6fe8ff; --green:#63f8b0; --yellow:#ffd166; --orange:#ffb454; --red:#ff5d7a; --purple:#b38cff; }
    * { box-sizing:border-box; }
    body { margin:0; font-family:"Rajdhani","Segoe UI",sans-serif; background:radial-gradient(circle at 20% 20%,rgba(111,232,255,.08),transparent 25%),radial-gradient(circle at 80% 10%,rgba(82,157,255,.09),transparent 20%),linear-gradient(180deg,#020c15,#071c2a 50%,#030d18); color:var(--text); }
    a { color:inherit; text-decoration:none; }
    .wrap { max-width:1500px; margin:0 auto; padding:22px; }
    .topbar { display:flex; justify-content:space-between; align-items:center; padding:14px 18px; background:linear-gradient(135deg,rgba(9,22,36,.95),rgba(2,11,18,.98)); border:1px solid var(--border); box-shadow:0 0 24px rgba(111,232,255,.08); margin-bottom:18px; }
    .brand { display:flex; align-items:center; gap:12px; }
    .brand-mark { width:14px; height:14px; background:linear-gradient(135deg,var(--green),var(--cyan)); border-radius:50%; box-shadow:0 0 18px rgba(99,248,176,.7); }
    .brand h1 { margin:0; font-size:1.3rem; letter-spacing:3px; font-family:"Orbitron",sans-serif; color:var(--cyan); text-transform:uppercase; }
    .status { padding:5px 11px; border:1px solid rgba(99,248,176,.4); background:rgba(99,248,176,.08); color:var(--green); letter-spacing:1.5px; font-size:.7rem; text-transform:uppercase; }
    .nav { display:flex; flex-wrap:wrap; gap:10px; margin-bottom:20px; }
    .nav a { padding:8px 14px; border:1px solid var(--border); background:rgba(12,24,35,.8); color:var(--text); }
    .nav a.active { border-color:rgba(111,232,255,.75); color:var(--cyan); background:rgba(111,232,255,.08); }
    .kpis { display:grid; gap:16px; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); margin-bottom:18px; }
    .kpi { padding:18px 20px; border:1px solid var(--border); background:linear-gradient(135deg,rgba(8,23,34,.9),rgba(5,15,24,.96)); }
    .kpi .label { font-size:.7rem; color:var(--muted); text-transform:uppercase; letter-spacing:1.2px; }
    .kpi .value { font-size:2rem; font-weight:700; color:var(--cyan); margin-top:8px; }
    .kpi .delta { margin-top:6px; color:var(--green); font-size:.72rem; }
    .main { display:grid; grid-template-columns:1.6fr 1fr; gap:16px; }
    .card { background:linear-gradient(135deg,rgba(6,21,31,.97),rgba(3,13,20,.96)); border:1px solid var(--border); padding:18px; }
    .title { margin:0 0 14px; color:var(--cyan); font-size:.82rem; letter-spacing:2px; text-transform:uppercase; }
    .traffic { position:relative; height:250px; border:1px solid var(--border); background:linear-gradient(180deg,rgba(10,31,40,.7),rgba(5,15,24,.9)); overflow:hidden; }
    .traffic-grid { position:absolute; inset:0; background-image:linear-gradient(rgba(111,232,255,.06) 1px, transparent 1px), linear-gradient(90deg, rgba(111,232,255,.06) 1px, transparent 1px); background-size:24px 24px; }
    .heatmap { position:absolute; inset:18px; display:grid; grid-template-columns:repeat(12,1fr); grid-template-rows:repeat(7,1fr); gap:6px; }
    .cell { border-radius:3px; background: rgba(111,232,255,.08); border:1px solid rgba(111,232,255,.08); }
    .cell.level1 { background: rgba(99,248,176,.28); }
    .cell.level2 { background: rgba(111,232,255,.35); }
    .cell.level3 { background: rgba(255,209,102,.38); }
    .cell.level4 { background: rgba(255,93,122,.45); }
    .list { list-style:none; margin:0; padding:0; display:grid; gap:10px; }
    .list li { display:flex; justify-content:space-between; border-bottom:1px solid rgba(111,232,255,.14); padding-bottom:8px; }
    .badge { display:inline-block; padding:4px 8px; border-radius:999px; font-size:.68rem; }
    .badge.green { background:rgba(99,248,176,.16); color:var(--green); }
    .badge.orange { background:rgba(255,180,84,.15); color:var(--orange); }
    .badge.red { background:rgba(255,93,122,.14); color:var(--red); }
    .mini-bars { display:grid; grid-template-columns:repeat(12,minmax(0,1fr)); gap:8px; height:120px; align-items:end; margin-top:12px; }
    .mini-bars span { display:block; background:linear-gradient(180deg,var(--cyan),rgba(111,232,255,.2)); border:1px solid rgba(111,232,255,.15); }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div class="brand">
        <span class="brand-mark"></span>
        <h1>PakShield | Mask | Network Guardian</h1>
      </div>
      <div class="status">Observability Core Online</div>
    </div>
    <nav class="nav">
      <a class="active" href="/">Dashboard</a>
      <a href="/security">Threats</a>
      <a href="/ids">IDS</a>
      <a href="/ips">IPS</a>
      <a href="/explorer">Explorer</a>
      <a href="/reports">Reports</a>
      <a href="/incidents">Incidents</a>
    </nav>
    <section class="kpis">
      <div class="kpi"><div class="label">Network Traffic</div><div class="value">4.8M</div><div class="delta">+14.2% over previous window</div></div>
      <div class="kpi"><div class="label">Threats</div><div class="value">128</div><div class="delta">8 critical / 24 high</div></div>
      <div class="kpi"><div class="label">Mask Sessions</div><div class="value">74</div><div class="delta">12 active tunnels</div></div>
      <div class="kpi"><div class="label">PakShield Risk</div><div class="value">31</div><div class="delta">Steady, below alert threshold</div></div>
    </section>
    <div class="main">
      <div class="card">
        <h2 class="title">Network Heat Map</h2>
        <div class="traffic">
          <div class="traffic-grid"></div>
          <div class="heatmap">
            <div class="cell level1"></div><div class="cell level2"></div><div class="cell level1"></div><div class="cell level3"></div><div class="cell level2"></div><div class="cell level1"></div><div class="cell level2"></div><div class="cell level2"></div><div class="cell level1"></div><div class="cell level3"></div><div class="cell level2"></div><div class="cell level1"></div>
            <div class="cell level2"></div><div class="cell level3"></div><div class="cell level4"></div><div class="cell level2"></div><div class="cell level1"></div><div class="cell level1"></div><div class="cell level2"></div><div class="cell level3"></div><div class="cell level2"></div><div class="cell level1"></div><div class="cell level3"></div><div class="cell level1"></div>
            <div class="cell level1"></div><div class="cell level2"></div><div class="cell level2"></div><div class="cell level1"></div><div class="cell level3"></div><div class="cell level4"></div><div class="cell level4"></div><div class="cell level2"></div><div class="cell level1"></div><div class="cell level2"></div><div class="cell level1"></div><div class="cell level2"></div>
            <div class="cell level2"></div><div class="cell level1"></div><div class="cell level3"></div><div class="cell level2"></div><div class="cell level1"></div><div class="cell level2"></div><div class="cell level3"></div><div class="cell level4"></div><div class="cell level2"></div><div class="cell level1"></div><div class="cell level2"></div><div class="cell level1"></div>
            <div class="cell level1"></div><div class="cell level2"></div><div class="cell level2"></div><div class="cell level1"></div><div class="cell level1"></div><div class="cell level3"></div><div class="cell level2"></div><div class="cell level1"></div><div class="cell level2"></div><div class="cell level3"></div><div class="cell level1"></div><div class="cell level2"></div>
            <div class="cell level2"></div><div class="cell level3"></div><div class="cell level1"></div><div class="cell level2"></div><div class="cell level3"></div><div class="cell level4"></div><div class="cell level2"></div><div class="cell level1"></div><div class="cell level2"></div><div class="cell level1"></div><div class="cell level3"></div><div class="cell level2"></div>
            <div class="cell level1"></div><div class="cell level2"></div><div class="cell level1"></div><div class="cell level1"></div><div class="cell level2"></div><div class="cell level3"></div><div class="cell level1"></div><div class="cell level2"></div><div class="cell level2"></div><div class="cell level1"></div><div class="cell level1"></div><div class="cell level2"></div>
          </div>
        </div>
      </div>
      <div class="card">
        <h2 class="title">Live Telemetry</h2>
        <ul class="list">
          <li><span>PakShield scan path</span><span class="badge green">Healthy</span></li>
          <li><span>Mask egress tunnel</span><span class="badge orange">Elevated</span></li>
          <li><span>Threat feed ingest</span><span class="badge green">Stable</span></li>
          <li><span>Peer anomaly count</span><span class="badge red">12</span></li>
        </ul>
      </div>
    </div>
    <div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:16px; margin-top:16px;">
      <div class="card">
        <h2 class="title">Network Traffic</h2>
        <div class="mini-bars">
          <span style="height:40%"></span><span style="height:55%"></span><span style="height:62%"></span><span style="height:46%"></span><span style="height:74%"></span><span style="height:86%"></span><span style="height:68%"></span><span style="height:90%"></span><span style="height:77%"></span><span style="height:82%"></span><span style="height:73%"></span><span style="height:95%"></span>
        </div>
      </div>
      <div class="card">
        <h2 class="title">Threat Summary</h2>
        <ul class="list">
          <li><span>Credential abuse</span><span>21</span></li>
          <li><span>Reconnaissance</span><span>37</span></li>
          <li><span>Beaconing</span><span>18</span></li>
          <li><span>Port scanning</span><span>52</span></li>
        </ul>
      </div>
      <div class="card">
        <h2 class="title">Mask + PakShield</h2>
        <ul class="list">
          <li><span>Cross-app envelopes</span><span>893</span></li>
          <li><span>Correlated events</span><span>241</span></li>
          <li><span>Graph edges</span><span>1.4k</span></li>
          <li><span>Policy drift</span><span>06</span></li>
        </ul>
      </div>
    </div>
  </div>
</body>
</html>
"""

new_text, count = re.subn(pattern, replacement, text, count=1, flags=re.S)
if count != 1:
    raise RuntimeError(f'Failed to replace template; count={count}')
p.write_text(new_text, encoding='utf-8')
print('repaired dashboard template and JSON constant')
