# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Control panel injection for dashboard monitoring pages.

Provides CSS, shared JS utilities, and per-page control button HTML
that gets injected before </body> at serve time.
"""

# ---------------------------------------------------------------------------
# Shared CSS for control elements
# ---------------------------------------------------------------------------

_CTRL_CSS = """<style>
.ctrl-bar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;padding:12px 16px;
background:linear-gradient(135deg,rgba(22,27,34,.95),rgba(13,17,23,.95));
border:1px solid var(--border);border-radius:10px;align-items:center}
.ctrl-btn{padding:7px 14px;border-radius:8px;border:1px solid var(--border);
background:rgba(22,27,34,.8);color:var(--text);font-size:.82rem;cursor:pointer;
transition:.2s;display:inline-flex;align-items:center;gap:6px;font-family:inherit}
.ctrl-btn:hover{border-color:var(--blue);background:rgba(88,166,255,.1)}
.ctrl-btn.go{border-color:var(--green);color:var(--green)}
.ctrl-btn.go:hover{background:rgba(63,185,80,.15)}
.ctrl-btn.danger{border-color:var(--red);color:var(--red)}
.ctrl-btn.danger:hover{background:rgba(248,81,73,.15)}
.ctrl-btn:disabled{opacity:.4;cursor:not-allowed}
.ctrl-select{padding:7px 10px;border-radius:8px;border:1px solid var(--border);
background:var(--card);color:var(--blue);font-size:.82rem;cursor:pointer;font-family:inherit}
.ctrl-toast{position:fixed;bottom:20px;right:20px;padding:12px 20px;border-radius:8px;
font-size:.85rem;z-index:9999;opacity:1;transition:opacity .3s}
.ctrl-toast.ok{background:rgba(63,185,80,.2);border:1px solid var(--green);color:var(--green)}
.ctrl-toast.err{background:rgba(248,81,73,.2);border:1px solid var(--red);color:var(--red)}
.ctrl-modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.6);display:flex;
align-items:center;justify-content:center;z-index:9998}
.ctrl-modal{background:var(--card);border:1px solid var(--border);border-radius:12px;
padding:24px;max-width:420px;width:90%}
.ctrl-modal h3{margin-bottom:12px;font-size:1rem}
.ctrl-modal input{width:100%;padding:8px 12px;border-radius:6px;
border:1px solid var(--border);background:var(--bg);color:var(--text);
font-size:.85rem;margin-top:8px;font-family:inherit}
.ctrl-modal .acts{display:flex;gap:8px;justify-content:flex-end;margin-top:16px}
.ctrl-lbl{color:var(--dim);font-size:.75rem;text-transform:uppercase;
letter-spacing:.5px;margin-right:4px}
</style>"""

# ---------------------------------------------------------------------------
# Shared JS utility functions
# ---------------------------------------------------------------------------

_CTRL_JS = """<script nonce="{{NONCE}}">
function ctrlPost(u,b){
  return fetch(u,{method:'POST',headers:{'Content-Type':'application/json','X-Requested-With':'XMLHttpRequest'},
    body:JSON.stringify(b||{})}).then(function(r){return r.json();});
}
function ctrlGo(btn,u,b){
  btn.disabled=true;
  ctrlPost(u,b).then(function(r){
    toast(r.ok?'ok':'err',r.message||'Done');
    btn.disabled=false;
    if(typeof load==='function')setTimeout(load,500);
  }).catch(function(e){toast('err',e.message);btn.disabled=false;});
}
function toast(cls,msg){
  var t=document.createElement('div');t.className='ctrl-toast '+cls;
  t.textContent=msg;document.body.appendChild(t);
  setTimeout(function(){t.style.opacity='0';
    setTimeout(function(){t.remove()},300)},3000);
}
function askOk(msg,fn){
  var bg=document.createElement('div');bg.className='ctrl-modal-bg';
  var box=document.createElement('div');box.className='ctrl-modal';
  var h=document.createElement('h3');h.textContent=msg;box.appendChild(h);
  var acts=document.createElement('div');acts.className='acts';
  var c=document.createElement('button');c.className='ctrl-btn';c.textContent='Cancel';
  c.onclick=function(){bg.remove()};
  var o=document.createElement('button');o.className='ctrl-btn danger';o.textContent='Confirm';
  o.onclick=function(){bg.remove();fn()};
  acts.appendChild(c);acts.appendChild(o);box.appendChild(acts);
  bg.appendChild(box);document.body.appendChild(bg);
  bg.onclick=function(e){if(e.target===bg)bg.remove()};
}
function askVal(title,ph,fn){
  var bg=document.createElement('div');bg.className='ctrl-modal-bg';
  var box=document.createElement('div');box.className='ctrl-modal';
  var h=document.createElement('h3');h.textContent=title;box.appendChild(h);
  var inp=document.createElement('input');inp.placeholder=ph;box.appendChild(inp);
  var acts=document.createElement('div');acts.className='acts';
  var c=document.createElement('button');c.className='ctrl-btn';c.textContent='Cancel';
  c.onclick=function(){bg.remove()};
  var o=document.createElement('button');o.className='ctrl-btn go';o.textContent='Go';
  o.onclick=function(){var v=inp.value;bg.remove();fn(v)};
  acts.appendChild(c);acts.appendChild(o);box.appendChild(acts);
  bg.appendChild(box);document.body.appendChild(bg);
  inp.addEventListener('keydown',function(e){if(e.key==='Enter')o.click()});
  setTimeout(function(){inp.focus()},100);
}
function _mvCtrl(){
  var n=document.querySelector('.nav');
  var c=document.getElementById('ctrlBar');
  if(n&&c){n.parentNode.insertBefore(c,n.nextSibling);c.style.display='';}
}
</script>"""

# ---------------------------------------------------------------------------
# Per-page control HTML
# ---------------------------------------------------------------------------

_CTRL_IDS = """\
<div id="ctrlBar" class="ctrl-bar" style="display:none">
<span class="ctrl-lbl">Controls:</span>
<button class="ctrl-btn go" id="cStart">&#9654; Start IDS</button>
<button class="ctrl-btn danger" id="cStop">&#9632; Stop IDS</button>
<button class="ctrl-btn" id="cClear">&#128465; Clear Alerts</button>
</div>
<script nonce="{{NONCE}}">
document.getElementById('cStart').onclick=function(){ctrlGo(this,'/api/control/ids/start')};
document.getElementById('cStop').onclick=function(){
  askOk('Stop IDS monitoring?',function(){
    ctrlPost('/api/control/ids/stop').then(function(r){
      toast(r.ok?'ok':'err',r.message);if(typeof load==='function')setTimeout(load,500);
    });
  });
};
document.getElementById('cClear').onclick=function(){
  askOk('Clear all IDS alerts?',function(){
    ctrlPost('/api/control/ids/clear').then(function(r){
      toast(r.ok?'ok':'err',r.message);if(typeof load==='function')setTimeout(load,500);
    });
  });
};
_mvCtrl();
</script>"""

_CTRL_IPS = """\
<div id="ctrlBar" class="ctrl-bar" style="display:none">
<span class="ctrl-lbl">Controls:</span>
<button class="ctrl-btn go" id="cStart">&#9654; Start IPS</button>
<button class="ctrl-btn danger" id="cStop">&#9632; Stop IPS</button>
<button class="ctrl-btn" id="cAutoOn">&#9889; Auto-Respond ON</button>
<button class="ctrl-btn" id="cAutoOff">&#128683; Auto-Respond OFF</button>
</div>
<script nonce="{{NONCE}}">
document.getElementById('cStart').onclick=function(){ctrlGo(this,'/api/control/ips/start')};
document.getElementById('cStop').onclick=function(){
  askOk('Stop IPS protection?',function(){
    ctrlPost('/api/control/ips/stop').then(function(r){
      toast(r.ok?'ok':'err',r.message);if(typeof load==='function')setTimeout(load,500);
    });
  });
};
document.getElementById('cAutoOn').onclick=function(){ctrlGo(this,'/api/control/ips/auto-respond',{enabled:true})};
document.getElementById('cAutoOff').onclick=function(){ctrlGo(this,'/api/control/ips/auto-respond',{enabled:false})};
_mvCtrl();
</script>"""

_CTRL_WIFI = """\
<div id="ctrlBar" class="ctrl-bar" style="display:none">
<span class="ctrl-lbl">Controls:</span>
<button class="ctrl-btn go" id="cScan">&#128225; Scan Networks</button>
</div>
<script nonce="{{NONCE}}">
document.getElementById('cScan').onclick=function(){ctrlGo(this,'/api/control/wifi/scan')};
_mvCtrl();
</script>"""

_CTRL_CLOAKING = """\
<div id="ctrlBar" class="ctrl-bar" style="display:none">
<span class="ctrl-lbl">Controls:</span>
<select class="ctrl-select" id="cMode">
<option value="">Set Mode...</option>
<option value="disabled">Disabled</option><option value="mask">Mask</option>
<option value="rotate">Rotate</option><option value="proxy">Proxy</option>
<option value="decoy">Decoy</option><option value="full">Full</option>
</select>
<button class="ctrl-btn go" id="cStart">&#9654; Start</button>
<button class="ctrl-btn danger" id="cStop">&#9632; Stop</button>
</div>
<script nonce="{{NONCE}}">
document.getElementById('cMode').onchange=function(){
  var v=this.value;if(!v)return;
  ctrlPost('/api/control/cloaking/mode',{mode:v}).then(function(r){
    toast(r.ok?'ok':'err',r.message);if(typeof load==='function')setTimeout(load,500);
  });this.selectedIndex=0;
};
document.getElementById('cStart').onclick=function(){ctrlGo(this,'/api/control/cloaking/start')};
document.getElementById('cStop').onclick=function(){
  askOk('Stop IP cloaking?',function(){
    ctrlPost('/api/control/cloaking/stop').then(function(r){
      toast(r.ok?'ok':'err',r.message);if(typeof load==='function')setTimeout(load,500);
    });
  });
};
_mvCtrl();
</script>"""

_CTRL_EXPLORER = """\
<div id="ctrlBar" class="ctrl-bar" style="display:none">
<span class="ctrl-lbl">Controls:</span>
<button class="ctrl-btn go" id="cDiscover">&#127760; Discover Subnet</button>
</div>
<script nonce="{{NONCE}}">
document.getElementById('cDiscover').onclick=function(){
  var btn=this;
  askVal('Discover Network','Subnet (e.g. 192.168.1.0/24)',function(v){
    if(v)ctrlGo(btn,'/api/control/explorer/discover',{subnet:v});
  });
};
_mvCtrl();
</script>"""

_CTRL_AUDITOR = """\
<div id="ctrlBar" class="ctrl-bar" style="display:none">
<span class="ctrl-lbl">Controls:</span>
<button class="ctrl-btn go" id="cAudit">&#128270; Run Audit</button>
</div>
<script nonce="{{NONCE}}">
document.getElementById('cAudit').onclick=function(){
  var btn=this;
  askVal('Run Security Audit','Target IPs (comma-separated)',function(v){
    if(v){
      var targets=v.split(',').map(function(s){return s.trim()});
      ctrlGo(btn,'/api/control/auditor/audit',{targets:targets});
    }
  });
};
_mvCtrl();
</script>"""

_CTRL_AI = """\
<div id="ctrlBar" class="ctrl-bar" style="display:none">
<span class="ctrl-lbl">&#9432; Info:</span>
<span style="color:var(--dim);font-size:.82rem">AI models activate on data input. Use IDS, Explorer, and Auditor to generate data for analysis.</span>
</div>
<script nonce="{{NONCE}}">_mvCtrl();</script>"""

# ---------------------------------------------------------------------------
# Page -> controls mapping
# ---------------------------------------------------------------------------

_PAGE_CONTROLS = {
    "/ids": _CTRL_IDS,
    "/ips": _CTRL_IPS,
    "/wifi": _CTRL_WIFI,
    "/cloaking": _CTRL_CLOAKING,
    "/explorer": _CTRL_EXPLORER,
    "/auditor": _CTRL_AUDITOR,
    "/ai": _CTRL_AI,
}


def inject_controls(html: str, path: str, nonce: str) -> str:
    """Inject control bar CSS, JS, and buttons into a page's HTML."""
    ctrl = _PAGE_CONTROLS.get(path)
    if not ctrl:
        return html
    inject = (
        _CTRL_CSS + "\n"
        + _CTRL_JS.replace("{{NONCE}}", nonce) + "\n"
        + ctrl.replace("{{NONCE}}", nonce)
    )
    return html.replace("</body>", inject + "\n</body>")
