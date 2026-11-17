from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

app = FastAPI(title="Enterprise IT Asset & Incident Portal")

# --- Modele danych ---
class AssetIn(BaseModel):
    hostname: str
    ip_address: str
    environment: str = "production"
    criticality: str = "high"

class AssetOut(AssetIn):
    id: int
    status: str = "online"

class IncidentIn(BaseModel):
    asset_id: int
    title: str
    severity: str = "high"
    assignee: str = "unassigned"

class IncidentOut(IncidentIn):
    id: int
    status: str = "open"
    created_at: str

class IncidentStatusPatch(BaseModel):
    status: str

class CommentIn(BaseModel):
    author: str
    content: str

class CommentOut(CommentIn):
    id: int
    incident_id: int
    created_at: str

# --- Stan początkowy w pamięci ---
assets_db: List[AssetOut] = [
    AssetOut(id=1, hostname="srv-prod-api-01", ip_address="10.20.1.15", environment="production", criticality="critical", status="online"),
    AssetOut(id=2, hostname="db-core-postgres", ip_address="10.20.2.40", environment="production", criticality="critical", status="online"),
    AssetOut(id=3, hostname="gw-edge-waf", ip_address="10.20.0.1", environment="dmz", criticality="high", status="degraded"),
]

incidents_db: List[IncidentOut] = [
    IncidentOut(id=1, asset_id=3, title="Anomalia ruchu TLS na porcie 443", severity="critical", assignee="M. Owsiejew", status="investigating", created_at="2026-11-17T10:15:00"),
    IncidentOut(id=2, asset_id=1, title="Wysokie zużycie pamięci kontenera worker", severity="medium", assignee="SOC Tier-1", status="open", created_at="2026-11-17T12:30:00"),
]

comments_db: List[CommentOut] = [
    CommentOut(id=1, incident_id=1, author="M. Owsiejew", content="Zebrano zrzut pakietów eBPF, trwa analiza sygnatur.", created_at="2026-11-17T10:22:00"),
]

# --- Frontend SPA ---
@app.get("/", response_class=HTMLResponse)
def dashboard():
    return """
    <!DOCTYPE html>
    <html lang="pl">
    <head>
      <meta charset="UTF-8" />
      <title>SecOps Asset & Incident Portal</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 24px; }
        .container { max-width: 1100px; margin: 0 auto; }
        header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 16px; margin-bottom: 24px; }
        h1 { margin: 0; font-size: 22px; color: #38bdf8; }
        .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 24px; }
        .card { background: #1e293b; padding: 16px; border-radius: 10px; border: 1px solid #334155; }
        .card h3 { margin: 0 0 8px 0; font-size: 13px; color: #94a3b8; text-transform: uppercase; }
        .card .num { font-size: 28px; font-weight: bold; color: #f8fafc; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        input, select, button { padding: 8px 12px; border-radius: 6px; border: 1px solid #334155; background: #0f172a; color: #f8fafc; margin: 4px 0; }
        button { background: #0284c7; border: none; cursor: pointer; font-weight: 600; }
        button:hover { background: #0369a1; }
        button.danger { background: #dc2626; }
        button.success { background: #16a34a; }
        table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #334155; }
        th { color: #94a3b8; }
        .badge { padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: bold; background: #334155; }
      </style>
    </head>
    <body>
      <div class="container">
        <header>
          <h1>SecOps Asset &amp; Incident Portal</h1>
          <span style="color:#94a3b8; font-size:13px;">Blackbox Target Environment v2.0</span>
        </header>

        <div class="stats">
          <div class="card"><h3>Monitorowane Zasoby</h3><div class="num" id="statAssets">0</div></div>
          <div class="card"><h3>Aktywne Incydenty</h3><div class="num" id="statIncidents">0</div></div>
          <div class="card"><h3>Wpisy Analityczne</h3><div class="num" id="statComments">0</div></div>
        </div>

        <div class="grid">
          <div class="card">
            <h2>1. Rejestr Zasobów IT (Assets)</h2>
            <form id="assetForm">
              <input type="text" id="hostname" placeholder="Hostname (np. srv-db-02)" required />
              <input type="text" id="ip_address" placeholder="IP (np. 10.20.5.12)" required />
              <select id="environment">
                <option value="production">production</option>
                <option value="staging">staging</option>
                <option value="dmz">dmz</option>
              </select>
              <select id="criticality">
                <option value="critical">critical</option>
                <option value="high">high</option>
                <option value="medium">medium</option>
              </select>
              <button type="submit" id="btnAddAsset">Dodaj zasób</button>
            </form>
            <table>
              <thead><tr><th>ID</th><th>Host</th><th>IP</th><th>Krytyczność</th><th>Akcja</th></tr></thead>
              <tbody id="assetsTable"></tbody>
            </table>
          </div>

          <div class="card">
            <h2>2. Zgłoszenia Incydentów (Incidents)</h2>
            <form id="incidentForm">
              <input type="number" id="asset_id" placeholder="Asset ID (np. 1)" value="1" required />
              <input type="text" id="inc_title" placeholder="Opis incydentu" required />
              <select id="severity">
                <option value="critical">critical</option>
                <option value="high">high</option>
                <option value="medium">medium</option>
              </select>
              <input type="text" id="assignee" placeholder="Analityk" value="M. Owsiejew" />
              <button type="submit" id="btnAddIncident">Zgłoś incydent</button>
            </form>
            <table>
              <thead><tr><th>ID</th><th>Asset</th><th>Tytuł</th><th>Status</th><th>Akcje</th></tr></thead>
              <tbody id="incidentsTable"></tbody>
            </table>
          </div>
        </div>

        <div class="card" style="margin-top:20px;">
          <h2>3. Dziennik Operacyjny Incydentu #1 (Comments)</h2>
          <form id="commentForm">
            <input type="text" id="author" placeholder="Autor" value="SOC Analyst" required />
            <input type="text" id="content" placeholder="Treść notatki analitycznej..." style="width:60%;" required />
            <button type="submit" id="btnAddComment">Dodaj wpis</button>
          </form>
          <ul id="commentsList"></ul>
        </div>
      </div>

      <script>
        async function refreshAll() {
          const [aRes, iRes, cRes] = await Promise.all([
            fetch('/api/assets'),
            fetch('/api/incidents'),
            fetch('/api/incidents/1/comments')
          ]);
          const assets = await aRes.json();
          const incidents = await iRes.json();
          const comments = await cRes.json();

          document.getElementById('statAssets').innerText = assets.length;
          document.getElementById('statIncidents').innerText = incidents.length;
          document.getElementById('statComments').innerText = comments.length;

          document.getElementById('assetsTable').innerHTML = assets.map(a =>
            `<tr><td>#${a.id}</td><td>${a.hostname}</td><td>${a.ip_address}</td><td><span class="badge">${a.criticality}</span></td>
             <td><button class="danger" onclick="deleteAsset(${a.id})">Usuń</button></td></tr>`
          ).join('');

          document.getElementById('incidentsTable').innerHTML = incidents.map(i =>
            `<tr><td>#${i.id}</td><td>Asset #${i.asset_id}</td><td>${i.title}</td><td><span class="badge">${i.status}</span></td>
             <td><button class="success" onclick="resolveIncident(${i.id})">Zamknij</button></td></tr>`
          ).join('');

          document.getElementById('commentsList').innerHTML = comments.map(c =>
            `<li><strong>${c.author}</strong> (${c.created_at}): ${c.content}</li>`
          ).join('');
        }

        document.getElementById('assetForm').onsubmit = async (e) => {
          e.preventDefault();
          await fetch('/api/assets', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
              hostname: document.getElementById('hostname').value,
              ip_address: document.getElementById('ip_address').value,
              environment: document.getElementById('environment').value,
              criticality: document.getElementById('criticality').value
            })
          });
          refreshAll();
        };

        document.getElementById('incidentForm').onsubmit = async (e) => {
          e.preventDefault();
          await fetch('/api/incidents', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
              asset_id: parseInt(document.getElementById('asset_id').value),
              title: document.getElementById('inc_title').value,
              severity: document.getElementById('severity').value,
              assignee: document.getElementById('assignee').value
            })
          });
          refreshAll();
        };

        document.getElementById('commentForm').onsubmit = async (e) => {
          e.preventDefault();
          await fetch('/api/incidents/1/comments', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
              author: document.getElementById('author').value,
              content: document.getElementById('content').value
            })
          });
          refreshAll();
        };

        async function resolveIncident(id) {
          await fetch(`/api/incidents/${id}/status`, {
            method: 'PATCH',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ status: 'resolved' })
          });
          refreshAll();
        }

        async function deleteAsset(id) {
          await fetch(`/api/assets/${id}`, { method: 'DELETE' });
          refreshAll();
        }

        refreshAll();
      </script>
    </body>
    </html>
    """

# --- Endpointy REST API (3 encje relacyjne) ---
@app.get("/api/assets", response_model=List[AssetOut])
def list_assets():
    return assets_db

@app.post("/api/assets", response_model=AssetOut, status_code=201)
def create_asset(asset: AssetIn):
    new_id = max([a.id for a in assets_db], default=0) + 1
    created = AssetOut(id=new_id, **asset.model_dump())
    assets_db.append(created)
    return created

@app.delete("/api/assets/{asset_id}")
def delete_asset(asset_id: int):
    global assets_db
    for a in assets_db:
        if a.id == asset_id:
            assets_db = [x for x in assets_db if x.id != asset_id]
            return {"deleted": True, "id": asset_id}
    raise HTTPException(status_code=404, detail="Asset not found")

@app.get("/api/incidents", response_model=List[IncidentOut])
def list_incidents(status: Optional[str] = None):
    if status:
        return [i for i in incidents_db if i.status == status]
    return incidents_db

@app.post("/api/incidents", response_model=IncidentOut, status_code=201)
def create_incident(inc: IncidentIn):
    if not any(a.id == inc.asset_id for a in assets_db):
        raise HTTPException(status_code=404, detail="Referenced asset not found")
    new_id = max([i.id for i in incidents_db], default=0) + 1
    created = IncidentOut(id=new_id, created_at=datetime.utcnow().isoformat(), **inc.model_dump())
    incidents_db.append(created)
    return created

@app.patch("/api/incidents/{incident_id}/status", response_model=IncidentOut)
def update_incident_status(incident_id: int, patch: IncidentStatusPatch):
    for i in incidents_db:
        if i.id == incident_id:
            i.status = patch.status
            return i
    raise HTTPException(status_code=404, detail="Incident not found")

@app.get("/api/incidents/{incident_id}/comments", response_model=List[CommentOut])
def list_comments(incident_id: int):
    return [c for c in comments_db if c.incident_id == incident_id]

@app.post("/api/incidents/{incident_id}/comments", response_model=CommentOut, status_code=201)
def add_comment(incident_id: int, comment: CommentIn):
    if not any(i.id == incident_id for i in incidents_db):
        raise HTTPException(status_code=404, detail="Incident not found")
    new_id = max([c.id for c in comments_db], default=0) + 1
    created = CommentOut(id=new_id, incident_id=incident_id, created_at=datetime.utcnow().isoformat(), **comment.model_dump())
    comments_db.append(created)
    return created
