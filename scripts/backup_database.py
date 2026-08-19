import hashlib, json, sqlite3
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]; source=ROOT/'database'/'inventory_audit.db'; folder=ROOT/'backups'; folder.mkdir(parents=True,exist_ok=True)
target=folder/f'inventory_audit_scheduled_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db'
src=sqlite3.connect(source); dst=sqlite3.connect(target)
try:src.backup(dst)
finally:dst.close(); src.close()
check=sqlite3.connect(target).execute('PRAGMA integrity_check').fetchone()[0]; raw=target.read_bytes(); result={'file':target.name,'created_at':datetime.now(timezone.utc).isoformat(),'size_bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'integrity_status':check}
(target.with_suffix('.json')).write_text(json.dumps(result,indent=2),encoding='utf-8'); print(json.dumps(result))

