import base64, csv, hashlib, hmac, io, json, mimetypes, os, re, secrets, shutil, smtplib, sqlite3, ssl, subprocess, sys, time
from email.message import EmailMessage
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from datetime import datetime, timedelta, timezone
from http import cookies
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from supabase_sync import reconcile as reconcile_supabase, start_worker as start_supabase_worker, status as supabase_sync_status, trigger as trigger_supabase_sync

ROOT=Path(__file__).resolve().parents[1]
CONFIG_PATH=ROOT/'config'/'app.json'
DEFAULT={"host":"127.0.0.1","port":8080,"database":"database/inventory_audit.db","session_hours":8,"smtp":{"enabled":False},"whatsapp":{"enabled":False},"ocr":{"enabled":False,"provider":"azure-document-intelligence"},"erp":{"enabled":False},"supabase":{"enabled":False,"project_id":"txfjxjaeurszfxyjiqjd","url":"https://txfjxjaeurszfxyjiqjd.supabase.co","mode":"secure-mirror","interval_seconds":30,"batch_size":100},"https":{"enabled":False},"security":{"max_login_attempts":5,"lockout_minutes":15}}
CONFIG=DEFAULT|((json.loads(CONFIG_PATH.read_text(encoding='utf-8-sig')) if CONFIG_PATH.exists() else {}))
DB=ROOT/CONFIG['database']; DB.parent.mkdir(parents=True,exist_ok=True)
SESSIONS={}
LOGIN_ATTEMPTS={}
ALLOWED_ROLES={'Admin','Auditor','Manager','Viewer'}

def supabase_status(check_remote=False):
    cfg=CONFIG.get('supabase',{}); key=(os.getenv('IAM_SUPABASE_SECRET_KEY') or os.getenv('IAM_SUPABASE_SERVICE_ROLE_KEY','')).strip()
    result={'enabled':bool(cfg.get('enabled')),'configured':bool(cfg.get('url') and key),'project_id':cfg.get('project_id'),'url':cfg.get('url'),'mode':cfg.get('mode','secure-mirror')}
    if check_remote and result['configured']:
        try:
            headers={'apikey':key}
            if not key.startswith('sb_secret_'): headers['Authorization']='Bearer '+key
            req=Request(cfg['url'].rstrip('/')+'/rest/v1/iam_roles?select=id&limit=1',headers=headers)
            with urlopen(req,timeout=10) as response: result.update({'connected':response.status==200,'http_status':response.status})
        except (HTTPError,URLError,TimeoutError) as e: result.update({'connected':False,'error':str(e)})
    else: result['connected']=False
    return result

def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; c.execute('PRAGMA foreign_keys=ON'); return c
def password(raw,salt=None):
    salt=salt or secrets.token_hex(16); digest=hashlib.pbkdf2_hmac('sha256',raw.encode(),salt.encode(),210000).hex(); return f'pbkdf2_sha256${salt}${digest}'
def verify(raw,stored):
    _,salt,digest=stored.split('$'); return hmac.compare_digest(password(raw,salt).split('$')[-1],digest)
def audit(c,uid,action,etype,eid=None,details='',ip=''):
    c.execute('INSERT INTO audit_trail(user_id,action,entity_type,entity_id,details,ip_address) VALUES(?,?,?,?,?,?)',(uid,action,etype,eid,details,ip))
def init_db():
    with db() as c:
        sql=(ROOT/'database'/'migrations'/'001_initial.sql').read_text(); c.executescript(sql)
        c.execute("INSERT OR IGNORE INTO schema_migrations(version) VALUES('001_initial')")
        migration2=(ROOT/'database'/'migrations'/'002_procurement_grn_inventory.sql')
        if migration2.exists() and not c.execute("SELECT 1 FROM schema_migrations WHERE version='002_procurement_grn_inventory'").fetchone():
            c.executescript(migration2.read_text())
            c.execute("INSERT INTO schema_migrations(version) VALUES('002_procurement_grn_inventory')")
        migration3=(ROOT/'database'/'migrations'/'003_industry_gap_analysis.sql')
        if migration3.exists() and not c.execute("SELECT 1 FROM schema_migrations WHERE version='003_industry_gap_analysis'").fetchone():
            c.executescript(migration3.read_text())
            c.execute("INSERT INTO schema_migrations(version) VALUES('003_industry_gap_analysis')")
        migration4=(ROOT/'database'/'migrations'/'004_vendor_master.sql')
        if migration4.exists() and not c.execute("SELECT 1 FROM schema_migrations WHERE version='004_vendor_master'").fetchone():
            c.executescript(migration4.read_text())
            c.execute("INSERT INTO schema_migrations(version) VALUES('004_vendor_master')")
        migration5=(ROOT/'database'/'migrations'/'005_phase2_controls.sql')
        if migration5.exists() and not c.execute("SELECT 1 FROM schema_migrations WHERE version='005_phase2_controls'").fetchone():
            c.executescript(migration5.read_text())
            c.execute("INSERT INTO schema_migrations(version) VALUES('005_phase2_controls')")
        migration6=(ROOT/'database'/'migrations'/'006_integrations_production.sql')
        if migration6.exists() and not c.execute("SELECT 1 FROM schema_migrations WHERE version='006_integrations_production'").fetchone():
            c.executescript(migration6.read_text())
            c.execute("INSERT INTO schema_migrations(version) VALUES('006_integrations_production')")
        migration7=(ROOT/'database'/'migrations'/'007_supabase_sync.sql')
        if migration7.exists() and not c.execute("SELECT 1 FROM schema_migrations WHERE version='007_supabase_sync'").fetchone():
            c.executescript(migration7.read_text())
            c.execute("INSERT INTO schema_migrations(version) VALUES('007_supabase_sync')")
        migration8=(ROOT/'database'/'migrations'/'008_supabase_storage_reconciliation.sql')
        if migration8.exists() and not c.execute("SELECT 1 FROM schema_migrations WHERE version='008_supabase_storage_reconciliation'").fetchone():
            c.executescript(migration8.read_text())
            c.execute("INSERT INTO schema_migrations(version) VALUES('008_supabase_storage_reconciliation')")
        profiles=[('MANUFACTURING','Manufacturing','Drawing, serial, heat and inspection controls'),('PHARMA','Pharmaceutical','Batch, COA, quarantine and shelf-life controls'),('FOOD','Food','Lot, temperature, shelf-life and food-safety controls'),('CONSTRUCTION','Construction','Project, BOQ, measurement and test-certificate controls'),('HOSPITAL','Hospital','Sterility, licence, expiry and cold-chain controls'),('RETAIL','Retail','SKU, barcode, pack conversion and damage controls')]
        for code,name,description in profiles: c.execute('INSERT OR IGNORE INTO industry_profiles(code,name,description) VALUES(?,?,?)',(code,name,description))
        base_rules=[('QTY_TOLERANCE','Quantity tolerance percentage','PO','2','High'),('PRICE_TOLERANCE','Unit-price tolerance percentage','PO','0','High'),('PO_REQUIRED','Purchase Order required','PO','true','Critical'),('NON_PO_APPROVAL','Approved request required','Non-PO','true','Critical'),('INVOICE_REQUIRED','Invoice required','Both','true','High'),('REJECTION_CHECK','Rejected material must raise audit observation','Both','0','High')]
        industry_rules={'MANUFACTURING':[('BATCH_REQUIRED','Batch or serial traceability required','Both','true','Medium')],'PHARMA':[('BATCH_REQUIRED','Batch number required','Both','true','High'),('EXPIRY_REQUIRED','Expiry date required','Both','true','High'),('MIN_SHELF_LIFE','Minimum remaining shelf life percentage','Both','75','High'),('COA_REQUIRED','Certificate of Analysis required','Both','true','Critical')],'FOOD':[('BATCH_REQUIRED','Lot number required','Both','true','High'),('EXPIRY_REQUIRED','Expiry date required','Both','true','High'),('MIN_SHELF_LIFE','Minimum remaining shelf life percentage','Both','60','High')],'CONSTRUCTION':[('BATCH_REQUIRED','Heat or lot number required','Both','true','Medium')],'HOSPITAL':[('BATCH_REQUIRED','Batch number required','Both','true','High'),('EXPIRY_REQUIRED','Expiry date required','Both','true','Critical')],'RETAIL':[('BATCH_REQUIRED','Barcode or batch reference required','Both','true','Low')]}
        for code,_,_ in profiles:
            pid=c.execute('SELECT id FROM industry_profiles WHERE code=?',(code,)).fetchone()[0]
            for rule in base_rules+industry_rules.get(code,[]): c.execute('INSERT OR IGNORE INTO compliance_rules(industry_profile_id,rule_code,rule_name,applies_to,parameter_value,severity) VALUES(?,?,?,?,?,?)',(pid,*rule))
        admin_id=c.execute("SELECT id FROM users WHERE username='admin'").fetchone()[0]
        c.execute("INSERT OR IGNORE INTO approval_workflows(workflow_code,name,entity_type,department,min_amount,active,created_by) VALUES('NONPO_STANDARD','Standard Non-PO Approval','Non-PO Receipt',NULL,0,1,?)",(admin_id,))
        workflow_id=c.execute("SELECT id FROM approval_workflows WHERE workflow_code='NONPO_STANDARD'").fetchone()[0]
        c.execute("INSERT OR IGNORE INTO approval_steps(workflow_id,step_order,step_name,approver_role,sla_hours) VALUES(?,1,'Department Manager','Manager',24)",(workflow_id,))
        c.execute("INSERT OR IGNORE INTO approval_steps(workflow_id,step_order,step_name,approver_role,sla_hours) VALUES(?,2,'Final Administration Review','Admin',24)",(workflow_id,))
        for role in ['Admin','Auditor','Manager','Viewer']: c.execute('INSERT OR IGNORE INTO roles(name) VALUES(?)',(role,))
        rid=c.execute("SELECT id FROM roles WHERE name='Admin'").fetchone()[0]
        if not c.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
            initial_password=os.getenv('IAM_INITIAL_ADMIN_PASSWORD') or (secrets.token_urlsafe(14)+'Aa1')
            c.execute('INSERT INTO users(username,full_name,email,password_hash,role_id,must_change_password) VALUES(?,?,?,?,?,1)',('admin','System Administrator','admin@local.test',password(initial_password),rid))
            print('Initial admin username: admin')
            print('Initial admin password: '+initial_password)
            print('Change this password immediately after signing in.')
        uid=c.execute("SELECT id FROM users WHERE username='admin'").fetchone()[0]
        for t,code,name in [('severity','LOW','Low'),('severity','MEDIUM','Medium'),('severity','HIGH','High'),('severity','CRITICAL','Critical'),('department','WAREHOUSE','Warehouse'),('department','QUALITY','Quality'),('category','INVENTORY','Inventory Control'),('category','COMPLIANCE','Compliance')]:
            c.execute('INSERT OR IGNORE INTO masters(master_type,code,name) VALUES(?,?,?)',(t,code,name))
        c.execute("INSERT OR IGNORE INTO observations(reference_no,title,description,site,department,category,severity,status,owner_id,due_date,created_by) VALUES('IAO-2026-0001','Cycle count variance','Physical stock differs from system quantity','Main Warehouse','Warehouse','Inventory Control','High','Open',?,date('now','+7 day'),?)",(uid,uid))
        oid=c.execute("SELECT id FROM observations WHERE reference_no='IAO-2026-0001'").fetchone()[0]
        c.execute("INSERT OR IGNORE INTO incidents(incident_no,observation_id,title,description,severity,status,owner_id,created_by) VALUES('INC-2026-0001',?,'Stock variance investigation','Investigate count and transaction history','High','Investigating',?,?)",(oid,uid,uid))
        c.execute("INSERT OR IGNORE INTO capas(capa_no,observation_id,action_type,action,owner_id,target_date,status,created_by) VALUES('CAPA-2026-0001',?,'Corrective','Reconcile stock and retrain counting team',?,date('now','+14 day'),'Open',?)",(oid,uid,uid))

class App(BaseHTTPRequestHandler):
    server_version='InventoryAudit/1.0'
    def log_message(self,fmt,*args): print('%s - %s'%(self.address_string(),fmt%args))
    def send_json(self,obj,status=200,headers=None):
        data=json.dumps(obj,default=str).encode(); self.send_response(status); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(data))); self.send_header('X-Content-Type-Options','nosniff'); self.send_header('X-Frame-Options','DENY'); self.send_header('Referrer-Policy','no-referrer'); self.send_header('Content-Security-Policy',"default-src 'self'; img-src 'self' blob: data:; style-src 'self'; script-src 'self' 'unsafe-inline'; connect-src 'self'"); self.send_header('Cache-Control','no-store');
        for k,v in (headers or {}).items(): self.send_header(k,v)
        self.end_headers(); self.wfile.write(data)
    def body(self):
        try: return json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))) or b'{}')
        except: return None
    def user(self):
        jar=cookies.SimpleCookie(self.headers.get('Cookie')); token=jar.get('session')
        if not token:return None
        token_hash=hashlib.sha256(token.value.encode()).hexdigest()
        with db() as c:
            row=c.execute('SELECT u.id,u.username,u.full_name,u.email,r.name role,s.csrf_token FROM persistent_sessions s JOIN users u ON u.id=s.user_id JOIN roles r ON r.id=u.role_id WHERE s.token_hash=? AND s.expires_at>CURRENT_TIMESTAMP AND u.active=1',(token_hash,)).fetchone()
            if row:c.execute('UPDATE persistent_sessions SET last_seen_at=CURRENT_TIMESTAMP WHERE token_hash=?',(token_hash,))
            return row
    def csrf_ok(self):
        u=self.user(); supplied=self.headers.get('X-CSRF-Token',''); return bool(u and supplied and hmac.compare_digest(supplied,u['csrf_token']))
    def require(self,roles=None):
        u=self.user()
        if not u: self.send_json({'error':'Authentication required'},401); return None
        if roles and u['role'] not in roles: self.send_json({'error':'Forbidden'},403); return None
        return u
    def do_POST(self):
        p=urlparse(self.path).path; data=self.body()
        if data is None: return self.send_json({'error':'Invalid JSON'},400)
        if p=='/api/login':
            key=(self.client_address[0],data.get('username','').lower()); attempts=[x for x in LOGIN_ATTEMPTS.get(key,[]) if time.time()-x<CONFIG.get('security',{}).get('lockout_minutes',15)*60]; LOGIN_ATTEMPTS[key]=attempts
            if len(attempts)>=CONFIG.get('security',{}).get('max_login_attempts',5):return self.send_json({'error':'Too many login attempts. Try again later.'},429)
            with db() as c:
                row=c.execute('SELECT u.*,r.name role FROM users u JOIN roles r ON r.id=u.role_id WHERE u.username=? AND u.active=1',(data.get('username',''),)).fetchone()
                if not row or not verify(data.get('password',''),row['password_hash']):
                    attempts.append(time.time()); LOGIN_ATTEMPTS[key]=attempts; c.execute('INSERT INTO security_events(event_type,username,ip_address,details) VALUES(?,?,?,?)',('LOGIN_FAILED',data.get('username'),self.client_address[0],f'Attempt {len(attempts)}')); return self.send_json({'error':'Invalid username or password'},401)
                LOGIN_ATTEMPTS.pop(key,None); token=secrets.token_urlsafe(32); csrf=secrets.token_urlsafe(24); token_hash=hashlib.sha256(token.encode()).hexdigest(); expires=(datetime.now(timezone.utc)+timedelta(hours=CONFIG['session_hours'])).strftime('%Y-%m-%d %H:%M:%S'); c.execute('INSERT INTO persistent_sessions(token_hash,user_id,csrf_token,expires_at,ip_address,user_agent) VALUES(?,?,?,?,?,?)',(token_hash,row['id'],csrf,expires,self.client_address[0],self.headers.get('User-Agent','')[:300])); audit(c,row['id'],'LOGIN','session',details='Successful login',ip=self.client_address[0])
            secure='; Secure' if CONFIG.get('https',{}).get('enabled') else ''; return self.send_json({'user':dict(id=row['id'],username=row['username'],full_name=row['full_name'],role=row['role'],must_change_password=bool(row['must_change_password'])),'csrf_token':csrf},headers={'Set-Cookie':f'session={token}; HttpOnly; SameSite=Strict; Path=/{secure}'})
        if not self.csrf_ok():return self.send_json({'error':'Invalid or missing CSRF token'},403)
        if p=='/api/change-password':
            u=self.require()
            if not u:return
            with db() as c:
                row=c.execute('SELECT password_hash FROM users WHERE id=?',(u['id'],)).fetchone()
                if not row or not verify(data.get('current_password',''),row['password_hash']):return self.send_json({'error':'Current password is incorrect'},400)
                new=data.get('new_password','')
                if len(new)<10 or not re.search(r'[A-Z]',new) or not re.search(r'[a-z]',new) or not re.search(r'\d',new):return self.send_json({'error':'Password must be 10+ characters with upper, lower and number'},400)
                c.execute('UPDATE users SET password_hash=?,must_change_password=0,updated_at=CURRENT_TIMESTAMP WHERE id=?',(password(new),u['id'])); audit(c,u['id'],'CHANGE_PASSWORD','User',u['id'],ip=self.client_address[0]); return self.send_json({'changed':True})
        u=self.require({'Admin','Auditor','Manager'}); 
        if not u:return
        if p=='/api/supabase-sync-now':
            if u['role']!='Admin':return self.send_json({'error':'Admin only'},403)
            trigger_supabase_sync()
            with db() as c: audit(c,u['id'],'TRIGGER_SYNC','Supabase Mirror',details='Manual synchronization requested',ip=self.client_address[0])
            return self.send_json({'queued':True,'sync':supabase_sync_status()},202)
        if p=='/api/supabase-reconcile':
            if u['role']!='Admin':return self.send_json({'error':'Admin only'},403)
            result=reconcile_supabase(DB,CONFIG)
            with db() as c:audit(c,u['id'],'RECONCILE','Supabase Mirror',details=json.dumps(result),ip=self.client_address[0])
            return self.send_json(result,200 if result.get('status')!='Failed' else 502)
        tables={'/api/observations':('observations','Inventory Audit Observation'),'/api/incidents':('incidents','Incident')}
        if p=='/api/observations': return self.create_observation(u,data)
        if p=='/api/incidents': return self.create_incident(u,data)
        if p=='/api/capas': return self.create_capa(u,data)
        if p=='/api/transfers': return self.create_transfer(u,data)
        if p=='/api/escalations': return self.create_escalation(u,data)
        if p=='/api/share': return self.share(u,data)
        if p=='/api/purchase-orders/import': return self.import_purchase_orders(u,data)
        if p=='/api/invoices': return self.upload_invoice(u,data)
        if p=='/api/non-po-requests': return self.create_non_po_request(u,data)
        if p=='/api/non-po-approve': return self.approve_non_po_request(u,data)
        if p=='/api/grns': return self.create_grn(u,data)
        if p=='/api/vendors': return self.create_vendor(u,data)
        if p=='/api/vendors/import': return self.import_vendors(u,data)
        if p=='/api/admin/users': return self.create_user(u,data)
        if p=='/api/admin/users/reset-password': return self.admin_reset_password(u,data)
        if p=='/api/approval-workflows': return self.create_approval_workflow(u,data)
        if p=='/api/approvals/start': return self.start_approval(u,data)
        if p=='/api/approvals/action': return self.approval_action(u,data)
        if p=='/api/transaction-control': return self.transaction_control(u,data)
        if p=='/api/notifications/send': return self.process_notification(u,data)
        if p=='/api/ocr/process': return self.process_image_ocr(u,data)
        if p=='/api/whatsapp/send': return self.send_whatsapp(u,data)
        if p=='/api/cost-centres': return self.create_cost_centre(u,data)
        if p=='/api/budgets': return self.create_budget(u,data)
        if p=='/api/budget/commit': return self.commit_budget(u,data)
        if p=='/api/erp/sync': return self.erp_sync(u,data)
        if p=='/api/admin/backup': return self.create_backup(u,data)
        if p=='/api/masters':
            if u['role']!='Admin': return self.send_json({'error':'Admin only'},403)
            with db() as c:
                cur=c.execute('INSERT INTO masters(master_type,code,name,active) VALUES(?,?,?,?)',(data['master_type'],data['code'],data['name'],int(data.get('active',1)))); audit(c,u['id'],'CREATE','Master',cur.lastrowid,json.dumps(data),self.client_address[0]); return self.send_json({'id':cur.lastrowid},201)
        self.send_json({'error':'Not found'},404)
    def create_user(self,u,d):
        if u['role']!='Admin':return self.send_json({'error':'Admin only'},403)
        role=d.get('role','Viewer')
        if role not in ALLOWED_ROLES:return self.send_json({'error':'Invalid role'},400)
        raw=d.get('password') or ('Tmp@'+secrets.token_urlsafe(8))
        if len(raw)<10:return self.send_json({'error':'Password must be at least 10 characters'},400)
        try:
            with db() as c:
                rid=c.execute('SELECT id FROM roles WHERE name=?',(role,)).fetchone()['id']; cur=c.execute('INSERT INTO users(username,full_name,email,password_hash,role_id,active,must_change_password) VALUES(?,?,?,?,?,?,1)',(d['username'],d['full_name'],d.get('email'),password(raw),rid,int(d.get('active',1)))); audit(c,u['id'],'CREATE','User',cur.lastrowid,d['username'],self.client_address[0]); return self.send_json({'id':cur.lastrowid,'temporary_password':raw,'must_change_password':True},201)
        except (KeyError,sqlite3.IntegrityError):return self.send_json({'error':'Username already exists or required data is missing'},409)
    def admin_reset_password(self,u,d):
        if u['role']!='Admin':return self.send_json({'error':'Admin only'},403)
        raw='Tmp@'+secrets.token_urlsafe(9)
        with db() as c:
            cur=c.execute('UPDATE users SET password_hash=?,must_change_password=1,updated_at=CURRENT_TIMESTAMP WHERE id=?',(password(raw),d['id']))
            if not cur.rowcount:return self.send_json({'error':'User not found'},404)
            audit(c,u['id'],'RESET_PASSWORD','User',d['id'],'Temporary password issued',self.client_address[0]); return self.send_json({'id':d['id'],'temporary_password':raw,'must_change_password':True})
    def create_approval_workflow(self,u,d):
        if u['role']!='Admin':return self.send_json({'error':'Admin only'},403)
        steps=d.get('steps') or []
        if not d.get('workflow_code') or not d.get('name') or not d.get('entity_type') or not steps:return self.send_json({'error':'Workflow code, name, entity type and steps are required'},400)
        try:
            with db() as c:
                cur=c.execute('INSERT INTO approval_workflows(workflow_code,name,entity_type,department,min_amount,max_amount,active,created_by) VALUES(?,?,?,?,?,?,?,?)',(d['workflow_code'],d['name'],d['entity_type'],d.get('department'),d.get('min_amount'),d.get('max_amount'),int(d.get('active',1)),u['id'])); wid=cur.lastrowid
                for i,s in enumerate(steps,1):c.execute('INSERT INTO approval_steps(workflow_id,step_order,step_name,approver_role,approver_user_id,sla_hours) VALUES(?,?,?,?,?,?)',(wid,i,s['step_name'],s['approver_role'],s.get('approver_user_id'),int(s.get('sla_hours',24))))
                audit(c,u['id'],'CREATE','Approval Workflow',wid,d['workflow_code'],self.client_address[0]); return self.send_json({'id':wid,'steps':len(steps)},201)
        except sqlite3.IntegrityError:return self.send_json({'error':'Workflow code already exists or step is invalid'},409)
    def queue_email(self,c,u,recipient,subject,body,related_type,related_id):
        cur=c.execute('INSERT INTO notification_outbox(recipient,subject,body,related_type,related_id,status,created_by) VALUES(?,?,?,?,?,?,?)',(recipient,subject,body,related_type,related_id,'Pending',u['id'])); return cur.lastrowid
    def start_approval(self,u,d):
        with db() as c:
            wf=c.execute('SELECT * FROM approval_workflows WHERE workflow_code=? AND active=1',(d.get('workflow_code','NONPO_STANDARD'),)).fetchone()
            if not wf:return self.send_json({'error':'Active workflow not found'},404)
            try:cur=c.execute('INSERT INTO approval_instances(workflow_id,entity_type,entity_id,requested_by) VALUES(?,?,?,?)',(wf['id'],d['entity_type'],d['entity_id'],u['id']))
            except sqlite3.IntegrityError:return self.send_json({'error':'Approval already exists for this record'},409)
            iid=cur.lastrowid; token=secrets.token_urlsafe(32); token_hash=hashlib.sha256(token.encode()).hexdigest(); c.execute("INSERT INTO approval_link_tokens(instance_id,token_hash,expires_at) VALUES(?,?,datetime('now','+48 hours'))",(iid,token_hash)); step=c.execute('SELECT * FROM approval_steps WHERE workflow_id=? AND step_order=1',(wf['id'],)).fetchone(); recipient=d.get('recipient') or 'approval@local.test'; link=f"http://{CONFIG['host']}:{CONFIG['port']}/?approval_token={token}"; outbox=self.queue_email(c,u,recipient,f"Approval required: {d['entity_type']} #{d['entity_id']}",f"Review and approve: {link}\nStep: {step['step_name'] if step else 'Approval'}",d['entity_type'],d['entity_id']); audit(c,u['id'],'START_APPROVAL',d['entity_type'],d['entity_id'],wf['workflow_code'],self.client_address[0]); return self.send_json({'instance_id':iid,'status':'Pending','approval_link':link,'expires_hours':48,'outbox_id':outbox},201)
    def approval_action(self,u,d):
        with db() as c:
            inst=c.execute('SELECT i.*,w.name workflow_name FROM approval_instances i JOIN approval_workflows w ON w.id=i.workflow_id WHERE i.id=? AND i.status="Pending"',(d['instance_id'],)).fetchone()
            if not inst:return self.send_json({'error':'Pending approval not found'},404)
            step=c.execute('SELECT * FROM approval_steps WHERE workflow_id=? AND step_order=?',(inst['workflow_id'],inst['current_step'])).fetchone()
            if not step or (u['role']!=step['approver_role'] and u['role']!='Admin' and step['approver_user_id']!=u['id']):return self.send_json({'error':'Not authorized for the current approval step'},403)
            action=d.get('action')
            if action not in {'Approved','Rejected','Returned'}:return self.send_json({'error':'Invalid approval action'},400)
            c.execute('INSERT INTO approval_actions(instance_id,step_order,action,note,acted_by) VALUES(?,?,?,?,?)',(inst['id'],inst['current_step'],action,d.get('note'),u['id']))
            if action=='Approved':
                nxt=c.execute('SELECT 1 FROM approval_steps WHERE workflow_id=? AND step_order=?',(inst['workflow_id'],inst['current_step']+1)).fetchone()
                if nxt:c.execute('UPDATE approval_instances SET current_step=current_step+1 WHERE id=?',(inst['id'],)); status='Pending'
                else:c.execute("UPDATE approval_instances SET status='Approved',completed_at=CURRENT_TIMESTAMP WHERE id=?",(inst['id'],)); status='Approved'
            else:c.execute('UPDATE approval_instances SET status=?,completed_at=CURRENT_TIMESTAMP WHERE id=?',(action,inst['id'])); status=action
            if status!='Pending':c.execute('UPDATE approval_link_tokens SET used_at=CURRENT_TIMESTAMP WHERE instance_id=? AND used_at IS NULL',(inst['id'],))
            if status in {'Approved','Rejected'} and inst['entity_type']=='Non-PO Receipt':c.execute('UPDATE non_po_requests SET status=?,approver_id=?,approval_note=?,approved_at=CURRENT_TIMESTAMP WHERE id=?',(status,u['id'],d.get('note'),inst['entity_id']))
            audit(c,u['id'],action.upper(),'Approval',inst['id'],d.get('note',''),self.client_address[0]); return self.send_json({'instance_id':inst['id'],'status':status})
    def transaction_control(self,u,d):
        allowed={'Draft':['Submitted'],'Submitted':['Under Review','Returned'],'Under Review':['Approved','Returned'],'Returned':['Submitted'],'Approved':['Closed']}; target=d.get('status')
        with db() as c:
            row=c.execute('SELECT * FROM transaction_controls WHERE entity_type=? AND entity_id=?',(d['entity_type'],d['entity_id'])).fetchone(); current=row['control_status'] if row else 'Draft'
            if target not in allowed.get(current,[]):return self.send_json({'error':f'Invalid transition: {current} to {target}'},400)
            if target in {'Under Review','Approved','Closed'} and u['role'] not in {'Admin','Manager'}:return self.send_json({'error':'Manager or Admin required'},403)
            c.execute('INSERT INTO transaction_controls(entity_type,entity_id,control_status,review_note,reviewed_by,approved_by,closed_by) VALUES(?,?,?,?,?,?,?) ON CONFLICT(entity_type,entity_id) DO UPDATE SET control_status=excluded.control_status,review_note=excluded.review_note,reviewed_by=COALESCE(excluded.reviewed_by,transaction_controls.reviewed_by),approved_by=COALESCE(excluded.approved_by,transaction_controls.approved_by),closed_by=COALESCE(excluded.closed_by,transaction_controls.closed_by),updated_at=CURRENT_TIMESTAMP',(d['entity_type'],d['entity_id'],target,d.get('note'),u['id'] if target=='Under Review' else None,u['id'] if target=='Approved' else None,u['id'] if target=='Closed' else None)); audit(c,u['id'],target.upper().replace(' ','_'),d['entity_type'],d['entity_id'],d.get('note',''),self.client_address[0]); return self.send_json({'entity_type':d['entity_type'],'entity_id':d['entity_id'],'previous':current,'status':target})
    def process_notification(self,u,d):
        with db() as c:
            row=c.execute('SELECT * FROM notification_outbox WHERE id=?',(d['id'],)).fetchone()
            if not row:return self.send_json({'error':'Notification not found'},404)
            smtp=CONFIG.get('smtp',{}); status='Placeholder'; message='SMTP not configured; retained in auditable outbox.'
            if smtp.get('enabled'):
                try:
                    msg=EmailMessage(); msg['From']=smtp['from']; msg['To']=row['recipient']; msg['Subject']=row['subject']; msg.set_content(row['body'])
                    with smtplib.SMTP(smtp['host'],int(smtp.get('port',587)),timeout=15) as server:
                        if smtp.get('starttls',True):server.starttls()
                        if smtp.get('username'):server.login(smtp['username'],smtp.get('password',''))
                        server.send_message(msg)
                    status='Sent'; message='Delivered by configured SMTP provider.'
                except Exception as e:status='Failed'; message=str(e)[:300]
            c.execute('UPDATE notification_outbox SET status=?,provider_message=?,attempts=attempts+1,sent_at=CASE WHEN ?="Sent" THEN CURRENT_TIMESTAMP ELSE sent_at END WHERE id=?',(status,message,status,row['id'])); audit(c,u['id'],'SEND_NOTIFICATION','Notification',row['id'],status,self.client_address[0]); return self.send_json({'id':row['id'],'status':status,'message':message})
    def process_image_ocr(self,u,d):
        cfg=CONFIG.get('ocr',{}); provider=cfg.get('provider','azure-document-intelligence')
        with db() as c:
            inv=c.execute('SELECT * FROM invoices WHERE id=?',(d['invoice_id'],)).fetchone()
            if not inv:return self.send_json({'error':'Invoice not found'},404)
            path=(ROOT/inv['stored_path']).resolve(); uploads=(ROOT/'uploads').resolve()
            if uploads not in path.parents or not path.is_file():return self.send_json({'error':'Invoice document unavailable'},404)
            cur=c.execute('INSERT INTO ocr_jobs(invoice_id,provider,status,requested_by) VALUES(?,?,?,?)',(inv['id'],provider,'Processing',u['id'])); job_id=cur.lastrowid
        if not cfg.get('enabled'):
            with db() as c:c.execute('UPDATE ocr_jobs SET status="Configuration Required",error_message=?,completed_at=CURRENT_TIMESTAMP WHERE id=?',(f'Configure {provider} endpoint and key',job_id))
            return self.send_json({'id':job_id,'status':'Configuration Required','provider':provider,'message':'Real OCR adapter is installed; configure provider credentials to process images.'},409)
        try:
            raw=path.read_bytes(); mime=inv['mime_type'] or 'application/octet-stream'; text=''; confidence=None; extracted={}
            if provider=='azure-document-intelligence':
                endpoint=cfg['endpoint'].rstrip('/'); model=cfg.get('model','prebuilt-invoice'); api_version=cfg.get('api_version','2024-11-30'); url=f'{endpoint}/documentintelligence/documentModels/{model}:analyze?api-version={api_version}'; req=Request(url,data=raw,method='POST',headers={'Ocp-Apim-Subscription-Key':cfg['key'],'Content-Type':mime}); resp=urlopen(req,timeout=30); operation=resp.headers.get('Operation-Location')
                if not operation:raise RuntimeError('OCR provider did not return an operation URL')
                result=None
                for _ in range(20):
                    time.sleep(1); poll=urlopen(Request(operation,headers={'Ocp-Apim-Subscription-Key':cfg['key']}),timeout=30); result=json.loads(poll.read())
                    if result.get('status') in {'succeeded','failed'}:break
                if not result or result.get('status')!='succeeded':raise RuntimeError((result or {}).get('error',{}).get('message','OCR timed out'))
                ar=result.get('analyzeResult',{}); text=ar.get('content',''); docs=ar.get('documents') or []; fields=(docs[0].get('fields',{}) if docs else {}); extracted={k:(v.get('content') or v.get('valueString') or v.get('valueNumber') or v.get('valueDate')) for k,v in fields.items()}; confs=[v.get('confidence') for v in fields.values() if v.get('confidence') is not None]; confidence=sum(confs)/len(confs) if confs else None
            elif provider=='generic-webhook':
                payload=json.dumps({'file_name':inv['file_name'],'mime_type':mime,'content_base64':base64.b64encode(raw).decode()}).encode(); headers={'Content-Type':'application/json'}
                if cfg.get('key'):headers['Authorization']='Bearer '+cfg['key']
                result=json.loads(urlopen(Request(cfg['endpoint'],data=payload,method='POST',headers=headers),timeout=60).read()); text=result.get('text',''); confidence=result.get('confidence'); extracted=result.get('fields') or {}
            else:raise RuntimeError('Unsupported OCR provider')
            if not text and not extracted:raise RuntimeError('OCR returned no extractable content')
            with db() as c:
                c.execute('UPDATE invoices SET ocr_status="Extracted",ocr_text=?,extracted_json=?,ocr_provider=?,ocr_confidence=? WHERE id=?',(text,json.dumps(extracted),provider,confidence,inv['id'])); c.execute('UPDATE ocr_jobs SET status="Completed",confidence=?,completed_at=CURRENT_TIMESTAMP WHERE id=?',(confidence,job_id)); audit(c,u['id'],'OCR','Invoice',inv['id'],provider,self.client_address[0])
            return self.send_json({'id':job_id,'invoice_id':inv['id'],'status':'Completed','provider':provider,'confidence':confidence,'fields':extracted})
        except Exception as e:
            with db() as c:c.execute('UPDATE ocr_jobs SET status="Failed",error_message=?,completed_at=CURRENT_TIMESTAMP WHERE id=?',(str(e)[:500],job_id))
            return self.send_json({'id':job_id,'status':'Failed','error':str(e)},502)
    def send_whatsapp(self,u,d):
        cfg=CONFIG.get('whatsapp',{}); recipient=re.sub(r'\D','',d.get('recipient','')); message=d.get('message_text','')
        if not recipient or not message:return self.send_json({'error':'Recipient and message are required'},400)
        with db() as c:
            cur=c.execute('INSERT INTO whatsapp_messages(recipient,template_name,message_text,related_type,related_id,status,created_by) VALUES(?,?,?,?,?,?,?)',(recipient,d.get('template_name'),message,d.get('related_type'),d.get('related_id'),'Processing',u['id'])); mid=cur.lastrowid
        if not cfg.get('enabled'):
            with db() as c:c.execute('UPDATE whatsapp_messages SET status="Configuration Required",provider_response=? WHERE id=?',('Configure Meta Cloud API token and phone_number_id',mid))
            return self.send_json({'id':mid,'status':'Configuration Required','message':'WhatsApp adapter is installed; configure Meta Cloud API credentials.'},409)
        try:
            api_version=cfg.get('api_version','v20.0'); url=f"https://graph.facebook.com/{api_version}/{cfg['phone_number_id']}/messages"; payload={'messaging_product':'whatsapp','to':recipient,'type':'text','text':{'preview_url':False,'body':message}}; req=Request(url,data=json.dumps(payload).encode(),method='POST',headers={'Authorization':'Bearer '+cfg['token'],'Content-Type':'application/json'}); result=json.loads(urlopen(req,timeout=30).read()); provider_id=(result.get('messages') or [{}])[0].get('id')
            with db() as c:c.execute('UPDATE whatsapp_messages SET status="Sent",provider_message_id=?,provider_response=?,sent_at=CURRENT_TIMESTAMP WHERE id=?',(provider_id,json.dumps(result),mid)); audit(c,u['id'],'SEND_WHATSAPP',d.get('related_type','Message'),d.get('related_id'),recipient,self.client_address[0])
            return self.send_json({'id':mid,'status':'Sent','provider_message_id':provider_id})
        except Exception as e:
            with db() as c:c.execute('UPDATE whatsapp_messages SET status="Failed",provider_response=? WHERE id=?',(str(e)[:500],mid))
            return self.send_json({'id':mid,'status':'Failed','error':str(e)},502)
    def create_cost_centre(self,u,d):
        if u['role']!='Admin':return self.send_json({'error':'Admin only'},403)
        try:
            with db() as c:
                cur=c.execute('INSERT INTO cost_centres(code,name,department,owner_user_id,erp_external_id,active,created_by) VALUES(?,?,?,?,?,?,?)',(d['code'],d['name'],d.get('department'),d.get('owner_user_id'),d.get('erp_external_id'),int(d.get('active',1)),u['id'])); audit(c,u['id'],'CREATE','Cost Centre',cur.lastrowid,d['code'],self.client_address[0]); return self.send_json({'id':cur.lastrowid},201)
        except (KeyError,sqlite3.IntegrityError):return self.send_json({'error':'Cost-centre code exists or required data is missing'},409)
    def create_budget(self,u,d):
        if u['role']!='Admin':return self.send_json({'error':'Admin only'},403)
        try:
            with db() as c:
                cur=c.execute('INSERT INTO budgets(budget_code,cost_centre_id,fiscal_year,category,allocated_amount,currency,status,created_by) VALUES(?,?,?,?,?,?,?,?)',(d['budget_code'],d['cost_centre_id'],d['fiscal_year'],d.get('category'),float(d['allocated_amount']),d.get('currency','INR'),d.get('status','Active'),u['id'])); audit(c,u['id'],'CREATE','Budget',cur.lastrowid,d['budget_code'],self.client_address[0]); return self.send_json({'id':cur.lastrowid},201)
        except (KeyError,ValueError,sqlite3.IntegrityError):return self.send_json({'error':'Invalid or duplicate budget'},409)
    def commit_budget(self,u,d):
        amount=float(d['amount'])
        with db() as c:
            b=c.execute('SELECT * FROM budgets WHERE id=? AND status="Active"',(d['budget_id'],)).fetchone()
            if not b:return self.send_json({'error':'Active budget not found'},404)
            available=b['allocated_amount']-b['committed_amount']-b['consumed_amount']
            if amount>available:return self.send_json({'error':'Budget exceeded','available':available,'requested':amount},409)
            kind=d.get('transaction_type','Commitment'); field='consumed_amount' if kind=='Consumption' else 'committed_amount'; c.execute(f'UPDATE budgets SET {field}={field}+? WHERE id=?',(amount,b['id'])); cur=c.execute('INSERT INTO budget_transactions(budget_id,transaction_type,amount,reference_type,reference_id,note,created_by) VALUES(?,?,?,?,?,?,?)',(b['id'],kind,amount,d['reference_type'],d['reference_id'],d.get('note'),u['id'])); audit(c,u['id'],'BUDGET_'+kind.upper(),'Budget',b['id'],str(amount),self.client_address[0]); return self.send_json({'id':cur.lastrowid,'budget_id':b['id'],'available_before':available,'available_after':available-amount},201)
    def erp_sync(self,u,d):
        if u['role']!='Admin':return self.send_json({'error':'Admin only'},403)
        cfg=CONFIG.get('erp',{}); entity=d.get('entity_type','GRN'); direction=d.get('direction','Export')
        with db() as c:
            queries={'GRN':'SELECT * FROM goods_receipt_notes','Vendor':'SELECT * FROM vendors','Purchase Order':'SELECT * FROM purchase_orders','Inventory':'SELECT * FROM inventory_stock','Budget':'SELECT * FROM budgets'}; rows=[dict(x) for x in c.execute(queries.get(entity,'SELECT * FROM goods_receipt_notes')).fetchall()]; payload={'entity_type':entity,'direction':direction,'records':rows}; status='Export Ready'; response='ERP endpoint not configured; payload retained locally.'
            if cfg.get('enabled'):
                try:
                    headers={'Content-Type':'application/json'}
                    if cfg.get('token'):headers['Authorization']='Bearer '+cfg['token']
                    result=urlopen(Request(cfg['endpoint'],data=json.dumps(payload,default=str).encode(),method='POST',headers=headers),timeout=30).read().decode(); status='Completed'; response=result[:2000]
                except Exception as e:status='Failed'; response=str(e)[:500]
            cur=c.execute('INSERT INTO erp_sync_log(direction,entity_type,record_count,status,endpoint,request_payload,response_payload,created_by) VALUES(?,?,?,?,?,?,?,?)',(direction,entity,len(rows),status,cfg.get('endpoint'),json.dumps(payload,default=str),response,u['id'])); audit(c,u['id'],'ERP_'+direction.upper(),'ERP Sync',cur.lastrowid,status,self.client_address[0]); return self.send_json({'id':cur.lastrowid,'status':status,'record_count':len(rows),'message':response},201 if status!='Failed' else 502)
    def create_backup(self,u,d):
        if u['role']!='Admin':return self.send_json({'error':'Admin only'},403)
        folder=ROOT/'backups'; folder.mkdir(parents=True,exist_ok=True); name=f'inventory_audit_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db'; target=folder/name
        source=sqlite3.connect(DB); dest=sqlite3.connect(target)
        try:source.backup(dest)
        finally:dest.close(); source.close()
        check=sqlite3.connect(target).execute('PRAGMA integrity_check').fetchone()[0]; raw=target.read_bytes(); digest=hashlib.sha256(raw).hexdigest()
        with db() as c:
            cur=c.execute('INSERT INTO backup_log(file_name,file_sha256,size_bytes,integrity_status,created_by) VALUES(?,?,?,?,?)',(name,digest,len(raw),check,u['id'])); audit(c,u['id'],'BACKUP','Database',cur.lastrowid,name,self.client_address[0]); return self.send_json({'id':cur.lastrowid,'file_name':name,'sha256':digest,'size_bytes':len(raw),'integrity_status':check},201)
    def create_vendor(self,u,d):
        if u['role']!='Admin':return self.send_json({'error':'Admin only'},403)
        if not d.get('vendor_code') or not d.get('legal_name'):return self.send_json({'error':'vendor_code and legal_name are required'},400)
        cols=['vendor_code','legal_name','trade_name','gstin_tax_id','pan_registration_no','contact_person','email','phone','address_line','city','state','postal_code','country','payment_terms','department','approval_status','active']; vals=[d.get(x) for x in cols]; vals[12]=vals[12] or 'India'; vals[15]=vals[15] or 'Pending'; vals[16]=int(str(vals[16] if vals[16] is not None else 1).lower() not in {'0','false','no'})
        try:
            with db() as c:
                duplicate=c.execute('SELECT id,vendor_code,legal_name FROM vendors WHERE lower(trim(legal_name))=lower(trim(?)) OR (gstin_tax_id IS NOT NULL AND gstin_tax_id<>"" AND gstin_tax_id=?) LIMIT 1',(d['legal_name'],d.get('gstin_tax_id'))).fetchone()
                if duplicate and not d.get('allow_duplicate'):return self.send_json({'error':'Potential duplicate vendor','duplicate':dict(duplicate),'hint':'Review the existing vendor or set allow_duplicate only after verification'},409)
                cur=c.execute(f"INSERT INTO vendors({','.join(cols)},created_by) VALUES({','.join('?' for _ in cols)},?)",(*vals,u['id'])); audit(c,u['id'],'CREATE','Vendor Master',cur.lastrowid,d['vendor_code'],self.client_address[0]); return self.send_json({'id':cur.lastrowid,'vendor_code':d['vendor_code']},201)
        except sqlite3.IntegrityError:return self.send_json({'error':'Vendor code already exists'},409)
    def import_vendors(self,u,d):
        if u['role']!='Admin':return self.send_json({'error':'Admin only'},403)
        required={'vendor_code','legal_name'}
        try:
            rows=list(csv.DictReader(io.StringIO(d.get('csv_text',''))))
            if not rows or not required.issubset(rows[0]):return self.send_json({'error':'Vendor CSV requires vendor_code and legal_name headers'},400)
            created=updated=0
            with db() as c:
                for row in rows:
                    code=row.get('vendor_code','').strip(); name=row.get('legal_name','').strip()
                    if not code or not name:raise ValueError('Every row requires vendor_code and legal_name')
                    existing=c.execute('SELECT id FROM vendors WHERE vendor_code=?',(code,)).fetchone(); active=int(str(row.get('active','1')).lower() not in {'0','false','no'}); values=(name,row.get('trade_name'),row.get('gstin_tax_id'),row.get('pan_registration_no'),row.get('contact_person'),row.get('email'),row.get('phone'),row.get('address_line'),row.get('city'),row.get('state'),row.get('postal_code'),row.get('country') or 'India',row.get('payment_terms'),row.get('department'),row.get('approval_status') or 'Pending',active,u['id'])
                    if existing:c.execute('UPDATE vendors SET legal_name=?,trade_name=?,gstin_tax_id=?,pan_registration_no=?,contact_person=?,email=?,phone=?,address_line=?,city=?,state=?,postal_code=?,country=?,payment_terms=?,department=?,approval_status=?,active=?,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',(*values,existing['id'])); updated+=1
                    else:c.execute('INSERT INTO vendors(legal_name,trade_name,gstin_tax_id,pan_registration_no,contact_person,email,phone,address_line,city,state,postal_code,country,payment_terms,department,approval_status,active,created_by,vendor_code) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(*values[:-1],u['id'],code)); created+=1
                audit(c,u['id'],'IMPORT','Vendor Master',details=f'Created {created}, updated {updated}',ip=self.client_address[0])
            return self.send_json({'created':created,'updated':updated,'total':len(rows)},201)
        except (ValueError,sqlite3.Error) as e:return self.send_json({'error':str(e)},400)
    def import_purchase_orders(self,u,d):
        required={'po_number','vendor_name','line_number','material_code','material_description','ordered_qty','unit','unit_price'}
        try:
            rows=list(csv.DictReader(io.StringIO(d.get('csv_text',''))))
            if not rows or not required.issubset(rows[0]): return self.send_json({'error':'PO CSV headers must include: '+', '.join(sorted(required))},400)
            with db() as c:
                imported={}
                for row in rows:
                    po=row['po_number'].strip()
                    if not po: raise ValueError('PO number cannot be blank')
                    found=c.execute('SELECT id FROM purchase_orders WHERE po_number=?',(po,)).fetchone()
                    if found: poid=found['id']
                    else:
                        cur=c.execute('INSERT INTO purchase_orders(po_number,po_date,vendor_code,vendor_name,department,currency,total_amount,source,created_by) VALUES(?,?,?,?,?,?,?,?,?)',(po,row.get('po_date'),row.get('vendor_code'),row['vendor_name'],row.get('department'),row.get('currency') or 'INR',0,'CSV Import',u['id'])); poid=cur.lastrowid
                    qty=float(row['ordered_qty']); price=float(row['unit_price']); tax=float(row.get('tax_rate') or 0)
                    c.execute('INSERT OR REPLACE INTO purchase_order_lines(purchase_order_id,line_number,material_code,material_description,ordered_qty,unit,unit_price,tax_rate,received_qty) VALUES(?,?,?,?,?,?,?,?,COALESCE((SELECT received_qty FROM purchase_order_lines WHERE purchase_order_id=? AND line_number=?),0))',(poid,int(row['line_number']),row['material_code'],row['material_description'],qty,row['unit'],price,tax,poid,int(row['line_number'])))
                    imported[po]=poid
                for po,poid in imported.items(): c.execute('UPDATE purchase_orders SET total_amount=(SELECT COALESCE(SUM(ordered_qty*unit_price*(1+tax_rate/100)),0) FROM purchase_order_lines WHERE purchase_order_id=?) WHERE id=?',(poid,poid))
                audit(c,u['id'],'IMPORT','Purchase Order',details=f'{len(rows)} lines / {len(imported)} POs',ip=self.client_address[0])
            return self.send_json({'purchase_orders':len(imported),'lines':len(rows),'po_numbers':list(imported)},201)
        except (ValueError,KeyError,sqlite3.Error) as e: return self.send_json({'error':str(e)},400)
    def upload_invoice(self,u,d):
        name=Path(d.get('file_name','invoice.bin')).name
        try: raw=base64.b64decode(d.get('content_base64',''),validate=True)
        except: return self.send_json({'error':'Invalid file content'},400)
        if not raw or len(raw)>10*1024*1024:return self.send_json({'error':'Invoice file must be 1 byte to 10 MB'},400)
        safe=re.sub(r'[^A-Za-z0-9._-]','_',name); folder=ROOT/'uploads'/'invoices'; folder.mkdir(parents=True,exist_ok=True); stored=f'{datetime.now().strftime("%Y%m%d%H%M%S")}_{secrets.token_hex(4)}_{safe}'; path=folder/stored; path.write_bytes(raw)
        text=''; status='Manual Review Required'
        if name.lower().endswith('.pdf'):
            try:
                import pdfplumber
                with pdfplumber.open(path) as pdf: text='\n'.join((p.extract_text() or '') for p in pdf.pages)
                status='Extracted' if text.strip() else 'Image OCR Engine Required'
            except Exception as e: status='Extraction Failed'
        elif name.lower().endswith(('.txt','.csv')):
            text=raw.decode('utf-8',errors='replace'); status='Extracted'
        fields={}
        patterns={'invoice_number':r'(?:invoice\s*(?:no|number|#)?)\s*[:#-]?\s*([A-Z0-9\-/]+)','po_number':r'(?:p\.?o\.?\s*(?:no|number|#)?)\s*[:#-]?\s*([A-Z0-9\-/]+)','invoice_date':r'(?:invoice\s*date|dated?)\s*[:#-]?\s*([0-9]{1,4}[-/.][0-9]{1,2}[-/.][0-9]{1,4})','total_amount':r'(?:grand\s*total|invoice\s*total|total\s*amount)\s*[:#₹$-]?\s*([0-9,]+(?:\.\d{1,2})?)'}
        for key,pattern in patterns.items():
            m=re.search(pattern,text,re.I); fields[key]=m.group(1).strip() if m else None
        poid=None
        with db() as c:
            if fields.get('po_number'):
                po=c.execute('SELECT id FROM purchase_orders WHERE po_number=?',(fields['po_number'],)).fetchone(); poid=po['id'] if po else None
            digest=hashlib.sha256(raw).hexdigest(); duplicate=c.execute('SELECT id FROM invoices WHERE file_sha256=? OR (invoice_number IS NOT NULL AND invoice_number=? AND lower(COALESCE(vendor_name,""))=lower(?)) ORDER BY id LIMIT 1',(digest,fields.get('invoice_number'),d.get('vendor_name',''))).fetchone(); dup_status='Potential Duplicate' if duplicate else 'Unique'
            cur=c.execute('INSERT INTO invoices(invoice_number,invoice_date,vendor_name,purchase_order_id,file_name,stored_path,mime_type,amount,tax_amount,ocr_status,ocr_text,extracted_json,file_sha256,duplicate_status,duplicate_of,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(fields.get('invoice_number'),fields.get('invoice_date'),d.get('vendor_name'),poid,name,str(path.relative_to(ROOT)),d.get('mime_type'),float(str(fields.get('total_amount') or '0').replace(',','')),0,status,text,json.dumps(fields),digest,dup_status,duplicate['id'] if duplicate else None,u['id'])); audit(c,u['id'],'UPLOAD','Invoice',cur.lastrowid,f'{name}; {dup_status}',self.client_address[0]); return self.send_json({'id':cur.lastrowid,'ocr_status':status,'extracted':fields,'purchase_order_id':poid,'duplicate_status':dup_status,'duplicate_of':duplicate['id'] if duplicate else None},201)
    def create_non_po_request(self,u,d):
        for k in ['department','vendor_name','justification']:
            if not d.get(k):return self.send_json({'error':f'{k} is required'},400)
        with db() as c:
            no=f"NPR-{datetime.now().year}-{c.execute('SELECT COUNT(*)+1 FROM non_po_requests').fetchone()[0]:04d}"; cur=c.execute('INSERT INTO non_po_requests(request_no,department,requester_id,vendor_name,justification,amount,invoice_id,approver_id) VALUES(?,?,?,?,?,?,?,?)',(no,d['department'],u['id'],d['vendor_name'],d['justification'],float(d.get('amount') or 0),d.get('invoice_id'),d.get('approver_id'))); audit(c,u['id'],'REQUEST_APPROVAL','Non-PO Receipt',cur.lastrowid,no,self.client_address[0]); return self.send_json({'id':cur.lastrowid,'request_no':no,'status':'Pending Approval','email_status':'Placeholder - request recorded for configured departmental approver'},201)
    def approve_non_po_request(self,u,d):
        if u['role'] not in {'Admin','Manager'}: return self.send_json({'error':'Manager or Admin approval required'},403)
        decision=d.get('decision','Approved');
        if decision not in {'Approved','Rejected'}:return self.send_json({'error':'Decision must be Approved or Rejected'},400)
        with db() as c:
            cur=c.execute('UPDATE non_po_requests SET status=?,approver_id=?,approval_note=?,approved_at=CURRENT_TIMESTAMP WHERE id=? AND status="Pending Approval"',(decision,u['id'],d.get('approval_note'),d['id']))
            if not cur.rowcount:return self.send_json({'error':'Pending request not found'},404)
            audit(c,u['id'],decision.upper(),'Non-PO Receipt',d['id'],d.get('approval_note',''),self.client_address[0]); return self.send_json({'id':d['id'],'status':decision})
    def create_grn(self,u,d):
        rtype=d.get('receipt_type'); lines=d.get('lines') or []
        if rtype not in {'PO','Non-PO'} or not lines:return self.send_json({'error':'receipt_type and at least one line are required'},400)
        with db() as c:
            if rtype=='PO':
                po=c.execute('SELECT * FROM purchase_orders WHERE id=?',(d.get('purchase_order_id'),)).fetchone()
                if not po:return self.send_json({'error':'Valid purchase_order_id required'},400)
                vendor=po['vendor_name']; department=po['department']
            else:
                req=c.execute("SELECT * FROM non_po_requests WHERE id=? AND status='Approved'",(d.get('non_po_request_id'),)).fetchone()
                if not req:return self.send_json({'error':'Approved non_po_request_id required before Non-PO GRN'},400)
                vendor=req['vendor_name']; department=req['department']
            profile=d.get('industry_profile_code','MANUFACTURING').upper(); no=f"GRN-{datetime.now().year}-{c.execute('SELECT COUNT(*)+1 FROM goods_receipt_notes').fetchone()[0]:04d}"; cur=c.execute('INSERT INTO goods_receipt_notes(grn_number,receipt_type,purchase_order_id,non_po_request_id,invoice_id,receipt_date,vendor_name,department,warehouse,status,inspection_status,industry_profile_code,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',(no,rtype,d.get('purchase_order_id'),d.get('non_po_request_id'),d.get('invoice_id'),d.get('receipt_date') or datetime.now().date().isoformat(),vendor,department,d.get('warehouse','Main Warehouse'),'Received',d.get('inspection_status','Passed'),profile,u['id'])); grnid=cur.lastrowid
            rejected_total=0
            for line in lines:
                received=float(line['received_qty']); rejected=float(line.get('rejected_qty') or 0); accepted=float(line.get('accepted_qty',received-rejected)); rejected_total+=rejected
                c.execute('INSERT INTO goods_receipt_lines(grn_id,po_line_id,material_code,material_description,received_qty,accepted_qty,rejected_qty,unit,batch_no,expiry_date,unit_cost) VALUES(?,?,?,?,?,?,?,?,?,?,?)',(grnid,line.get('po_line_id'),line['material_code'],line['material_description'],received,accepted,rejected,line['unit'],line.get('batch_no'),line.get('expiry_date'),float(line.get('unit_cost') or 0)))
                old=c.execute('SELECT quantity,average_cost FROM inventory_stock WHERE warehouse=? AND material_code=?',(d.get('warehouse','Main Warehouse'),line['material_code'])).fetchone(); oq=old['quantity'] if old else 0; oc=old['average_cost'] if old else 0; cost=float(line.get('unit_cost') or 0); nq=oq+accepted; avg=((oq*oc)+(accepted*cost))/nq if nq else 0
                c.execute('INSERT INTO inventory_stock(warehouse,material_code,material_description,unit,quantity,average_cost) VALUES(?,?,?,?,?,?) ON CONFLICT(warehouse,material_code) DO UPDATE SET material_description=excluded.material_description,unit=excluded.unit,quantity=excluded.quantity,average_cost=excluded.average_cost,updated_at=CURRENT_TIMESTAMP',(d.get('warehouse','Main Warehouse'),line['material_code'],line['material_description'],line['unit'],nq,avg)); c.execute('INSERT INTO inventory_movements(movement_type,material_code,warehouse,quantity,unit_cost,reference_type,reference_id,created_by) VALUES(?,?,?,?,?,?,?,?)',('GRN',line['material_code'],d.get('warehouse','Main Warehouse'),accepted,cost,'GRN',grnid,u['id']))
                if line.get('po_line_id'): c.execute('UPDATE purchase_order_lines SET received_qty=received_qty+? WHERE id=?',(received,line['po_line_id']))
            observation_id=None
            if rejected_total>0 or d.get('inspection_status')=='Failed':
                ref=f"IAO-{datetime.now().year}-{c.execute('SELECT COUNT(*)+1 FROM observations').fetchone()[0]:04d}"; obs=c.execute('INSERT INTO observations(reference_no,title,description,site,department,category,severity,status,owner_id,created_by) VALUES(?,?,?,?,?,?,?,?,?,?)',(ref,f'GRN inspection variance - {no}',f'Rejected quantity: {rejected_total}; linked GRN {no}',d.get('warehouse','Main Warehouse'),department,'Inventory Control','High','Open',u['id'],u['id'])); observation_id=obs.lastrowid; c.execute('UPDATE goods_receipt_notes SET observation_id=? WHERE id=?',(observation_id,grnid))
            gap_count,observation_id=self.run_gap_analysis(c,u,d,grnid,no,rtype,lines,observation_id,department,profile)
            audit(c,u['id'],'CREATE','GRN',grnid,no,self.client_address[0]); return self.send_json({'id':grnid,'grn_number':no,'inventory_updated':True,'observation_id':observation_id,'gap_count':gap_count,'compliance_status':'Gap' if gap_count else 'Compliant'},201)
    def run_gap_analysis(self,c,u,d,grnid,grn_no,rtype,lines,observation_id,department,profile):
        prow=c.execute('SELECT id FROM industry_profiles WHERE code=? AND active=1',(profile,)).fetchone()
        if not prow: profile='MANUFACTURING'; prow=c.execute("SELECT id FROM industry_profiles WHERE code='MANUFACTURING'").fetchone()
        pid=prow['id']; rules={r['rule_code']:dict(r) for r in c.execute('SELECT * FROM compliance_rules WHERE industry_profile_id=? AND enabled=1 AND applies_to IN (?,"Both")',(pid,rtype)).fetchall()}; checks=[]
        def add(code,name,expected,actual,result,severity,category,variance=None): checks.append((code,name,str(expected),str(actual),variance,result,severity,category))
        inv_ok=bool(d.get('invoice_id')); r=rules.get('INVOICE_REQUIRED');
        if r:add('INVOICE_REQUIRED',r['rule_name'],'Invoice linked','Linked' if inv_ok else 'Missing','Pass' if inv_ok else 'Gap',r['severity'],'Document')
        if rtype=='PO':
            po_ok=bool(d.get('purchase_order_id')); r=rules.get('PO_REQUIRED');
            if r:add('PO_REQUIRED',r['rule_name'],'PO linked','Linked' if po_ok else 'Missing','Pass' if po_ok else 'Gap',r['severity'],'Approval')
            qty_tol=float(rules.get('QTY_TOLERANCE',{}).get('parameter_value') or 0); price_tol=float(rules.get('PRICE_TOLERANCE',{}).get('parameter_value') or 0)
            for line in lines:
                pol=c.execute('SELECT * FROM purchase_order_lines WHERE id=?',(line.get('po_line_id'),)).fetchone()
                if not pol:
                    add('PO_LINE_MATCH','Material line matched to PO','PO line','Missing','Gap','High','Quantity'); continue
                received=float(line['received_qty']); balance=float(pol['ordered_qty'])-float(pol['received_qty'])+received; qty_var=((received-balance)/balance*100) if balance else (100 if received else 0); qpass=received<=balance*(1+qty_tol/100)
                add('QTY_TOLERANCE',f"Quantity tolerance - {line['material_code']}",f'≤ {balance*(1+qty_tol/100):.3f}',received,'Pass' if qpass else 'Gap',rules.get('QTY_TOLERANCE',{}).get('severity','High'),'Quantity',qty_var)
                actual_price=float(line.get('unit_cost') or 0); po_price=float(pol['unit_price']); price_var=((actual_price-po_price)/po_price*100) if po_price else 0; ppass=abs(price_var)<=price_tol
                add('PRICE_TOLERANCE',f"Price tolerance - {line['material_code']}",po_price,actual_price,'Pass' if ppass else 'Gap',rules.get('PRICE_TOLERANCE',{}).get('severity','High'),'Price',price_var)
        else:
            approved=bool(d.get('non_po_request_id')); r=rules.get('NON_PO_APPROVAL');
            if r:add('NON_PO_APPROVAL',r['rule_name'],'Approved request','Linked' if approved else 'Missing','Pass' if approved else 'Gap',r['severity'],'Approval')
        for line in lines:
            if 'BATCH_REQUIRED' in rules:add('BATCH_REQUIRED',rules['BATCH_REQUIRED']['rule_name'],'Batch/serial reference',line.get('batch_no') or 'Missing','Pass' if line.get('batch_no') else 'Gap',rules['BATCH_REQUIRED']['severity'],'Traceability')
            if 'EXPIRY_REQUIRED' in rules:add('EXPIRY_REQUIRED',rules['EXPIRY_REQUIRED']['rule_name'],'Expiry date',line.get('expiry_date') or 'Missing','Pass' if line.get('expiry_date') else 'Gap',rules['EXPIRY_REQUIRED']['severity'],'Shelf Life')
            rejected=float(line.get('rejected_qty') or 0); add('REJECTION_CHECK','Rejected quantity check','0',rejected,'Pass' if rejected==0 else 'Gap','High','Quality',rejected)
        gaps=[x for x in checks if x[5]=='Gap']
        if gaps and not observation_id:
            ref=f"IAO-{datetime.now().year}-{c.execute('SELECT COUNT(*)+1 FROM observations').fetchone()[0]:04d}"; summary=', '.join(sorted(set(x[7] for x in gaps))); obs=c.execute('INSERT INTO observations(reference_no,title,description,site,department,category,severity,status,owner_id,created_by) VALUES(?,?,?,?,?,?,?,?,?,?)',(ref,f'GRN compliance gaps - {grn_no}',f'{len(gaps)} gap(s): {summary}',d.get('warehouse','Main Warehouse'),department,'Inventory Control','High','Open',u['id'],u['id'])); observation_id=obs.lastrowid; c.execute('UPDATE goods_receipt_notes SET observation_id=? WHERE id=?',(observation_id,grnid))
        for code,name,expected,actual,variance,result,severity,category in checks:c.execute('INSERT INTO grn_compliance_checks(grn_id,industry_profile_id,rule_code,check_name,expected_value,actual_value,variance_value,result,severity,gap_category,observation_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)',(grnid,pid,code,name,expected,actual,variance,result,severity,category,observation_id if result=='Gap' else None))
        c.execute('UPDATE goods_receipt_notes SET industry_profile_code=?,compliance_status=?,gap_count=? WHERE id=?',(profile,'Gap' if gaps else 'Compliant',len(gaps),grnid)); return len(gaps),observation_id
    def create_observation(self,u,d):
        req=['title','severity']; missing=[x for x in req if not d.get(x)]
        if missing:return self.send_json({'error':'Missing: '+','.join(missing)},400)
        with db() as c:
            no=f"IAO-{datetime.now().year}-{c.execute('SELECT COUNT(*)+1 FROM observations').fetchone()[0]:04d}"; cur=c.execute('INSERT INTO observations(reference_no,title,description,site,department,category,severity,status,owner_id,due_date,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?)',(no,d['title'],d.get('description'),d.get('site'),d.get('department'),d.get('category'),d['severity'],d.get('status','Open'),d.get('owner_id') or u['id'],d.get('due_date'),u['id'])); audit(c,u['id'],'CREATE','Inventory Audit Observation',cur.lastrowid,no,self.client_address[0]); return self.send_json({'id':cur.lastrowid,'reference_no':no},201)
    def create_incident(self,u,d):
        with db() as c:
            no=f"INC-{datetime.now().year}-{c.execute('SELECT COUNT(*)+1 FROM incidents').fetchone()[0]:04d}"; cur=c.execute('INSERT INTO incidents(incident_no,observation_id,title,description,severity,status,owner_id,created_by) VALUES(?,?,?,?,?,?,?,?)',(no,d.get('observation_id'),d['title'],d.get('description'),d.get('severity','Medium'),d.get('status','Open'),d.get('owner_id') or u['id'],u['id'])); audit(c,u['id'],'CREATE','Incident',cur.lastrowid,no,self.client_address[0]); return self.send_json({'id':cur.lastrowid,'incident_no':no},201)
    def create_capa(self,u,d):
        with db() as c:
            no=f"CAPA-{datetime.now().year}-{c.execute('SELECT COUNT(*)+1 FROM capas').fetchone()[0]:04d}"; cur=c.execute('INSERT INTO capas(capa_no,observation_id,incident_id,action_type,action,owner_id,target_date,status,created_by) VALUES(?,?,?,?,?,?,?,?,?)',(no,d.get('observation_id'),d.get('incident_id'),d.get('action_type','Corrective'),d['action'],d.get('owner_id') or u['id'],d.get('target_date'),d.get('status','Open'),u['id'])); audit(c,u['id'],'CREATE','CAPA',cur.lastrowid,no,self.client_address[0]); return self.send_json({'id':cur.lastrowid,'capa_no':no},201)
    def create_transfer(self,u,d):
        with db() as c:
            oid=int(d['observation_id']); old=c.execute('SELECT owner_id FROM observations WHERE id=?',(oid,)).fetchone(); cur=c.execute('INSERT INTO transfers(observation_id,from_user_id,to_user_id,note,created_by) VALUES(?,?,?,?,?)',(oid,old['owner_id'] if old else None,d['to_user_id'],d.get('note'),u['id'])); c.execute('UPDATE observations SET owner_id=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',(d['to_user_id'],oid)); audit(c,u['id'],'TRANSFER','Inventory Audit Observation',oid,json.dumps(d),self.client_address[0]); return self.send_json({'id':cur.lastrowid},201)
    def create_escalation(self,u,d):
        with db() as c:
            cur=c.execute('INSERT INTO escalations(observation_id,level,reason,escalated_to,status,created_by) VALUES(?,?,?,?,?,?)',(d['observation_id'],d.get('level',1),d['reason'],d.get('escalated_to'),d.get('status','Open'),u['id'])); audit(c,u['id'],'ESCALATE','Inventory Audit Observation',d['observation_id'],d['reason'],self.client_address[0]); return self.send_json({'id':cur.lastrowid},201)
    def share(self,u,d):
        channel=d.get('channel','email').lower(); enabled=bool(CONFIG.get('smtp',{}).get('enabled')) if channel=='email' else bool(CONFIG.get('whatsapp',{}).get('enabled')); status='Queued' if enabled else 'Placeholder'
        msg='Integration configured; provider adapter ready for implementation.' if enabled else f'{channel.title()} provider not configured; request recorded only.'
        with db() as c:
            cur=c.execute('INSERT INTO share_log(entity_type,entity_id,channel,recipient,status,provider_message,created_by) VALUES(?,?,?,?,?,?,?)',(d.get('entity_type','Inventory Audit Observation'),d['entity_id'],channel,d['recipient'],status,msg,u['id'])); audit(c,u['id'],'SHARE',d.get('entity_type','Inventory Audit Observation'),d['entity_id'],f'{channel}:{status}',self.client_address[0]); return self.send_json({'id':cur.lastrowid,'status':status,'message':msg},202)
    def do_PUT(self):
        p=urlparse(self.path).path; u=self.require({'Admin'})
        if not u:return
        data=self.body()
        um=re.fullmatch(r'/api/admin/users/(\d+)',p)
        if um:
            if data.get('role') not in ALLOWED_ROLES:return self.send_json({'error':'Invalid role'},400)
            with db() as c:
                rid=c.execute('SELECT id FROM roles WHERE name=?',(data['role'],)).fetchone()['id']; cur=c.execute('UPDATE users SET full_name=?,email=?,role_id=?,active=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',(data['full_name'],data.get('email'),rid,int(data.get('active',1)),int(um.group(1))))
                if not cur.rowcount:return self.send_json({'error':'User not found'},404)
                audit(c,u['id'],'UPDATE','User',int(um.group(1)),data['role'],self.client_address[0]); return self.send_json({'id':int(um.group(1)),'updated':True})
        m=re.fullmatch(r'/api/vendors/(\d+)',p)
        if not m:return self.send_json({'error':'Not found'},404)
        if not data or not data.get('vendor_code') or not data.get('legal_name'):return self.send_json({'error':'vendor_code and legal_name are required'},400)
        cols=['vendor_code','legal_name','trade_name','gstin_tax_id','pan_registration_no','contact_person','email','phone','address_line','city','state','postal_code','country','payment_terms','department','approval_status','active']; vals=[data.get(x) for x in cols]; vals[12]=vals[12] or 'India'; vals[15]=vals[15] or 'Pending'; vals[16]=int(str(vals[16] if vals[16] is not None else 1).lower() not in {'0','false','no'})
        try:
            with db() as c:
                cur=c.execute('UPDATE vendors SET '+','.join(f'{x}=?' for x in cols)+',updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',(*vals,u['id'],int(m.group(1))))
                if not cur.rowcount:return self.send_json({'error':'Vendor not found'},404)
                audit(c,u['id'],'UPDATE','Vendor Master',int(m.group(1)),data['vendor_code'],self.client_address[0]); return self.send_json({'id':int(m.group(1)),'updated':True})
        except sqlite3.IntegrityError:return self.send_json({'error':'Vendor code already exists'},409)
    def do_DELETE(self):
        p=urlparse(self.path).path; u=self.require({'Admin'})
        if not u:return
        um=re.fullmatch(r'/api/admin/users/(\d+)',p)
        if um:
            if int(um.group(1))==u['id']:return self.send_json({'error':'Cannot deactivate your own account'},400)
            with db() as c:
                cur=c.execute('UPDATE users SET active=0,updated_at=CURRENT_TIMESTAMP WHERE id=?',(int(um.group(1)),))
                if not cur.rowcount:return self.send_json({'error':'User not found'},404)
                audit(c,u['id'],'DEACTIVATE','User',int(um.group(1)),ip=self.client_address[0]); return self.send_json({'id':int(um.group(1)),'deleted':True,'recoverable':True})
        m=re.fullmatch(r'/api/vendors/(\d+)',p)
        if not m:return self.send_json({'error':'Not found'},404)
        with db() as c:
            cur=c.execute('UPDATE vendors SET active=0,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',(u['id'],int(m.group(1))))
            if not cur.rowcount:return self.send_json({'error':'Vendor not found'},404)
            audit(c,u['id'],'DEACTIVATE','Vendor Master',int(m.group(1)),'Safe delete',self.client_address[0]); return self.send_json({'id':int(m.group(1)),'deleted':True,'recoverable':True})
    def do_GET(self):
        parsed=urlparse(self.path); p=parsed.path
        if p=='/api/health': return self.send_json({'status':'ok','database':str(DB),'app':'Inventory Audit Management Phase 1','supabase':supabase_status(check_remote=True)|{'sync':supabase_sync_status()}})
        if p=='/api/approval-link':
            token=(parse_qs(parsed.query).get('token') or [''])[0]; token_hash=hashlib.sha256(token.encode()).hexdigest()
            with db() as c:
                row=c.execute("SELECT t.instance_id,t.expires_at,i.entity_type,i.entity_id,i.status,w.name workflow_name FROM approval_link_tokens t JOIN approval_instances i ON i.id=t.instance_id JOIN approval_workflows w ON w.id=i.workflow_id WHERE t.token_hash=? AND t.used_at IS NULL AND t.expires_at>CURRENT_TIMESTAMP",(token_hash,)).fetchone()
                if not row:return self.send_json({'error':'Approval link is invalid or expired'},404)
                return self.send_json(dict(row))
        if p.startswith('/api/'):
            u=self.require();
            if not u:return
            doc_match=re.fullmatch(r'/api/invoices/(\d+)/document',p)
            if doc_match:
                with db() as c:
                    inv=c.execute('SELECT * FROM invoices WHERE id=?',(int(doc_match.group(1)),)).fetchone()
                    if not inv:return self.send_json({'error':'Invoice not found'},404)
                    target=(ROOT/inv['stored_path']).resolve(); uploads=(ROOT/'uploads').resolve()
                    if uploads not in target.parents or not target.is_file():return self.send_json({'error':'Document unavailable'},404)
                    action='download' if parse_qs(parsed.query).get('download')==['1'] else 'view'; c.execute('INSERT INTO document_access_log(invoice_id,user_id,action,ip_address) VALUES(?,?,?,?)',(inv['id'],u['id'],action,self.client_address[0])); audit(c,u['id'],action.upper(),'Invoice Document',inv['id'],inv['file_name'],self.client_address[0]); data=target.read_bytes(); self.send_response(200); self.send_header('Content-Type',inv['mime_type'] or mimetypes.guess_type(inv['file_name'])[0] or 'application/octet-stream'); self.send_header('Content-Disposition',f'{"attachment" if action=="download" else "inline"}; filename="{Path(inv["file_name"]).name}"'); self.send_header('Content-Length',str(len(data))); self.send_header('X-Content-Type-Options','nosniff'); self.end_headers(); return self.wfile.write(data)
            if p=='/api/templates/vendor-master.csv':
                data=(ROOT/'templates'/'vendor_master_template.csv').read_bytes(); self.send_response(200); self.send_header('Content-Type','text/csv'); self.send_header('Content-Disposition','attachment; filename=vendor_master_template.csv'); self.send_header('Content-Length',str(len(data))); self.end_headers(); return self.wfile.write(data)
            with db() as c:
                if p=='/api/me': return self.send_json({'user':dict(u)})
                if p=='/api/supabase-sync':
                    if u['role']!='Admin':return self.send_json({'error':'Admin only'},403)
                    runs=[dict(x) for x in c.execute('SELECT * FROM supabase_sync_runs ORDER BY id DESC LIMIT 20').fetchall()]
                    counts=[dict(x) for x in c.execute('SELECT source_table,COUNT(*) records FROM supabase_sync_state WHERE active=1 GROUP BY source_table ORDER BY source_table').fetchall()]
                    files=[dict(x) for x in c.execute('SELECT entity_type,entity_id,local_path,object_path,sha256,size_bytes,status,attempts,last_error,synced_at FROM supabase_file_sync_state ORDER BY entity_type,entity_id').fetchall()]
                    failures=[dict(x) for x in c.execute('SELECT * FROM supabase_sync_failures WHERE resolved=0 ORDER BY last_failed_at DESC LIMIT 100').fetchall()]
                    reconciliations=[dict(x) for x in c.execute('SELECT * FROM supabase_reconciliation_runs ORDER BY id DESC LIMIT 20').fetchall()]
                    return self.send_json({'status':supabase_sync_status(),'record_counts':counts,'files':files,'open_failures':failures,'recent_runs':runs,'reconciliations':reconciliations})
                if p=='/api/dashboard':
                    stats={t:c.execute(f'SELECT COUNT(*) n FROM {t}').fetchone()['n'] for t in ['observations','incidents','capas','escalations']}; stats['overdue']=c.execute("SELECT COUNT(*) n FROM observations WHERE due_date<date('now') AND status NOT IN ('Closed','Completed')").fetchone()['n']; return self.send_json(stats)
                if p=='/api/purchase-orders': return self.send_json([dict(x) for x in c.execute('SELECT p.*,COUNT(l.id) line_count,COALESCE(SUM(l.received_qty),0) received_qty FROM purchase_orders p LEFT JOIN purchase_order_lines l ON l.purchase_order_id=p.id GROUP BY p.id ORDER BY p.id DESC').fetchall()])
                if p=='/api/purchase-order-lines':
                    poid=(parse_qs(parsed.query).get('purchase_order_id') or [None])[0]
                    return self.send_json([dict(x) for x in c.execute('SELECT * FROM purchase_order_lines WHERE purchase_order_id=? ORDER BY line_number',(poid,)).fetchall()])
                if p=='/api/invoices': return self.send_json([dict(x) for x in c.execute('SELECT i.*,p.po_number FROM invoices i LEFT JOIN purchase_orders p ON p.id=i.purchase_order_id ORDER BY i.id DESC').fetchall()])
                if p=='/api/non-po-requests': return self.send_json([dict(x) for x in c.execute('SELECT n.*,r.full_name requester,a.full_name approver FROM non_po_requests n JOIN users r ON r.id=n.requester_id LEFT JOIN users a ON a.id=n.approver_id ORDER BY n.id DESC').fetchall()])
                if p=='/api/grns': return self.send_json([dict(x) for x in c.execute('SELECT g.*,p.po_number,n.request_no FROM goods_receipt_notes g LEFT JOIN purchase_orders p ON p.id=g.purchase_order_id LEFT JOIN non_po_requests n ON n.id=g.non_po_request_id ORDER BY g.id DESC').fetchall()])
                if p=='/api/inventory': return self.send_json([dict(x) for x in c.execute('SELECT * FROM inventory_stock ORDER BY warehouse,material_description').fetchall()])
                if p=='/api/inventory-movements': return self.send_json([dict(x) for x in c.execute('SELECT * FROM inventory_movements ORDER BY id DESC LIMIT 500').fetchall()])
                if p=='/api/industry-profiles': return self.send_json([dict(x) for x in c.execute('SELECT * FROM industry_profiles WHERE active=1 ORDER BY name').fetchall()])
                if p=='/api/compliance-rules': return self.send_json([dict(x) for x in c.execute('SELECT r.*,p.code industry_code,p.name industry_name FROM compliance_rules r JOIN industry_profiles p ON p.id=r.industry_profile_id ORDER BY p.name,r.rule_name').fetchall()])
                if p=='/api/gap-analysis': return self.send_json([dict(x) for x in c.execute('SELECT x.*,g.grn_number,g.receipt_type,g.vendor_name,g.industry_profile_code FROM grn_compliance_checks x JOIN goods_receipt_notes g ON g.id=x.grn_id WHERE x.result<>"Pass" ORDER BY x.id DESC').fetchall()])
                if p=='/api/vendors': return self.send_json([dict(x) for x in c.execute('SELECT * FROM vendors ORDER BY active DESC,legal_name').fetchall()])
                if p=='/api/complete-records':
                    sql='''SELECT g.id,g.grn_number,g.receipt_type,g.receipt_date,g.vendor_name,v.vendor_code,g.department,g.warehouse,g.industry_profile_code,g.inspection_status,g.compliance_status,g.gap_count,p.po_number,n.request_no,n.status non_po_approval_status,i.invoice_number,i.file_name invoice_file,i.ocr_status,i.amount invoice_amount,(SELECT GROUP_CONCAT(l.material_code||' - '||l.material_description||' | received '||l.received_qty||' | accepted '||l.accepted_qty||' | rejected '||l.rejected_qty||' '||l.unit,'; ') FROM goods_receipt_lines l WHERE l.grn_id=g.id) materials,(SELECT GROUP_CONCAT(s.material_code||'='||s.quantity||' '||s.unit,'; ') FROM inventory_stock s WHERE s.warehouse=g.warehouse AND s.material_code IN (SELECT material_code FROM goods_receipt_lines WHERE grn_id=g.id)) current_stock,o.reference_no observation_no,o.status observation_status,(SELECT GROUP_CONCAT(DISTINCT inc.incident_no) FROM incidents inc WHERE inc.observation_id=o.id) incident_numbers,(SELECT GROUP_CONCAT(DISTINCT cp.capa_no) FROM capas cp WHERE cp.observation_id=o.id) capa_numbers,(SELECT COUNT(*) FROM escalations e WHERE e.observation_id=o.id) escalation_count,(SELECT COUNT(*) FROM share_log sh WHERE sh.entity_id IN (g.id,o.id) AND sh.entity_type IN ('GRN','Inventory Audit Observation')) share_count,g.created_at FROM goods_receipt_notes g LEFT JOIN purchase_orders p ON p.id=g.purchase_order_id LEFT JOIN non_po_requests n ON n.id=g.non_po_request_id LEFT JOIN invoices i ON i.id=g.invoice_id LEFT JOIN observations o ON o.id=g.observation_id LEFT JOIN vendors v ON lower(v.legal_name)=lower(g.vendor_name) ORDER BY g.id DESC'''
                    return self.send_json([dict(x) for x in c.execute(sql).fetchall()])
                if p=='/api/approval-workflows': return self.send_json([dict(x) for x in c.execute('SELECT w.*,COUNT(s.id) step_count FROM approval_workflows w LEFT JOIN approval_steps s ON s.workflow_id=w.id GROUP BY w.id ORDER BY w.id DESC').fetchall()])
                if p=='/api/approval-steps': return self.send_json([dict(x) for x in c.execute('SELECT s.*,w.workflow_code FROM approval_steps s JOIN approval_workflows w ON w.id=s.workflow_id ORDER BY w.id,s.step_order').fetchall()])
                if p=='/api/approvals': return self.send_json([dict(x) for x in c.execute('SELECT i.*,w.workflow_code,w.name workflow_name,u.full_name requester,(SELECT step_name FROM approval_steps WHERE workflow_id=i.workflow_id AND step_order=i.current_step) current_step_name FROM approval_instances i JOIN approval_workflows w ON w.id=i.workflow_id JOIN users u ON u.id=i.requested_by ORDER BY i.id DESC').fetchall()])
                if p=='/api/transaction-controls': return self.send_json([dict(x) for x in c.execute('SELECT * FROM transaction_controls ORDER BY updated_at DESC').fetchall()])
                if p=='/api/notifications': return self.send_json([dict(x) for x in c.execute('SELECT * FROM notification_outbox ORDER BY id DESC LIMIT 500').fetchall()])
                if p=='/api/document-access': return self.send_json([dict(x) for x in c.execute('SELECT d.*,i.invoice_number,i.file_name,u.username FROM document_access_log d JOIN invoices i ON i.id=d.invoice_id JOIN users u ON u.id=d.user_id ORDER BY d.id DESC LIMIT 500').fetchall()])
                if p=='/api/ocr-jobs': return self.send_json([dict(x) for x in c.execute('SELECT j.*,i.invoice_number,i.file_name FROM ocr_jobs j JOIN invoices i ON i.id=j.invoice_id ORDER BY j.id DESC').fetchall()])
                if p=='/api/whatsapp-messages': return self.send_json([dict(x) for x in c.execute('SELECT * FROM whatsapp_messages ORDER BY id DESC').fetchall()])
                if p=='/api/cost-centres': return self.send_json([dict(x) for x in c.execute('SELECT c.*,u.full_name owner FROM cost_centres c LEFT JOIN users u ON u.id=c.owner_user_id ORDER BY c.active DESC,c.name').fetchall()])
                if p=='/api/budgets': return self.send_json([dict(x) for x in c.execute('SELECT b.*,c.code cost_centre_code,c.name cost_centre_name,(b.allocated_amount-b.committed_amount-b.consumed_amount) available_amount FROM budgets b JOIN cost_centres c ON c.id=b.cost_centre_id ORDER BY b.fiscal_year DESC,b.budget_code').fetchall()])
                if p=='/api/budget-transactions': return self.send_json([dict(x) for x in c.execute('SELECT t.*,b.budget_code FROM budget_transactions t JOIN budgets b ON b.id=t.budget_id ORDER BY t.id DESC').fetchall()])
                if p=='/api/erp-sync-log': return self.send_json([dict(x) for x in c.execute('SELECT id,direction,entity_type,record_count,status,endpoint,response_payload,created_at FROM erp_sync_log ORDER BY id DESC').fetchall()])
                if p=='/api/backups': return self.send_json([dict(x) for x in c.execute('SELECT * FROM backup_log ORDER BY id DESC').fetchall()])
                if p=='/api/security-events':
                    if u['role']!='Admin':return self.send_json({'error':'Admin only'},403)
                    return self.send_json([dict(x) for x in c.execute('SELECT * FROM security_events ORDER BY id DESC LIMIT 500').fetchall()])
                if p=='/api/users':
                    if u['role']!='Admin':return self.send_json({'error':'Admin only'},403)
                    return self.send_json([dict(x) for x in c.execute('SELECT u.id,u.username,u.full_name,u.email,r.name role,u.active,u.must_change_password,u.created_at,u.updated_at FROM users u JOIN roles r ON r.id=u.role_id ORDER BY u.full_name').fetchall()])
                mapping={'/api/observations':'SELECT o.*,u.full_name owner FROM observations o LEFT JOIN users u ON u.id=o.owner_id ORDER BY o.id DESC','/api/incidents':'SELECT i.*,u.full_name owner FROM incidents i LEFT JOIN users u ON u.id=i.owner_id ORDER BY i.id DESC','/api/capas':'SELECT c.*,u.full_name owner FROM capas c LEFT JOIN users u ON u.id=c.owner_id ORDER BY c.id DESC','/api/transfers':'SELECT t.*,fu.full_name from_user,tu.full_name to_user FROM transfers t LEFT JOIN users fu ON fu.id=t.from_user_id LEFT JOIN users tu ON tu.id=t.to_user_id ORDER BY t.id DESC','/api/escalations':'SELECT e.*,u.full_name escalated_to_name FROM escalations e LEFT JOIN users u ON u.id=e.escalated_to ORDER BY e.id DESC','/api/audit':'SELECT a.*,u.username FROM audit_trail a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 500','/api/masters':'SELECT * FROM masters ORDER BY master_type,name','/api/users':'SELECT u.id,u.username,u.full_name,u.email,r.name role,u.active FROM users u JOIN roles r ON r.id=u.role_id ORDER BY u.full_name','/api/shares':'SELECT * FROM share_log ORDER BY id DESC'}
                if p in mapping:return self.send_json([dict(x) for x in c.execute(mapping[p]).fetchall()])
                if p=='/api/reports/summary.csv':
                    rows=c.execute('SELECT reference_no,title,site,department,category,severity,status,due_date,created_at FROM observations ORDER BY id').fetchall(); out=io.StringIO(); w=csv.writer(out); w.writerow(rows[0].keys() if rows else ['reference_no']); w.writerows([list(r) for r in rows]); data=out.getvalue().encode(); self.send_response(200); self.send_header('Content-Type','text/csv'); self.send_header('Content-Disposition','attachment; filename=inventory_audit_observations.csv'); self.send_header('Content-Length',str(len(data))); self.end_headers(); return self.wfile.write(data)
            return self.send_json({'error':'Not found'},404)
        self.static(p)
    def static(self,p):
        rel='index.html' if p in ('/','') else p.lstrip('/'); target=(ROOT/'frontend'/rel).resolve(); base=(ROOT/'frontend').resolve()
        if base not in target.parents and target!=base:return self.send_json({'error':'Forbidden'},403)
        if not target.is_file(): target=ROOT/'frontend'/'index.html'
        data=target.read_bytes(); self.send_response(200); self.send_header('Content-Type',mimetypes.guess_type(str(target))[0] or 'application/octet-stream'); self.send_header('Content-Length',str(len(data))); self.send_header('X-Content-Type-Options','nosniff'); self.send_header('X-Frame-Options','DENY'); self.send_header('Referrer-Policy','no-referrer'); self.send_header('Content-Security-Policy',"default-src 'self'; img-src 'self' blob: data:; style-src 'self'; script-src 'self' 'unsafe-inline'; connect-src 'self'"); self.end_headers(); self.wfile.write(data)

if __name__=='__main__':
    init_db(); start_supabase_worker(DB,CONFIG); host=os.getenv('IAM_HOST',CONFIG['host']); port=int(os.getenv('IAM_PORT',CONFIG['port'])); server=ThreadingHTTPServer((host,port),App); scheme='http'
    if CONFIG.get('https',{}).get('enabled'):
        cert=(ROOT/CONFIG['https']['cert_file']).resolve(); key=(ROOT/CONFIG['https']['key_file']).resolve()
        if not cert.is_file() or not key.is_file():raise RuntimeError('HTTPS is enabled but certificate or key file is missing')
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.minimum_version=ssl.TLSVersion.TLSv1_2; context.load_cert_chain(cert,key); server.socket=context.wrap_socket(server.socket,server_side=True); scheme='https'
    print(f'Inventory Audit Management running at {scheme}://{host}:{port}'); server.serve_forever()
