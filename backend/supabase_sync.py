import base64, hashlib, json, mimetypes, os, re, sqlite3, threading, uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

BUSINESS_TABLES=(
    'masters','observations','incidents','capas','transfers','escalations','share_log','audit_trail',
    'vendors','purchase_orders','purchase_order_lines','invoices','non_po_requests','goods_receipt_notes',
    'goods_receipt_lines','inventory_stock','inventory_movements','industry_profiles','compliance_rules',
    'grn_compliance_checks','approval_workflows','approval_steps','approval_instances','approval_actions',
    'transaction_controls','notification_outbox','document_access_log','ocr_jobs','whatsapp_messages',
    'cost_centres','budgets','budget_transactions','erp_sync_log','security_events','backup_log'
)

STATUS={'running':False,'enabled':False,'connected':False,'last_started_at':None,'last_completed_at':None,
        'last_status':'Not started','records_uploaded':0,'records_deleted':0,'files_uploaded':0,'files_verified':0,
        'files_failed':0,'last_reconciliation':None,'last_error':None}
LOCK=threading.Lock(); WAKE=threading.Event(); STOP=threading.Event()

def _json_value(value):
    if isinstance(value,bytes): return {'encoding':'base64','value':base64.b64encode(value).decode()}
    return value

def _key():
    return (os.getenv('IAM_SUPABASE_SECRET_KEY') or os.getenv('IAM_SUPABASE_SERVICE_ROLE_KEY','')).strip()

def _headers(key):
    headers={'apikey':key,'Content-Type':'application/json','Prefer':'resolution=merge-duplicates,return=minimal'}
    if not key.startswith('sb_secret_'): headers['Authorization']='Bearer '+key
    return headers

def _post(url,key,records):
    query=urlencode({'on_conflict':'source_instance,source_table,source_id'})
    request=Request(url.rstrip('/')+'/rest/v1/iam_sync_records?'+query,
                    data=json.dumps(records,separators=(',',':')).encode(),method='POST',headers=_headers(key))
    with urlopen(request,timeout=30) as response:
        if response.status not in (200,201,204): raise RuntimeError(f'Unexpected Supabase response {response.status}')

def _upsert(url,key,table,on_conflict,records):
    query=urlencode({'on_conflict':on_conflict}); request=Request(url.rstrip('/')+f'/rest/v1/{table}?'+query,data=json.dumps(records,separators=(',',':')).encode(),method='POST',headers=_headers(key))
    with urlopen(request,timeout=30) as response:
        if response.status not in (200,201,204): raise RuntimeError(f'Unexpected Supabase response {response.status}')

def _upload_file(url,key,bucket,object_path,raw,mime_type):
    headers={'apikey':key,'Content-Type':mime_type or 'application/octet-stream','x-upsert':'true','cache-control':'3600'}
    if not key.startswith('sb_secret_'): headers['Authorization']='Bearer '+key
    request=Request(url.rstrip('/')+'/storage/v1/object/'+quote(bucket,safe='')+'/'+quote(object_path,safe='/'),data=raw,method='POST',headers=headers)
    with urlopen(request,timeout=60) as response:
        if response.status not in (200,201): raise RuntimeError(f'Upload returned {response.status}')

def _download_file(url,key,bucket,object_path):
    headers={'apikey':key}
    if not key.startswith('sb_secret_'): headers['Authorization']='Bearer '+key
    request=Request(url.rstrip('/')+'/storage/v1/object/'+quote(bucket,safe='')+'/'+quote(object_path,safe='/'),headers=headers)
    with urlopen(request,timeout=60) as response:return response.read()

def _get_rows(url,key,table,query):
    headers={'apikey':key}
    if not key.startswith('sb_secret_'): headers['Authorization']='Bearer '+key
    request=Request(url.rstrip('/')+f'/rest/v1/{table}?'+query,headers=headers)
    with urlopen(request,timeout=30) as response:return json.loads(response.read() or b'[]')

def _safe_name(name):
    value=re.sub(r'[^A-Za-z0-9._-]+','_',Path(name or 'document').name).strip('._')
    return value[:160] or 'document'

def _record_failure(connection,sync_type,source_table,source_id,error):
    connection.execute('INSERT INTO supabase_sync_failures(sync_type,source_table,source_id,error) VALUES(?,?,?,?) ON CONFLICT(sync_type,source_table,source_id,resolved) DO UPDATE SET error=excluded.error,attempt_count=supabase_sync_failures.attempt_count+1,last_failed_at=CURRENT_TIMESTAMP',(sync_type,source_table,source_id,str(error)[:1000]))

def _resolve_failure(connection,sync_type,source_table,source_id):
    connection.execute('UPDATE supabase_sync_failures SET resolved=1,resolved_at=CURRENT_TIMESTAMP WHERE sync_type=? AND source_table=? AND source_id=? AND resolved=0',(sync_type,source_table,source_id))

def _sync_invoice_files(connection,db_path,url,key,instance):
    uploaded=verified=failed=0; root=Path(db_path).resolve().parent.parent; bucket='iam-private-documents'
    if 'invoices' not in _existing_tables(connection):return uploaded,verified,failed
    for invoice in connection.execute('SELECT id,file_name,stored_path,mime_type,file_sha256 FROM invoices WHERE stored_path IS NOT NULL'):
        entity_id=str(invoice['id']); local=(root/invoice['stored_path']).resolve()
        if root not in local.parents or not local.is_file():
            message='Local invoice file is missing or outside the project directory'; _record_failure(connection,'File','invoices',entity_id,message); connection.execute('INSERT INTO supabase_file_sync_state(entity_type,entity_id,local_path,status,attempts,last_error) VALUES(?,?,?,?,1,?) ON CONFLICT(entity_type,entity_id) DO UPDATE SET status=excluded.status,attempts=supabase_file_sync_state.attempts+1,last_error=excluded.last_error',('Invoice',entity_id,invoice['stored_path'],'Missing',message)); failed+=1; continue
        raw=local.read_bytes(); digest=hashlib.sha256(raw).hexdigest(); size=len(raw); old=connection.execute('SELECT sha256,status FROM supabase_file_sync_state WHERE entity_type=? AND entity_id=?',('Invoice',entity_id)).fetchone()
        if old and old['sha256']==digest and old['status']=='Verified': verified+=1; continue
        object_path=f'{instance}/invoices/{entity_id}/{_safe_name(invoice["file_name"])}'
        try:
            mime=invoice['mime_type'] or mimetypes.guess_type(invoice['file_name'])[0] or 'application/octet-stream'; _upload_file(url,key,bucket,object_path,raw,mime); uploaded+=1
            remote=_download_file(url,key,bucket,object_path)
            if hashlib.sha256(remote).hexdigest()!=digest: raise RuntimeError('Uploaded file integrity verification failed')
            metadata={'source_instance':instance,'entity_type':'Invoice','entity_id':entity_id,'bucket_id':bucket,'object_path':object_path,'original_name':invoice['file_name'],'mime_type':mime,'size_bytes':size,'sha256':digest,'verified_at':datetime.now(timezone.utc).isoformat(),'status':'Verified','last_error':None}
            _upsert(url,key,'iam_sync_files','source_instance,entity_type,entity_id',[metadata]); connection.execute('INSERT INTO supabase_file_sync_state(entity_type,entity_id,local_path,object_path,sha256,size_bytes,status,attempts,last_error,synced_at) VALUES(?,?,?,?,?,?,"Verified",1,NULL,CURRENT_TIMESTAMP) ON CONFLICT(entity_type,entity_id) DO UPDATE SET local_path=excluded.local_path,object_path=excluded.object_path,sha256=excluded.sha256,size_bytes=excluded.size_bytes,status="Verified",attempts=supabase_file_sync_state.attempts+1,last_error=NULL,synced_at=CURRENT_TIMESTAMP',('Invoice',entity_id,invoice['stored_path'],object_path,digest,size)); _resolve_failure(connection,'File','invoices',entity_id); verified+=1
        except (HTTPError,URLError,TimeoutError,RuntimeError,OSError) as exc:
            _record_failure(connection,'File','invoices',entity_id,exc); connection.execute('INSERT INTO supabase_file_sync_state(entity_type,entity_id,local_path,object_path,sha256,size_bytes,status,attempts,last_error) VALUES(?,?,?,?,?,?,"Failed",1,?) ON CONFLICT(entity_type,entity_id) DO UPDATE SET status="Failed",attempts=supabase_file_sync_state.attempts+1,last_error=excluded.last_error',('Invoice',entity_id,invoice['stored_path'],object_path,digest,size,str(exc)[:1000])); failed+=1
    return uploaded,verified,failed

def _instance_id(connection):
    row=connection.execute("SELECT value FROM supabase_sync_meta WHERE key='instance_id'").fetchone()
    if row:return row[0]
    value=str(uuid.uuid4()); connection.execute("INSERT INTO supabase_sync_meta(key,value) VALUES('instance_id',?)",(value,)); return value

def _existing_tables(connection):
    return {r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}

def sync_once(db_path,config):
    if not LOCK.acquire(blocking=False): return {'status':'Already running'}
    started=datetime.now(timezone.utc).isoformat(); key=_key(); cfg=config.get('supabase',{})
    STATUS.update({'running':True,'enabled':bool(cfg.get('enabled')),'last_started_at':started,'last_status':'Running','last_error':None})
    uploaded=deleted=0; run_id=None
    try:
        if not cfg.get('enabled'): raise RuntimeError('Supabase synchronization is disabled')
        if not cfg.get('url') or not key: raise RuntimeError('Supabase URL or server secret key is missing')
        connection=sqlite3.connect(db_path,timeout=30); connection.row_factory=sqlite3.Row
        try:
            instance=_instance_id(connection)
            run_id=connection.execute("INSERT INTO supabase_sync_runs(status) VALUES('Running')").lastrowid; connection.commit()
            tables=_existing_tables(connection)
            pending=[]; state_updates=[]; current_keys=set()
            for table in BUSINESS_TABLES:
                if table not in tables: continue
                for row in connection.execute(f'SELECT * FROM "{table}"'):
                    payload={k:_json_value(row[k]) for k in row.keys()}; source_id=str(payload.get('id') if payload.get('id') is not None else hashlib.sha256(json.dumps(payload,sort_keys=True,default=str).encode()).hexdigest())
                    canonical=json.dumps(payload,sort_keys=True,separators=(',',':'),default=str); digest=hashlib.sha256(canonical.encode()).hexdigest(); current_keys.add((table,source_id))
                    old=connection.execute('SELECT payload_hash,active FROM supabase_sync_state WHERE source_table=? AND source_id=?',(table,source_id)).fetchone()
                    if not old or old['payload_hash']!=digest or not old['active']:
                        pending.append({'source_instance':instance,'source_table':table,'source_id':source_id,'payload':payload,'payload_hash':digest,'deleted_at':None,'synced_at':started})
                        state_updates.append((table,source_id,digest,1))
            for row in connection.execute('SELECT source_table,source_id FROM supabase_sync_state WHERE active=1'):
                key_tuple=(row['source_table'],row['source_id'])
                if key_tuple not in current_keys:
                    digest=hashlib.sha256(b'DELETED').hexdigest(); pending.append({'source_instance':instance,'source_table':row['source_table'],'source_id':row['source_id'],'payload':None,'payload_hash':digest,'deleted_at':started,'synced_at':started}); state_updates.append((row['source_table'],row['source_id'],digest,0)); deleted+=1
            batch_size=max(1,min(int(cfg.get('batch_size',100)),500))
            for offset in range(0,len(pending),batch_size): _post(cfg['url'],key,pending[offset:offset+batch_size])
            for table,source_id,digest,active in state_updates:
                connection.execute('INSERT INTO supabase_sync_state(source_table,source_id,payload_hash,active,synced_at) VALUES(?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(source_table,source_id) DO UPDATE SET payload_hash=excluded.payload_hash,active=excluded.active,synced_at=CURRENT_TIMESTAMP',(table,source_id,digest,active))
            uploaded=len(pending)-deleted; files_uploaded,files_verified,files_failed=_sync_invoice_files(connection,db_path,cfg['url'],key,instance); completed=datetime.now(timezone.utc).isoformat(); connection.execute("UPDATE supabase_sync_runs SET completed_at=CURRENT_TIMESTAMP,status='Completed',records_uploaded=?,records_deleted=? WHERE id=?",(uploaded,deleted,run_id)); connection.commit()
            STATUS.update({'connected':True,'last_completed_at':completed,'last_status':'Completed' if not files_failed else 'Completed with file warnings','records_uploaded':uploaded,'records_deleted':deleted,'files_uploaded':files_uploaded,'files_verified':files_verified,'files_failed':files_failed})
            return dict(STATUS)
        finally: connection.close()
    except (HTTPError,URLError,TimeoutError,sqlite3.Error,ValueError,RuntimeError) as exc:
        message=str(exc)
        try:
            if run_id:
                with sqlite3.connect(db_path) as log_db: log_db.execute("UPDATE supabase_sync_runs SET completed_at=CURRENT_TIMESTAMP,status='Failed',error=? WHERE id=?",(message[:1000],run_id))
        except sqlite3.Error: pass
        STATUS.update({'connected':False,'last_status':'Failed','last_error':message[:500]}); return dict(STATUS)
    finally:
        STATUS['running']=False; LOCK.release()

def trigger(): WAKE.set()
def status(): return dict(STATUS)

def reconcile(db_path,config):
    cfg=config.get('supabase',{}); key=_key()
    if not cfg.get('enabled') or not cfg.get('url') or not key:return {'status':'Unavailable','error':'Supabase connection is not configured'}
    connection=sqlite3.connect(db_path,timeout=30); connection.row_factory=sqlite3.Row
    try:
        instance=_instance_id(connection); encoded=quote(instance,safe=''); remote=_get_rows(cfg['url'],key,'iam_sync_records',f'source_instance=eq.{encoded}&deleted_at=is.null&select=source_table,source_id,payload_hash&limit=10000'); remote_files=_get_rows(cfg['url'],key,'iam_sync_files',f'source_instance=eq.{encoded}&select=entity_type,entity_id,sha256,status&limit=10000')
        local_map={(r['source_table'],r['source_id']):r['payload_hash'] for r in connection.execute('SELECT source_table,source_id,payload_hash FROM supabase_sync_state WHERE active=1')}; remote_map={(r['source_table'],r['source_id']):r['payload_hash'].strip() for r in remote}; local_file_map={(r['entity_type'],r['entity_id']):r['sha256'] for r in connection.execute("SELECT entity_type,entity_id,sha256 FROM supabase_file_sync_state WHERE status='Verified'")}; remote_file_map={(r['entity_type'],r['entity_id']):r['sha256'].strip() for r in remote_files if r.get('status')=='Verified'}
        local_keys=set(local_map); remote_keys=set(remote_map); common=local_keys&remote_keys; file_common=set(local_file_map)&set(remote_file_map); result={'checked_at':datetime.now(timezone.utc).isoformat(),'local_records':len(local_map),'remote_records':len(remote_map),'matched_records':sum(local_map[x]==remote_map[x] for x in common),'missing_remote':len(local_keys-remote_keys),'extra_remote':len(remote_keys-local_keys),'hash_mismatches':sum(local_map[x]!=remote_map[x] for x in common),'local_files':len(local_file_map),'remote_files':len(remote_file_map),'matched_files':sum(local_file_map[x]==remote_file_map[x] for x in file_common)}; result['status']='Matched' if result['missing_remote']==0 and result['extra_remote']==0 and result['hash_mismatches']==0 and result['local_files']==result['remote_files']==result['matched_files'] else 'Attention Required'
        connection.execute('INSERT INTO supabase_reconciliation_runs(local_records,remote_records,matched_records,missing_remote,extra_remote,hash_mismatches,local_files,remote_files,matched_files,status,details_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)',(result['local_records'],result['remote_records'],result['matched_records'],result['missing_remote'],result['extra_remote'],result['hash_mismatches'],result['local_files'],result['remote_files'],result['matched_files'],result['status'],json.dumps(result))); connection.commit(); STATUS['last_reconciliation']=result; return result
    except (HTTPError,URLError,TimeoutError,sqlite3.Error,ValueError) as exc:return {'status':'Failed','error':str(exc)[:500]}
    finally: connection.close()

def start_worker(db_path,config):
    cfg=config.get('supabase',{}); STATUS['enabled']=bool(cfg.get('enabled'))
    if not cfg.get('enabled'): return None
    interval=max(10,int(cfg.get('interval_seconds',30)))
    def work():
        while not STOP.is_set():
            result=sync_once(db_path,config)
            if result.get('connected'): reconcile(db_path,config)
            WAKE.wait(interval); WAKE.clear()
    thread=threading.Thread(target=work,name='supabase-mirror',daemon=True); thread.start(); return thread
