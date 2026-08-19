import os, shutil, sqlite3, sys, tempfile, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'backend'))
import supabase_sync

class SupabaseMirrorTests(unittest.TestCase):
    def test_initial_sync_and_change_detection(self):
        with tempfile.TemporaryDirectory() as folder:
            test_root=Path(folder)/'app'; (test_root/'database').mkdir(parents=True); target=test_root/'database'/'test.db'; shutil.copy2(ROOT/'database'/'inventory_audit.db',target)
            if (ROOT/'uploads').exists(): shutil.copytree(ROOT/'uploads',test_root/'uploads')
            connection=sqlite3.connect(target)
            try:
                connection.executescript((ROOT/'database'/'migrations'/'007_supabase_sync.sql').read_text())
                connection.executescript((ROOT/'database'/'migrations'/'008_supabase_storage_reconciliation.sql').read_text())
                connection.execute('DELETE FROM supabase_sync_state'); connection.execute('DELETE FROM supabase_sync_runs'); connection.execute('DELETE FROM supabase_file_sync_state'); connection.commit()
            finally: connection.close()
            batches=[]; objects={}; original_post=supabase_sync._post; original_key=supabase_sync._key; original_upload=supabase_sync._upload_file; original_download=supabase_sync._download_file; original_upsert=supabase_sync._upsert
            supabase_sync._post=lambda url,key,records:batches.extend(records)
            supabase_sync._key=lambda:'test_backend_key'
            supabase_sync._upload_file=lambda url,key,bucket,path,raw,mime:objects.__setitem__((bucket,path),raw)
            supabase_sync._download_file=lambda url,key,bucket,path:objects[(bucket,path)]
            supabase_sync._upsert=lambda *args,**kwargs:None
            try:
                config={'supabase':{'enabled':True,'url':'https://example.supabase.co','batch_size':25}}
                first=supabase_sync.sync_once(target,config)
                self.assertEqual(first['last_status'],'Completed'); self.assertGreater(first['records_uploaded'],0)
                self.assertTrue(all(r['source_table'] not in {'users','persistent_sessions','approval_link_tokens'} for r in batches))
                batches.clear(); second=supabase_sync.sync_once(target,config)
                self.assertEqual(second['records_uploaded'],0); self.assertEqual(batches,[])
                connection=sqlite3.connect(target)
                try: connection.execute("UPDATE observations SET title='Changed by test' WHERE id=(SELECT MIN(id) FROM observations)"); connection.commit()
                finally: connection.close()
                third=supabase_sync.sync_once(target,config)
                self.assertEqual(third['records_uploaded'],1); self.assertEqual(len(batches),1)
            finally:
                supabase_sync._post=original_post; supabase_sync._key=original_key; supabase_sync._upload_file=original_upload; supabase_sync._download_file=original_download; supabase_sync._upsert=original_upsert

if __name__=='__main__': unittest.main()
