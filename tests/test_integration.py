import http.cookiejar, json, os, unittest, urllib.error, urllib.request, uuid

BASE=os.environ.get('IAM_TEST_URL','http://127.0.0.1:8080')

class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        jar=http.cookiejar.CookieJar(); cls.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar)); cls.csrf=''
        test_password=os.environ.get('IAM_TEST_PASSWORD')
        if not test_password: raise unittest.SkipTest('Set IAM_TEST_PASSWORD to run authenticated integration tests')
        data=cls.call('/api/login','POST',{'username':os.environ.get('IAM_TEST_USER','admin'),'password':test_password},csrf=False)
        cls.csrf=data['csrf_token']
    @classmethod
    def call(cls,path,method='GET',body=None,csrf=True,raw=False):
        headers={'Content-Type':'application/json'}
        if csrf and cls.csrf:headers['X-CSRF-Token']=cls.csrf
        req=urllib.request.Request(BASE+path,data=json.dumps(body).encode() if body is not None else None,method=method,headers=headers)
        resp=cls.opener.open(req,timeout=15)
        return (resp.read(),resp) if raw else json.loads(resp.read())
    def test_01_health_and_headers(self):
        raw,resp=self.call('/api/health',raw=True); self.assertEqual(json.loads(raw)['status'],'ok'); self.assertEqual(resp.headers['X-Frame-Options'],'DENY'); self.assertIn('Content-Security-Policy',resp.headers)
    def test_02_csrf_rejected(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:self.call('/api/admin/backup','POST',{},csrf=False)
        self.assertEqual(cm.exception.code,403)
    def test_03_persistent_authenticated_session(self):
        me=self.call('/api/me'); self.assertEqual(me['user']['username'],os.environ.get('IAM_TEST_USER','admin'))
    def test_04_cost_centre_budget_and_limit(self):
        suffix=uuid.uuid4().hex[:8].upper(); cc=self.call('/api/cost-centres','POST',{'code':'CC-'+suffix,'name':'Automated Test Cost Centre'}); budget=self.call('/api/budgets','POST',{'budget_code':'B-'+suffix,'cost_centre_id':cc['id'],'fiscal_year':'2026-27','allocated_amount':1000}); committed=self.call('/api/budget/commit','POST',{'budget_id':budget['id'],'amount':250,'transaction_type':'Commitment','reference_type':'Test','reference_id':1}); self.assertEqual(committed['available_after'],750)
        with self.assertRaises(urllib.error.HTTPError) as cm:self.call('/api/budget/commit','POST',{'budget_id':budget['id'],'amount':751,'transaction_type':'Commitment','reference_type':'Test','reference_id':2})
        self.assertEqual(cm.exception.code,409)
    def test_05_erp_export_ready(self):
        result=self.call('/api/erp/sync','POST',{'direction':'Export','entity_type':'Vendor'}); self.assertIn(result['status'],{'Export Ready','Completed'})
    def test_06_provider_configuration_is_explicit(self):
        invoices=self.call('/api/invoices')
        if invoices:
            with self.assertRaises(urllib.error.HTTPError) as cm:self.call('/api/ocr/process','POST',{'invoice_id':invoices[0]['id']})
            self.assertEqual(cm.exception.code,409)
        with self.assertRaises(urllib.error.HTTPError) as cm:self.call('/api/whatsapp/send','POST',{'recipient':'919000000000','message_text':'Integration test'})
        self.assertEqual(cm.exception.code,409)
    def test_07_verified_backup(self):
        result=self.call('/api/admin/backup','POST',{}); self.assertEqual(result['integrity_status'],'ok'); self.assertEqual(len(result['sha256']),64); self.assertGreater(result['size_bytes'],0)

if __name__=='__main__':unittest.main(verbosity=2)
