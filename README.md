# Inventory Audit Management — Phase 1

A practical local MVP for managing **Inventory Audit Observations** through incident, CAPA, ownership transfer, escalation, sharing, reporting, and audit-trail workflows.

## Runtime

- Project path: `C:\SOFTWARE\Inventory_Audit_Management`
- Application URL: `http://127.0.0.1:8080`
- Health URL: `http://127.0.0.1:8080/api/health`
- Database: `C:\SOFTWARE\Inventory_Audit_Management\database\inventory_audit.db` (SQLite)

## First login

- Username: `admin`
- Password: set `IAM_INITIAL_ADMIN_PASSWORD` before the first run, or use the generated password displayed once in the server window.

The administrator must change the initial password after first sign-in. Existing installations retain their current password. This application binds to localhost by default.

## Windows setup and run

1. Open PowerShell.
2. Run: `cd C:\SOFTWARE\Inventory_Audit_Management`
3. Optional: copy `config\app.example.json` to `config\app.json` and adjust settings.
4. Run: `.\start.ps1`
5. Open `http://127.0.0.1:8080`.

## Mobile invoice camera

Open **Invoice & OCR → + New → Take invoice photo with mobile camera**. The control requests the rear camera, previews the captured invoice, and uploads it with the same 10 MB limit as other invoices. The default server is intentionally localhost-only. To use it from a separate phone, an administrator must deliberately bind the service to the facility LAN and configure Windows Firewall, a trusted HTTPS address, authentication policy, and device-network access; do not expose the development server directly to the internet.

Python 3.10+ is required. In Codex Desktop the launcher also recognizes its bundled Python runtime. No third-party packages are required.

## Included

- Secure PBKDF2 password hashing, server-side sessions, RBAC roles (Admin, Auditor, Manager, Viewer)
- Dashboard KPIs
- Inventory Audit Observation register and creation
- Linked Incident and CAPA records
- Ownership transfers, sharing log, and escalations
- Dynamic master data
- Downloadable CSV report
- Persistent SQLite database, migration, seed admin, and sample workflow data
- Append-only application audit trail for login and business actions
- Purchase Order CSV import using `templates\po_import_template.csv`
- PO and approved Non-PO GRN workflows
- Inventory balances, average cost, and immutable receipt movements
- Invoice document upload with local text extraction for text PDFs/TXT/CSV
- Non-PO departmental request and Manager/Admin approval controls
- Automatic Inventory Audit Observation creation for rejected or failed GRN inspection
- Configurable GRN compliance and gap-analysis engine
- Manufacturing, Pharmaceutical, Food, Construction, Hospital, and Retail profiles
- Quantity, price, document, approval, traceability, shelf-life, and quality gap recording
- Admin-only Vendor Master with add, edit, recoverable delete, CSV import/update, and audit logging
- Vendor upload template at `templates\vendor_master_template.csv`
- Complete Records traceability view joining vendor, PO/Non-PO, invoice, GRN, inventory, gaps, observation, incident, CAPA, escalation and sharing
- User Administration with roles, temporary-password reset, forced change and self-service password change
- Configurable multi-step approval workflows, approval inbox and 48-hour approval links
- Audited transaction status controls from Draft through Submitted, Review, Approval and Closure
- Duplicate invoice detection by SHA-256/document identity and invoice/vendor match
- Duplicate vendor blocking by legal name or tax identifier
- Authenticated invoice view/download with a document-access log
- SMTP delivery adapter and auditable notification outbox

The reusable build specification is in `SOFTWARE_PROMPT.md`.

## Integration placeholders

Email and approval notifications have an SMTP delivery adapter plus durable outbox/audit records; they send when SMTP is enabled and remain local placeholders when it is disabled. WhatsApp delivery remains integration-ready only. Image-only invoice OCR is also provider-ready; text-based PDF extraction works locally, while image scans are retained with `Image OCR Engine Required` status for external OCR or manual review.

SMTP delivery is implemented. Copy `config\app.example.json` to `config\app.json`, provide the SMTP host, port, sender and credentials, and set `smtp.enabled` to `true`. Without credentials, approval messages remain in Notification Outbox with `Placeholder` status. Keep secrets outside source control for production.

## Image OCR

The Invoice & OCR screen has a real provider execution action. Configure either:

- `azure-document-intelligence`: endpoint, subscription key, model and API version; or
- `generic-webhook`: an HTTPS endpoint returning `{text, confidence, fields}`.

Set `ocr.enabled` to `true`. OCR requests, confidence, extracted fields and failures are retained in OCR Jobs. No local OCR engine is bundled, and the software reports `Configuration Required` until a real provider is configured.

## WhatsApp

Configure the Meta WhatsApp Cloud API `token`, `phone_number_id` and API version, then set `whatsapp.enabled` to `true`. Messages use the real Graph API and retain the provider message ID and response. Without credentials, requests report `Configuration Required` and are not represented as sent.

## Budgets, cost centres and ERP

Admins can create cost centres and fiscal-year budgets. Commitments and consumption are blocked when they exceed the available amount. ERP Integration exports Vendor, Purchase Order, GRN, Inventory or Budget records. Configure an authenticated ERP HTTPS endpoint to transmit payloads; otherwise the full export is retained locally with `Export Ready` status.

## Production security and HTTPS

- Persistent database-backed sessions with expiry
- CSRF tokens on all mutations
- Login rate limiting and Security Events
- HttpOnly, SameSite cookies; Secure cookie when HTTPS is enabled
- CSP, frame-denial, referrer and MIME-sniffing headers
- TLS 1.2 minimum when `https.enabled` is true

Provide certificate and key files at the configured paths before enabling HTTPS. For a production network deployment, place the application behind a maintained reverse proxy/WAF, restrict firewall access and use organization-issued certificates.

## Backups and tests

Create backups from **Database Backups**, or run `scripts\backup_database.py`. Every backup receives an integrity check and SHA-256 manifest. `scripts\install_daily_backup_task.ps1` installs a Windows daily task at 02:00 and should be run by an authorized administrator.

Run the automated suite while the server is active:

`python tests\test_integration.py`

The suite validates security headers, CSRF rejection, persistent sessions, budget enforcement, ERP export behavior, provider-configuration handling and verified backups.

## Production notes

The built-in HTTP server is intended for local development/UAT. Before internet exposure, add TLS through a production reverse proxy, persistent session storage, CSRF protection, provider adapters, encrypted secret storage, backups, automated tests, and an admin password-change workflow.

## Supabase connection

The Supabase project **Inventory Audit Management** is provisioned in Mumbai with project ID `txfjxjaeurszfxyjiqjd`. The PostgreSQL core schema is in `database\supabase\001_inventory_audit_management.sql`; all 17 IAM tables have Row Level Security enabled.

The local application uses a secure server-side mirror connection and continues to use SQLite until data synchronization is explicitly enabled. Never put a Supabase service-role key in frontend files. To activate the server connection, copy `config\app.example.json` to `config\app.json`, set `supabase.enabled` to `true`, and set the key only in the server process:

`$env:IAM_SUPABASE_SECRET_KEY = 'your-sb_secret-key'`

Restart the server, then open `http://127.0.0.1:8080/api/health`. The `supabase.connected` value will be `true` when the private key and project URL are valid. `connect_supabase.ps1` stores a Windows DPAPI-encrypted, current-user-only copy at `config\supabase-key.dpapi`; `start.ps1` loads it automatically. For a managed production deployment, use Windows Credential Manager or an enterprise secret store.

### Automatic secure mirror

When Supabase is enabled and the server secret is valid, the application automatically mirrors business records every 30 seconds. The first run uploads the complete business dataset; later runs upload only changed records. Removed local records are retained in Supabase with a deletion timestamp for auditability.

Passwords, login sessions and approval-link tokens are deliberately excluded. The mirror is stored in `public.iam_sync_records`, protected by Row Level Security and accessible only to the server role. Administrators can inspect local synchronization history at `/api/supabase-sync` after signing in or request an immediate run with `POST /api/supabase-sync-now` using the normal CSRF header.

The local SQLite database remains the operational primary database in `secure-mirror` mode. Supabase is the durable off-machine mirror and integration source; it does not replace the local database transaction engine in this phase.

### Private document storage and reconciliation

Invoice PDFs, images and other uploaded invoice files are copied to the private `iam-private-documents` Supabase Storage bucket. Each changed file is downloaded by the backend after upload and its SHA-256 is compared with the local file before it is marked `Verified`. Metadata is retained in `public.iam_sync_files`; anonymous and ordinary authenticated access are blocked.

Administrators can open **Administration > Supabase Cloud** to view connection health, record and file counts, the retry queue, recent synchronization runs and reconciliation results. **Sync Now** requests an immediate retry. **Verify & Reconcile** compares local and cloud record IDs and hashes and reports missing, extra or mismatched content.
