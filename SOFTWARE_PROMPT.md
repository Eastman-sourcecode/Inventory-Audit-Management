# Software Build Prompt — GRN, Inventory and Inventory Audit Management

Build a secure, database-backed, browser-based facility management module integrated with the existing Inventory Audit Management application. Use the exact term **Inventory Audit Observation** throughout.

The workflow must support both **PO material inward** and **Non-PO material inward**:

1. Import Purchase Orders using a standard CSV format with PO header and material-line data. Required columns: `po_number`, `po_date`, `vendor_code`, `vendor_name`, `department`, `currency`, `line_number`, `material_code`, `material_description`, `ordered_qty`, `unit`, `unit_price`, and `tax_rate`. Preserve imported source, line numbers, received quantity, balance quantity, and audit history.
2. Upload invoices in PDF, image, TXT, or CSV form. Store the original document safely, extract text where supported, and map invoice number, invoice date, PO number, vendor, taxable amount, tax, and grand total into editable fields. Mark image-only documents for OCR-provider processing or manual review. Never silently treat uncertain OCR values as verified.
3. Match invoices, Purchase Orders, GRNs, and material lines. Flag quantity, rate, tax, duplicate-invoice, vendor, and amount variances.
4. Create GRNs for PO receipts. Record warehouse, receipt date, material, ordered/received/accepted/rejected quantity, unit, batch, expiry date, unit cost, and inspection result. Update inventory only with accepted quantity and retain an immutable inventory movement.
5. For Non-PO receipts, require a request containing department, requester, vendor, amount, business justification, invoice, and approver. Do not permit a Non-PO GRN until a Manager or Admin approves it. Record approval/rejection, date, note, and approver. Provide integration-ready email request and reminder events.
6. Perform receipt inspection and inventory audit at GRN time. If rejected quantity is greater than zero or inspection fails, automatically create and link an **Inventory Audit Observation**. Allow escalation to Incident and CAPA workflows.
7. Provide searchable screens and dashboards for Purchase Orders, invoices/OCR, pending Non-PO approvals, GRNs, current inventory, inventory movements, linked Inventory Audit Observations, incidents, CAPAs, and audit trail.
8. Allow authorized users to share PO, invoice, GRN, Non-PO approval request, and Inventory Audit Observation records by email or WhatsApp. Persist a share log even when external providers are not configured.
9. Enforce RBAC for Admin, Manager, Auditor, and Viewer. Use secure password hashing, server-side sessions, file type/size validation, safe filenames, immutable business audit entries, and a real relational database.
10. Deliver migrations, seed data, a standard PO import template, Windows setup instructions, integration configuration, test cases, and clear labeling of real versus placeholder integrations.

Acceptance criteria: a user can import a PO, upload/read an invoice, create a PO GRN, update stock, submit and approve a Non-PO request, create a Non-PO GRN only after approval, automatically raise an Inventory Audit Observation for rejected material, and trace every action through the audit trail.

Add configurable industry profiles for Manufacturing, Pharmaceutical, Food, Construction, Hospital, and Retail. At GRN submission, execute enabled rules for PO/non-PO applicability and record pass/gap results for quantity tolerance, price tolerance, invoice presence, approval, batch/serial/lot traceability, expiry/shelf life, and rejected quantity. Summarize material gaps in a linked Inventory Audit Observation and expose the detailed expected value, actual value, variance, severity, category, and resolution status on a GRN Gap Analysis screen.
