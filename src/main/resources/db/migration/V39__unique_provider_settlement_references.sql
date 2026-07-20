-- M-12: invoice and approval references are mandatory audit identities and
-- must remain unique alongside claim_id and payment_ref.

ALTER TABLE provider_invoice_records
    ADD UNIQUE KEY uq_pir_invoice_ref (invoice_ref);

ALTER TABLE provider_approvals
    ADD UNIQUE KEY uq_pa_approval_ref (approval_ref);
