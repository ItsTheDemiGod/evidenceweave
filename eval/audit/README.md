# Blind manual audit

You are labelling 32 sentences from the EvidenceWeave evaluation. This is a single-labeller audit.

1. **Do NOT open `audit_key.csv` before you have finished labelling.** It reveals which sentences the verifier accepted.
2. Open `audit_items.csv` (Excel works; it is UTF-8 with BOM). Each row has a sentence and the log lines it cites.
3. Fill the `label` column with one of:
   - **S** - every factual claim in the sentence is shown by the listed log lines.
   - **P** - some claims are shown and some are not, or the sentence goes beyond the lines.
   - **U** - the claim is not shown, or it is contradicted, by the listed lines.
4. Judge ONLY by the listed log lines, not by outside knowledge. Ignore writing style.
5. Use `notes` freely. Save as CSV (keep the same file name and columns).
6. Score with: `python scripts/audit_score.py --labels eval/audit/audit_items.csv`
