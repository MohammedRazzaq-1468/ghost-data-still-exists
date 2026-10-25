# Optional screenshot extraction prompt

The default run uses deterministic parsing and does not call a hosted model. When `--vision` is enabled, the solution sends each evidence screenshot to the configured OpenAI model with this extraction-only instruction:

> Transcribe records visible in this business screenshot into JSON only: `{"records":[{"system_id":string,"resource_id":string,"category":string,"state":string,"observed_at":string|null,"subject_reference":string|null,"name":string|null,"email":string|null,"phone":string|null,"email_hash":string|null,"note":string|null}]}`. Include selected panels and table rows only when their record IDs are legible. Do not infer deletion status or propose operations. Use null for unreadable fields.

Model recommendation for optional image extraction: `gpt-6.1-sol`, with `gpt-6-astra` as a fallback for screenshots that remain ambiguous after a first extraction. The model only transcribes visible values; identity matching, point-in-time filtering, policy handling, status decisions, remediation planning, and CSV serialization remain deterministic.
