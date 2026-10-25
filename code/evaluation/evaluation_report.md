# Evaluation report

## Public sample set

The solution was run against all 32 public requests and compared with `dataset/sample_output.csv`. Object-key ordering and JSON whitespace were ignored. A step was considered an exact match when its phase, system, resource, operation, state, and evidence ID all matched.

| Measure | Result |
| --- | ---: |
| Sample cases evaluated | 32 |
| Status accuracy | 32 / 32 (100%) |
| Exact ordered step sequences | 15 / 32 (46.9%) |
| Expected steps | 193 |
| Predicted steps | 165 |
| Exact step matches | 165 |
| Step precision | 100% |
| Step recall | 85.5% |
| Step F1 | 92.2% |
| Aligned field accuracy | 852 / 1,158 (73.6%) |

The sequence measure compares the complete ordered list of six-field step tuples. Aligned field accuracy compares each of those six fields at the same array position and counts a missing step as a mismatch.

## Full prediction file checks

The full run produced 518 rows in case ID order with 2,097 total steps: 132 `COMPLETE`, 353 `INCOMPLETE`, and 33 `NOT_APPLICABLE`. The CSV header and JSON array structure were checked; step numbers were consecutive, `COMPLETE` rows contained evidence-backed verification steps, and `NOT_APPLICABLE` rows had empty arrays. These are format and consistency checks, not a comparison to hidden answers.

## Additional behavior checks

Five hand-authored checks passed:

1. Spanish account-erasure wording is authorized.
2. A marketing-only unsubscribe is not treated as account deletion.
3. A record for `Mateo Rios Gil` does not match the shorter alias `Mateo Rios` when another identifier differs.
4. An HTTP 404 profile readback maps to `ABSENT`.
5. A tombstone may retain the stable `user_id` without treating it as direct PII.

Run these checks and the public sample comparison with:

```bash
python code/evaluation/main.py --expected dataset/sample_output.csv --predictions path/to/sample-predictions.csv
```

## Failures found and improvements made

- The first parser pass let the generic `service_exports` JSON container override the actual service category. Child paths now determine whether a row is a profile, backup, connector, security record, or export.
- The first identity matcher treated a shorter name as a match for a longer unrelated name. Structured names now require an exact normalized value; email, hash, phone, and user identifiers use stronger matching rules.
- The first log parser missed trace-level subject identifiers, 404 readbacks, and handover rows prefixed with a dash. It now propagates identity keys within a trace, recognizes HTTP 404 and zero-row results, and parses the handover format.
- Address-keyed contact lookups in the analytics service and legacy support contact index are handled as deletable secondary identifiers. Shared support conversations still follow the redaction policy.
- PDFs are parsed locally with `pypdf`. Screenshot transcription remains optional and was not used in the measured run because no API key was configured.

The remaining 28 missed sample steps mostly concern de-identified resource rows that have no direct subject key in the available evidence, plus a small number of resources that the deterministic parser cannot associate with a request. Status accuracy and exact sequence accuracy are separate measures; the 100% sample status result should not be read as perfect step-level reconstruction or as a guarantee on the hidden set.
