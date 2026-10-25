# Model token and cost report

## Final full-dataset run

The run used the deterministic local parser and policy pipeline in `code/main.py` on all 518 rows from `dataset/deletion_requests.csv`. Screenshot vision mode was off. No hosted model provider was called.

| Provider / model | Calls | Input tokens | Output tokens | Total tokens | Estimated cost |
| --- | ---: | ---: | ---: | ---: | ---: |
| OpenAI / `gpt-6.1-sol` (recommended, not invoked) | 0 | 0 | 0 | 0 | $0.00 |
| Local deterministic pipeline / no model | 0 | 0 | 0 | 0 | $0.00 |
| **Overall** | **0** | **0** | **0** | **0** | **$0.00** |

| Average per request | Value |
| --- | ---: |
| Input tokens | 0 |
| Output tokens | 0 |
| Total tokens | 0 |
| Estimated cost | $0.00 |

The full output contains 518 request rows. The recommended optional model for screenshot transcription is OpenAI `gpt-6.1-sol`. It was not used for the reported output because no API key was configured, so no model tokens or model charges are included. The code accepts another vision-capable model with `--model` and records API-reported input and output tokens when `--vision` is enabled.
