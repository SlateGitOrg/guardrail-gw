## Evaluation on the heldout split

### Detectors

1500 samples, 2563 gold spans.

| category (overlap match) | TP | FP | FN | precision | recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| pii | 1291 | 0 | 1 | 1.000 | 0.999 | 1.000 |
| secret | 1271 | 5 | 0 | 0.996 | 1.000 | 0.998 |

| kind (exact span + kind) | TP | FP | FN | precision | recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| email | 319 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| phone | 214 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| credit_card | 105 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| iban | 206 | 0 | 1 | 1.000 | 0.995 | 0.998 |
| us_ssn | 114 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| in_aadhaar | 105 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| es_dni | 129 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| cn_ric | 99 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| aws_access_key | 133 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| github_token | 0 | 121 | 121 | 0.000 | 0.000 | 0.000 |
| slack_token | 136 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| stripe_key | 109 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| google_api_key | 129 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| llm_api_key | 103 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| jwt | 102 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| private_key | 107 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| credential_assignment | 113 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| high_entropy_token | 218 | 5 | 0 | 0.978 | 1.000 | 0.989 |

### Injection scorer

| samples | threshold | TP | FP | FN | TN | precision | recall | F1 | ROC-AUC |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 600 | 0.70 | 203 | 0 | 23 | 374 | 1.000 | 0.898 | 0.946 | 0.990 |

