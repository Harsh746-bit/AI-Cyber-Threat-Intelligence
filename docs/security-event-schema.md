
# SENTRIX Security Event Schema — Version 1

## Purpose
Define a common event contract for network-flow ingestion,
ML detection, incident storage, and dashboard presentation.

## Event fields

| Field | Type | Required | Description |
|---|---|---|---|
| event_id | UUID string | Yes | Unique event identifier |
| schema_version | String | Yes | Schema version, initially 1.0 |
| event_type | String | Yes | NETWORK_FLOW |
| observed_at | UTC timestamp or null | No | Actual observation time, if available |
| source_ip | IP address or null | No | Source IP supplied by a collector |
| destination_ip | IP address or null | No | Destination IP supplied by a collector |
| source_port | Integer or null | No | Source port, when available |
| destination_port | Integer or null | No | Valid destination port, when available |
| protocol | String or integer or null | No | Protocol, when available |
| features | Object | Yes for ML inference | Validated network-flow feature values |
| dataset_label | String or null | Offline evaluation only | Ground-truth dataset label |
| predicted_label | String or null | No | Model prediction |
| confidence | Number or null | No | Model confidence, when supported |
| risk_score | Number or null | No | Platform risk score, calculated separately |
| incident_status | String | Yes | OPEN, INVESTIGATING, or RESOLVED |

## Data rules

1. Never use dataset_label as a model input.
2. Keep ground-truth labels separate from predictions.
3. Reject or explicitly handle invalid feature values.
4. Convert positive and negative infinity to missing values
   during preprocessing.
5. Fit imputers and scalers on training data only.
6. Do not invent IP addresses, timestamps, or protocol values.
7. Validate ports and timestamps before accepting them.
8. Keep dataset-only fields out of production inference unless
   explicitly permitted by the production contract.
9. Calculate risk_score separately from model confidence.
10. Version future schema changes explicitly.

## CIC-IDS2017 mapping

- Destination Port -> destination_port metadata and model feature
- Remaining validated feature columns -> features
- Label -> dataset_label only
- Source IP -> unavailable in the audited CSV columns
- Destination IP -> unavailable in the audited CSV columns
- Protocol -> unavailable in the audited CSV columns
- Observation timestamp -> unavailable in the audited CSV columns

The CSV schema must be inspected and validated before ingestion.
