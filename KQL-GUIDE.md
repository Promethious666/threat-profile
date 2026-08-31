# KQL Review and Deployment Guide

The workbench includes ten KQL hunting starters for Microsoft Sentinel and Microsoft Defender XDR. Each query is mapped to ATT&CK and contains the operational context an analyst needs to assess it.

## What “schema reviewed” means

For every query, the repository records:

- target Microsoft product and required data source;
- tables and expected output fields;
- the Microsoft Learn schema or feature pages used for review;
- the date of the schema review;
- lookback period and near-real-time limitations;
- likely false positives, tuning suggestions and validation steps.

Automated tests enforce the presence of this metadata and verify important schema literals, including:

- `SigninLogs.ResultType == "0"` for a successful Entra sign-in;
- `DeviceLogonEvents.LogonType == "RemoteInteractive"` for Remote Desktop logons;
- `DeviceNetworkEvents.ActionType == "ConnectionSuccess"` for successful network connections.

The official documentation links live beside each query in the interface and in `pages-src/detections.js`.

## What it does not mean

Schema review is not tenant certification. Microsoft licensing, connectors, retention, streaming availability, action-type values, enrichment coverage and custom-detection requirements can differ. Aggregated hunts may intentionally omit identifiers required by scheduled custom detections.

The catalogue therefore uses the status **Schema reviewed · Tenant validation required**. No query is labelled production-ready by default.

## Safe promotion checklist

1. Confirm the prerequisite product, connector and table contain recent data.
2. Run the query over a short lookback and inspect a small result sample.
3. Compare representative events with the relevant Microsoft entity or investigation page.
4. Review the tenant's actual enum values and nullable fields.
5. Identify authorised simulations, scanners, VPNs, automation and administrator workflows.
6. Tune exclusions narrowly and document their owner and review date.
7. Measure result volume over a representative period.
8. If promoting to a scheduled analytic or custom detection, preserve the identifiers and timestamp required by that product.
9. Test a known-positive scenario where it is safe to do so.
10. Assign an operational owner, severity rationale, response steps and a future review date.

## Catalogue scope

The current starters cover delivered QR-code phishing, Safe Links click-throughs, risky Entra sign-ins, password spraying, cloud administration anomalies, suspicious Office child processes, public-source RDP, rare outbound interpreter traffic, startup-folder persistence and Controlled Folder Access events.

Queries should stay transparent and reviewable. If a future change cannot be supported by an official Microsoft schema or feature document, record the limitation plainly rather than silently guessing a field.
