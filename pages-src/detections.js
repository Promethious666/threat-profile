export const DETECTIONS = [
  {
    id: "delivered-qr-phish",
    title: "Delivered QR-code phishing",
    techniqueIds: ["T1566.002"],
    type: "Hunting starter",
    status: "Schema reviewed · Tenant validation required",
    purpose: "Find inbound messages classified as phishing that reached a mailbox and contain a URL extracted from a QR code.",
    targetProduct: "Microsoft Defender XDR Advanced Hunting",
    prerequisites: ["Microsoft Defender for Office 365", "EmailEvents and EmailUrlInfo retention for the selected lookback"],
    tables: ["EmailEvents", "EmailUrlInfo"],
    schemaVerifiedAt: "2026-08-30",
    lookback: "7 days",
    nrtCompatibility: "Not suitable for near-real-time custom detections because latest-delivery fields are not available through the Streaming API.",
    expectedFields: ["Timestamp", "NetworkMessageId", "RecipientEmailAddress", "Subject", "Url", "UrlDomain"],
    falsePositives: ["Authorised phishing simulations", "Messages with an incorrect upstream verdict"],
    tuning: ["Exclude approved simulation senders and domains", "Prioritise high-value recipients", "Review delivery and remediation state before escalation"],
    validationSteps: ["Confirm both tables contain recent records", "Run with a 24-hour lookback first", "Review a small sample against the Defender email entity page", "Tune exclusions before considering a custom detection"],
    documentationLinks: [
      { label: "EmailEvents schema", url: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table" },
      { label: "EmailUrlInfo schema", url: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailurlinfo-table" },
      { label: "Custom detection requirements", url: "https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules" },
    ],
    kql: `let LatestPhish =
    EmailEvents
    | where Timestamp > ago(7d)
    | summarize arg_max(Timestamp, *) by NetworkMessageId, RecipientEmailAddress
    | where EmailDirection == "Inbound"
    | where ThreatTypes has "Phish"
    | extend CurrentDeliveryLocation =
        iff(isnotempty(LatestDeliveryLocation), LatestDeliveryLocation, DeliveryLocation)
    | where CurrentDeliveryLocation == "Inbox/Folder"
    | project EmailTimestamp=Timestamp, EmailReportId=ReportId,
        NetworkMessageId, RecipientEmailAddress, SenderFromAddress,
        Subject, ThreatTypes, DeliveryAction, LatestDeliveryAction,
        CurrentDeliveryLocation;
EmailUrlInfo
| where Timestamp > ago(7d)
| where UrlLocation == "QRCode"
| project NetworkMessageId, Url, UrlDomain
| join kind=inner (LatestPhish) on NetworkMessageId
| project Timestamp=EmailTimestamp, EmailReportId, NetworkMessageId,
    RecipientEmailAddress, SenderFromAddress, Subject, ThreatTypes,
    DeliveryAction, LatestDeliveryAction, CurrentDeliveryLocation,
    Url, UrlDomain`,
  },
  {
    id: "safe-links-click-through",
    title: "Malicious Safe Links click-through",
    techniqueIds: ["T1204.001", "T1566.002"],
    type: "Hunting starter",
    status: "Schema reviewed · Tenant validation required",
    purpose: "Identify allowed or deliberately continued clicks where Safe Links recorded a phishing or malware verdict.",
    targetProduct: "Microsoft Defender XDR Advanced Hunting",
    prerequisites: ["Microsoft Defender for Office 365", "Safe Links protection for the relevant workload"],
    tables: ["UrlClickEvents"],
    schemaVerifiedAt: "2026-08-30",
    lookback: "7 days",
    nrtCompatibility: "Review Streaming API column support before promotion to a near-real-time detection.",
    expectedFields: ["Timestamp", "AccountUpn", "Url", "ActionType", "ThreatTypes", "NetworkMessageId"],
    falsePositives: ["Authorised phishing simulations", "False-positive URL verdicts", "Clicks made during security investigation"],
    tuning: ["Exclude approved simulation infrastructure", "Prioritise ClickAllowed and explicit click-through events", "Correlate with email and identity activity before declaring compromise"],
    validationSteps: ["Confirm Safe Links events are present", "Review ActionType values in the tenant", "Validate known simulation traffic", "Tune exclusions before scheduling"],
    documentationLinks: [
      { label: "UrlClickEvents schema", url: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table" },
      { label: "Advanced hunting best practices", url: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-best-practices" },
    ],
    kql: `UrlClickEvents
| where Timestamp > ago(7d)
| where ThreatTypes has_any ("Phish", "Malware")
| where ActionType == "ClickAllowed" or IsClickedThrough == true
| project Timestamp, ReportId, AccountUpn, Url, ActionType,
    IsClickedThrough, ThreatTypes, DetectionMethods, Workload,
    IPAddress, NetworkMessageId`,
  },
  {
    id: "risky-interactive-signin",
    title: "Successful medium or high-risk interactive sign-ins",
    techniqueIds: ["T1078.004"],
    type: "Hunting starter",
    status: "Schema reviewed · Tenant validation required",
    purpose: "Surface successful interactive Entra sign-ins carrying medium or high risk for identity investigation.",
    targetProduct: "Microsoft Sentinel / Log Analytics",
    prerequisites: ["Microsoft Entra sign-in logs streamed to Log Analytics", "Entra ID P2 for visible Identity Protection risk detail"],
    tables: ["SigninLogs"],
    schemaVerifiedAt: "2026-08-30",
    lookback: "7 days",
    nrtCompatibility: "Suitable for scheduled analytics after tenant field and threshold validation.",
    expectedFields: ["TimeGenerated", "UserPrincipalName", "IPAddress", "AppDisplayName", "RiskLevelDuringSignIn", "CorrelationId"],
    falsePositives: ["Legitimate travel", "Corporate VPN egress", "New managed devices", "Risk fields hidden by licensing"],
    tuning: ["Exclude trusted named locations", "Prioritise privileged users", "Use device and Conditional Access state", "Separate interactive from non-interactive sign-ins"],
    validationSteps: ["Confirm ResultType is populated as a string", "Check risk-field visibility", "Compare results with Entra sign-in details", "Tune trusted networks and user scope"],
    documentationLinks: [
      { label: "SigninLogs schema", url: "https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs" },
      { label: "Send Entra logs to Azure Monitor", url: "https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-integrate-activity-logs-with-azure-monitor-logs" },
    ],
    kql: `SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == "0"
| where RiskLevelDuringSignIn in~ ("medium", "high")
    or RiskLevelAggregated in~ ("medium", "high")
| project TimeGenerated, UserPrincipalName, UserId, IPAddress,
    Location, AppDisplayName, ClientAppUsed, IsInteractive,
    ConditionalAccessStatus, RiskLevelDuringSignIn,
    RiskLevelAggregated, RiskEventTypes_V2, DeviceDetail,
    CorrelationId`,
  },
  {
    id: "password-spray-candidate",
    title: "NTLM or Kerberos password-spray candidate",
    techniqueIds: ["T1110.003"],
    type: "Hunting starter",
    status: "Schema reviewed · Tenant validation required",
    purpose: "Find one source generating repeated failed NTLM or Kerberos logons across several accounts in a short window.",
    targetProduct: "Microsoft Defender XDR Advanced Hunting",
    prerequisites: ["Microsoft Defender for Identity for on-premises identity visibility"],
    tables: ["IdentityLogonEvents"],
    schemaVerifiedAt: "2026-08-30",
    lookback: "1 hour",
    nrtCompatibility: "Aggregation removes event identifiers; keep as a hunt until redesigned for custom-detection requirements.",
    expectedFields: ["IPAddress", "Protocol", "Attempts", "DistinctAccounts", "FirstSeen", "LastSeen"],
    falsePositives: ["NAT gateways", "Vulnerability scanners", "Stale services", "Expired service-account credentials"],
    tuning: ["Exclude known scanners and identity infrastructure", "Adjust attempt and account thresholds", "Separate service accounts", "Review source subnet ownership"],
    validationSteps: ["Confirm Defender for Identity events are present", "Inspect common ActionType and Protocol values", "Run against one known benign failure burst", "Tune thresholds by network zone"],
    documentationLinks: [
      { label: "IdentityLogonEvents schema", url: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitylogonevents-table" },
      { label: "Advanced hunting best practices", url: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-best-practices" },
    ],
    kql: `IdentityLogonEvents
| where Timestamp > ago(1h)
| where ActionType == "LogonFailed"
| where Protocol in~ ("NTLM", "Kerberos")
| where isnotempty(IPAddress)
| extend AccountKey =
    iff(isnotempty(AccountSid), AccountSid,
        iff(isnotempty(AccountUpn), AccountUpn,
            strcat(AccountDomain, "/", AccountName)))
| summarize Attempts=count(),
    DistinctAccounts=dcount(AccountKey),
    Accounts=make_set(AccountKey, 20),
    FirstSeen=min(Timestamp),
    LastSeen=max(Timestamp)
    by IPAddress, Protocol, WindowStart=bin(Timestamp, 15m)
| where Attempts >= 20 and DistinctAccounts >= 5`,
  },
  {
    id: "cloud-admin-anomaly",
    title: "Anomalous cloud administrator activity",
    techniqueIds: ["T1078.004"],
    type: "Hunting starter",
    status: "Schema reviewed · Tenant validation required",
    purpose: "Prioritise administrative cloud activity involving an anonymous proxy or behaviour marked uncommon for the account.",
    targetProduct: "Microsoft Defender XDR Advanced Hunting",
    prerequisites: ["Microsoft Defender for Cloud Apps", "Relevant application connectors and Microsoft 365 activity collection"],
    tables: ["CloudAppEvents"],
    schemaVerifiedAt: "2026-08-30",
    lookback: "24 hours",
    nrtCompatibility: "Validate connector latency and enrichment fields before considering a scheduled custom detection.",
    expectedFields: ["Timestamp", "AccountDisplayName", "Application", "ActionType", "IPAddress", "UncommonForUser"],
    falsePositives: ["Approved VPN or privacy services", "Third-party administrators", "First-time legitimate actions"],
    tuning: ["Scope high-impact actions", "Exclude approved administration IPs", "Separate service accounts", "Review application context"],
    validationSteps: ["Confirm connected applications populate CloudAppEvents", "Inspect UncommonForUser format", "Review known administrative changes", "Define high-impact ActionType values"],
    documentationLinks: [
      { label: "CloudAppEvents schema", url: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table" },
    ],
    kql: `CloudAppEvents
| where Timestamp > ago(24h)
| where IsAdminOperation == true
| where IsAnonymousProxy == true
    or tostring(UncommonForUser) !in ("", "[]")
| project Timestamp, ReportId, AccountId, AccountObjectId,
    AccountDisplayName, Application, ActionType, ActivityType,
    IPAddress, CountryCode, City, IsAnonymousProxy,
    UncommonForUser, LastSeenForUser, ObjectName, ObjectType`,
  },
  {
    id: "office-child-process",
    title: "Office application spawning an interpreter or LOLBin",
    techniqueIds: ["T1204.002", "T1059"],
    type: "Hunting starter",
    status: "Schema reviewed · Tenant validation required",
    purpose: "Find Office applications starting command interpreters or common living-off-the-land binaries.",
    targetProduct: "Microsoft Defender XDR Advanced Hunting",
    prerequisites: ["Microsoft Defender for Endpoint"],
    tables: ["DeviceProcessEvents"],
    schemaVerifiedAt: "2026-08-30",
    lookback: "7 days",
    nrtCompatibility: "Can be adapted to a custom detection after preserving required identifiers and tuning benign parent-child combinations.",
    expectedFields: ["Timestamp", "DeviceId", "DeviceName", "FileName", "ProcessCommandLine", "InitiatingProcessFileName"],
    falsePositives: ["Legitimate macros and add-ins", "Document-management software", "Administrator workflows"],
    tuning: ["Baseline expected parent-child pairs", "Exclude managed add-ins", "Prioritise encoded or downloaded content in a separate tuned analytic"],
    validationSteps: ["Confirm process telemetry coverage", "Review known Office automation", "Inspect command-line completeness", "Tune application-specific exclusions"],
    documentationLinks: [
      { label: "DeviceProcessEvents schema", url: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table" },
      { label: "Custom detection requirements", url: "https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules" },
    ],
    kql: `let OfficeParents = dynamic([
    "winword.exe", "excel.exe", "powerpnt.exe",
    "outlook.exe", "msaccess.exe", "visio.exe"
]);
let SuspiciousChildren = dynamic([
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"
]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (OfficeParents)
| where FileName in~ (SuspiciousChildren)
| project Timestamp, ReportId, DeviceId, DeviceName,
    AccountName, AccountUpn, FileName, FolderPath, SHA1,
    ProcessCommandLine, InitiatingProcessFileName,
    InitiatingProcessCommandLine, InitiatingProcessSHA1`,
  },
  {
    id: "public-rdp-local-admin",
    title: "Public-source RDP involving a local administrator",
    techniqueIds: ["T1021.001"],
    type: "Hunting starter",
    status: "Schema reviewed · Tenant validation required",
    purpose: "Review successful and failed public-source Remote Desktop logons involving accounts identified as local administrators.",
    targetProduct: "Microsoft Defender XDR Advanced Hunting",
    prerequisites: ["Microsoft Defender for Endpoint"],
    tables: ["DeviceLogonEvents"],
    schemaVerifiedAt: "2026-08-30",
    lookback: "7 days",
    nrtCompatibility: "Can be adapted after separating success and failure logic and preserving required identifiers.",
    expectedFields: ["Timestamp", "DeviceId", "DeviceName", "ActionType", "AccountName", "RemoteIP"],
    falsePositives: ["Approved VPN egress", "Jump hosts", "Managed service providers", "Authorised remote support"],
    tuning: ["Exclude approved source ranges", "Scope administration hosts", "Separate successful and failed events", "Prioritise unmanaged destinations"],
    validationSteps: ["Confirm the raw LogonType value RemoteInteractive", "Review RemoteIPType coverage", "Validate known jump-host traffic", "Split success and failure follow-up logic"],
    documentationLinks: [
      { label: "DeviceLogonEvents schema", url: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table" },
    ],
    kql: `DeviceLogonEvents
| where Timestamp > ago(7d)
| where LogonType == "RemoteInteractive"
| where IsLocalAdmin == true
| where RemoteIPType == "Public"
| project Timestamp, ReportId, DeviceId, DeviceName,
    ActionType, AccountDomain, AccountName, AccountSid,
    LogonType, Protocol, RemoteIP, RemoteDeviceName,
    FailureReason`,
  },
  {
    id: "rare-interpreter-network",
    title: "Low-prevalence outbound connection from an interpreter or LOLBin",
    techniqueIds: ["T1105", "T1071.001"],
    type: "Hunting starter",
    status: "Schema reviewed · Tenant validation required",
    purpose: "Find successful public network connections from interpreters or LOLBins to destinations seen on very few devices.",
    targetProduct: "Microsoft Defender XDR Advanced Hunting",
    prerequisites: ["Microsoft Defender for Endpoint"],
    tables: ["DeviceNetworkEvents"],
    schemaVerifiedAt: "2026-08-30",
    lookback: "7 days",
    nrtCompatibility: "Aggregation makes this hunt-only as written.",
    expectedFields: ["RemoteUrl", "RemoteIP", "RemotePort", "InitiatingProcessFileName", "Connections", "Devices"],
    falsePositives: ["Automation", "Software deployment", "Update services", "Content-delivery networks"],
    tuning: ["Exclude approved automation", "Build destination prevalence baselines", "Account for forward proxies", "Prioritise unusual process and destination combinations"],
    validationSteps: ["Confirm ConnectionSuccess values are present", "Review public/private IP classification", "Baseline approved automation", "Validate destination visibility behind proxies"],
    documentationLinks: [
      { label: "DeviceNetworkEvents schema", url: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table" },
      { label: "Guided query example", url: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-query-builder" },
    ],
    kql: `let Interpreters = dynamic([
    "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe"
]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName in~ (Interpreters)
| where RemoteIPType == "Public"
| where isnotempty(RemoteUrl) or isnotempty(RemoteIP)
| summarize FirstSeen=min(Timestamp),
    LastSeen=max(Timestamp), Connections=count(),
    Devices=dcount(DeviceId),
    Users=make_set(InitiatingProcessAccountUpn, 10)
    by RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName
| where Devices <= 2
| order by Connections asc`,
  },
  {
    id: "startup-folder-persistence",
    title: "Startup-folder persistence activity",
    techniqueIds: ["T1547.001"],
    type: "Hunting starter",
    status: "Schema reviewed · Tenant validation required",
    purpose: "Review file activity in Windows startup folders that can provide logon persistence.",
    targetProduct: "Microsoft Defender XDR Advanced Hunting",
    prerequisites: ["Microsoft Defender for Endpoint"],
    tables: ["DeviceFileEvents"],
    schemaVerifiedAt: "2026-08-30",
    lookback: "7 days",
    nrtCompatibility: "Can be adapted after action scoping and tenant validation.",
    expectedFields: ["Timestamp", "DeviceId", "DeviceName", "ActionType", "FileName", "FolderPath", "SHA1"],
    falsePositives: ["Legitimate installers", "Logon scripts", "Software-management tools"],
    tuning: ["Exclude trusted installers", "Review expected shortcut files", "Account for maintenance windows", "Prioritise uncommon initiating processes"],
    validationSteps: ["Confirm startup-folder paths in tenant data", "Review common ActionType values", "Identify approved installers", "Tune common file and process patterns"],
    documentationLinks: [
      { label: "DeviceFileEvents schema", url: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table" },
    ],
    kql: `DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath contains
    @"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
| project Timestamp, ReportId, DeviceId, DeviceName,
    ActionType, FileName, FolderPath, SHA1,
    FileOriginUrl, FileOriginIP,
    InitiatingProcessAccountUpn, InitiatingProcessFileName,
    InitiatingProcessCommandLine`,
  },
  {
    id: "controlled-folder-access",
    title: "Controlled Folder Access ransomware precursor",
    techniqueIds: ["T1486"],
    type: "Hunting starter",
    status: "Schema reviewed · Tenant validation required",
    purpose: "Review audited or blocked Controlled Folder Access events as a possible precursor to destructive file activity.",
    targetProduct: "Microsoft Defender XDR Advanced Hunting",
    prerequisites: ["Microsoft Defender for Endpoint", "Controlled Folder Access enabled in audit or block mode"],
    tables: ["DeviceEvents"],
    schemaVerifiedAt: "2026-08-30",
    lookback: "7 days",
    nrtCompatibility: "Requires baselining and additional burst or process logic before promotion.",
    expectedFields: ["Timestamp", "DeviceId", "DeviceName", "ActionType", "FileName", "InitiatingProcessFileName"],
    falsePositives: ["Backup software", "Indexing", "Document editors", "Line-of-business applications"],
    tuning: ["Exclude known applications", "Look for unusual-process bursts", "Correlate with file and process activity", "Prioritise high-value devices"],
    validationSteps: ["Confirm Controlled Folder Access is enabled", "Check both audited and blocked action types", "Review common benign applications", "Add tenant-specific burst thresholds"],
    documentationLinks: [
      { label: "DeviceEvents schema", url: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table" },
      { label: "Monitor Controlled Folder Access", url: "https://learn.microsoft.com/en-us/defender-endpoint/controlled-folder-access-monitor" },
    ],
    kql: `DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in (
    "ControlledFolderAccessViolationAudited",
    "ControlledFolderAccessViolationBlocked"
)
| project Timestamp, ReportId, DeviceId, DeviceName,
    ActionType, FileName, FolderPath,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessSHA1`,
  },
];

export function detectionsForTechnique(techniqueId) {
  const parentId = String(techniqueId || "").split(".")[0];
  return DETECTIONS.filter((detection) => detection.techniqueIds.some((id) =>
    id === techniqueId || id === parentId || id.split(".")[0] === parentId));
}
