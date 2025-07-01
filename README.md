Chronicle Detection Rules with YARA-L for CrowdStrike & Zscaler Logs
Introduction
Google Chronicle is a cloud-based security analytics platform (part of Google Security Operations) that uses a specialized detection language called YARA-L to hunt threats across massive log data
cloud.google.com
. In this guide, we’ll walk through how to write detection rules in Chronicle’s YARA-L language, ingest and normalize log data from CrowdStrike Falcon and Zscaler, and provide real-world example rules for common use cases (malware detection, login anomalies, data exfiltration, policy bypass). We also include a custom rule example based on best practices. This step-by-step guide is structured for a beginner, with clear sections, sample rule code, and references to official documentation and blogs for further reading.
Understanding Chronicle YARA-L Rules
YARA-L (YARA for Logs) is Chronicle’s rule language for defining detections. It is derived from the traditional YARA (used for file-based malware patterns) but is designed for log events – the “L” stands for logs
cloud.google.com
. Unlike YARA which matches patterns in files, YARA-L rules operate on structured log data (Chronicle’s Unified Data Model (UDM)) and can correlate events over time. Note: YARA-L and classic YARA are different – YARA-L was created for Chronicle’s big data context, while YARA (by VirusTotal) is for malware/file identification
socprime.com
. Rule Structure: A Chronicle detection rule in YARA-L has a specific structure with several sections
socprime.com
:
Rule – A unique rule name (one word or snake_case) describing what it detects.
Meta – Metadata about the rule (e.g. author, creation date, description, version, etc.).
Events – The core logic: one or more event variables with conditions on log fields (using UDM field names). This defines what events or patterns you are looking for.
Match (optional) – A time window to group or chain multiple events (e.g. “over 5m” for 5 minutes) and/or placeholder variables for grouping values. This helps in multi-event correlation.
Condition – The triggering condition using the event variables (and possibly match placeholders) that must be satisfied for the rule to fire an alert.
A simple rule can omit the match section (for single-event logic) and just have a condition checking one event. More complex rules use multiple event variables and a time window. Each section is indented under the rule definition in the YARA-L syntax.
Step-by-Step: Writing a Chronicle YARA-L Rule
Access the Chronicle Rules Editor: Log in to your Chronicle (Google SecOps) instance. Navigate to the Rules section (via the “View Rules” option in the Chronicle UI) and open the Rules Editor
socprime.com
socprime.com
. Click “New Rule” to create a new detection rule.
Name the Rule: In the Rule section, provide a descriptive name for the rule. This is just a single line beginning with rule and the rule identifier. For example: rule suspicious_admin_activity { (Chronicle will add an ID behind the scenes). Choose a name that reflects the alert’s purpose to easily find it later
socprime.com
.
Fill in Meta Information: Under the meta: section, add key–value pairs for details about the rule. Common meta fields include:
author – Your name or email (who wrote the rule)
description – A short description of what the rule detects
rule_version – Version number or date
yara_version – YARA-L version (e.g. "YL2.0")
any other tags or info (product, severity, etc.)
For example:
yalm
Copy
meta:
  author = "analyst@example.com"
  description = "Detects unusual admin activity"
  rule_version = "1.0"
  yara_version = "YL2.0"
These meta fields don’t affect logic but are good for documentation
socprime.com
.
Define the Events Section: Under events:, outline the conditions that describe the event(s) of interest. Each event is represented by a variable (like $e1, $e2, or a named var) and one or more predicates that must all be true for that event. Use Chronicle’s UDM field names to refer to log attributes. For example, you might specify an event of type process launch with a certain process name:
yalm
Copy
events:
  $e1.metadata.event_type = "PROCESS_LAUNCH"
  $e1.principal.process.command_line = $cmd
  re.regex($cmd, `\bsvchost(\.exe)?\b`) nocase
  not re.regex($cmd, `\\Windows\\System32\\`) nocase
In this snippet, $e1 is an event that must be a process launch, and we capture its command line in the placeholder $cmd. We then require $cmd to match “svchost” (case-insensitive) and also not contain “\Windows\System32\” (meaning svchost ran from an unusual location)
cloud.google.com
. Multiple conditions in one event block are implicitly ANDed – all must be true for $e1 to be considered a match. You can define multiple event variables ($e1, $e2, etc.) to capture different events for correlation. For each event variable, list its required field conditions. Best Practice: Always start the events section with restrictive filters (like event type, product, etc.) before more complex conditions. This improves performance by narrowing scope early
cloud.google.com
cloud.google.com
. For example, filter by metadata.event_type or log source first, then do regex or other checks.
Use Match for Multi-Event Logic (if needed): If your rule needs to correlate multiple events (e.g. two different logs by the same user within a time frame), use the match: section. The match section typically contains a grouping key and a time window. For example:
yalm
Copy
match:
  $user over 5m
This means “group events by the $user value in a rolling 5-minute window.” The $user would be defined in the events section (e.g. $e1.principal.user.userid = $user). Chronicle will consider events with the same $user within 5 minutes as one group for the condition evaluation
cloud.google.com
cloud.google.com
. You can also specify multiple values (e.g., $user, $ip over 10m to group by user and IP). The match section helps enforce that events occur close in time. If your detection is a single event or you only care about existence of an event, you can omit match: altogether (Chronicle then treats each event independently or uses the implicit timeframe of the rule execution).
Define the Condition: The condition: section specifies the logic to trigger an alert, using the event variables (and match variables, if any). It’s a boolean expression that typically checks for the presence of events or specific counts. For a single-event rule, the condition is often just $e1 (true if the event $e1 was found)
cloud.google.com
. For multi-event rules, you might require multiple events to exist (e.g. $e1 and $e2) or use count operators like # (the number of events in the match window). For example:
yalm
Copy
condition:
  $e1 and $e2 and #city > 1
This condition would mean “we have both event $e1 and $e2, and there is more than one distinct $city value in the matched events.” (This example aligns with a use-case of the same user logging in from >1 city)
cloud.google.com
cloud.google.com
. Chronicle’s YARA-L supports and, or, not, as well as functions like count(), array_distinct(), etc., in the condition. The #variable syntax gives the count of distinct values of a placeholder in the match group (e.g. #city is how many unique cities were seen). Ensure your condition properly reflects the scenario you want to detect (e.g., $e1 and $e2 means both events occurred in the group).
(Optional) Outcome Section: Chronicle YARA-L also has an outcome: section (optional) which lets you define variables for enrichment or scoring. For example, you can calculate a $risk_score or prepare arrays of values from the events to include in the detection details. Outcomes do not influence whether the rule triggers (unless you incorporate them into the condition), but they can add context. A common use is to set a risk score and then require it to meet a threshold in the condition. For instance, you could start with a base score and add or subtract points based on event details, then alert only if the score is high
medium.com
medium.com
. For beginners, you can skip outcome until you need advanced scoring.
Test and Save the Rule: Before enabling the rule on live data, use Chronicle’s rule testing (Retrohunt) feature. You can run the rule against historical data to see if it generates expected detections (and adjust for false positives). Once satisfied, save and enable the rule. Chronicle will continuously apply it to incoming logs and generate alerts (“detections”) when conditions are met.
Ingesting and Normalizing CrowdStrike & Zscaler Logs in Chronicle
Before your rules can detect threats in CrowdStrike or Zscaler logs, you need to ingest and normalize those logs into Chronicle. Chronicle uses a Unified Data Model (UDM) to represent events consistently, regardless of source. Ingestion involves setting up feeds or connectors for each source:
CrowdStrike Falcon: Google Chronicle provides a built-in parser for CrowdStrike Falcon logs. Typically, you configure a Falcon Data Replicator feed to send CrowdStrike data to Chronicle
cloud.google.com
cloud.google.com
. In the Chronicle UI, under SIEM Settings > Feeds, you’d add a new feed, choose CrowdStrike Falcon as the log type, and enter the details (such as AWS SQS queue or S3 bucket that CrowdStrike is exporting logs to)
cloud.google.com
cloud.google.com
. Once set up, Chronicle will start receiving Falcon logs (like EDR telemetry and detection alerts). Chronicle automatically normalizes these logs using its parser for CrowdStrike Falcon, which maps the raw fields into the UDM schema
cloud.google.com
. For example, CrowdStrike event fields like machine name, process hash, etc., get mapped to UDM fields (principal.asset_id, target.process.sha256, etc.). Chronicle identifies the correct parser via an ingestion label. For CrowdStrike, the ingestion labels include CS_EDR (endpoint telemetry), CS_DETECTS (Falcon detections/alerts), and CS_IOC (indicator feeds)
cloud.google.com
. These labels are applied to events as they come in, and the parser will translate them to UDM. In summary: enable the CrowdStrike integration (with API keys or data feeds) and Chronicle will take care of normalizing the logs to its schema
cloud.google.com
.
Zscaler (Internet Access and Firewall): Chronicle supports ingesting Zscaler logs via a webhook feed. In the Chronicle feeds setup, you can select Webhook as the source type and choose the specific Zscaler log type (for example, “Zscaler Internet Access Audit Logs” or “ZScaler NGFW”)
cloud.google.com
cloud.google.com
. You will need to provide an API key or token from Zscaler and configure Zscaler’s Nanolog Streaming Service (NSS) or API to forward logs to the Chronicle-provided webhook URL. After configuring, Chronicle will receive Zscaler logs (such as web gateway logs or firewall logs) and normalize them. Like CrowdStrike, Zscaler logs also have an ingestion label – for instance, ZSCALER_INTERNET_ACCESS for ZIA web logs, or ZSCALER_FIREWALL for Zscaler firewall logs
cloud.google.com
. These labels ensure the appropriate parser is used to map Zscaler fields to UDM. The Chronicle documentation provides a field mapping table that shows how Zscaler log fields (URL, category, action, bytes, etc.) map to UDM fields
cloud.google.com
. Key fields such as URL, user, source IP, destination IP, bytes sent/received, action (allowed/blocked) will be available in UDM form (for example, network.http.url, principal.user.userid, network.client.ip, network.bytes_sent, security_result.action, etc.). Once logs are flowing in and normalized, you can write YARA-L rules against those UDM fields without worrying about the original log format.
Verification: After setting up feeds, it’s good practice to verify that events from CrowdStrike and Zscaler are visible in Chronicle’s search and have the expected fields. For example, you might search for a known test event (like a blocked malware from CrowdStrike or a web access from Zscaler) to ensure the integration works. With logs successfully ingested, you’re ready to build detection rules that leverage CrowdStrike’s endpoint data and Zscaler’s web traffic data.
Example Detection Rules for Common Use Cases
Below are several example YARA-L rules addressing typical use cases. Each includes a brief explanation and a sample rule (written in YARA-L 2.0 syntax). These demonstrate how to detect malware activity, anomalous logins, potential data exfiltration, and policy bypass attempts. Note: Adjust field names and values as needed for your environment; the UDM field names used here are based on Chronicle’s mappings for CrowdStrike and Zscaler logs.
Example 1: Malware Detection (Suspicious Process Execution)
This rule detects a suspicious process execution on an endpoint – specifically, svchost.exe running from an unusual directory. This could indicate malware attempting to masquerade as a Windows service host in the wrong location. It uses endpoint telemetry (e.g. from CrowdStrike EDR) about process launches:
yaral
Copy
rule suspicious_unusual_location_svchost_execution {
  meta:
    author = "Google Cloud Security"
    description = "Windows 'svchost.exe' executed from an unusual location (possible malware)"
    yara_version = "YL2.0"
    rule_version = "1.0"
  events:
    $e1.metadata.vendor_name = "CrowdStrike"
    $e1.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($e1.principal.process.command_line, `\bsvchost(\.exe)?\b`) nocase
    not re.regex($e1.principal.process.command_line, `\\Windows\\System32\\`) nocase
  condition:
    $e1
}
How it works: The rule looks for any PROCESS_LAUNCH event (metadata.event_type) from CrowdStrike logs where the process command-line contains “svchost” (case-insensitive)
cloud.google.com
 but is not running from the standard \Windows\System32\ path (which is where svchost.exe normally resides). If such an event is found, the condition $e1 is true and a detection is generated. We explicitly filtered to vendor_name = "CrowdStrike" and the event type to narrow it to endpoint data, which is a best practice for performance
cloud.google.com
. This rule would catch, for example, malware that copied svchost.exe to a different folder and executed it. (If you have other EDR or Windows logs normalized in Chronicle, this rule could catch those as well since it’s based on common UDM fields.)
Example 2: Login Anomaly (Multiple Cities in Short Time)
This rule identifies a user logging in from two different city locations within a 5-minute window – a scenario that could indicate a compromised account (impossible travel) or VPN usage anomaly. It uses authentication logs (for instance from Okta, Azure AD, or any identity provider logs ingested into Chronicle as USER_LOGIN events):
yaral
Copy
rule DifferentCityLogin {
  meta:
    author = "Analyst Team"
    description = "User logged in from two different cities within 5 minutes (impossible travel)"
    yara_version = "YL2.0"
    rule_version = "1.0"
  events:
    $udm.metadata.event_type = "USER_LOGIN"
    $udm.principal.user.userid = $user
    $udm.principal.location.city = $city
  match:
    $user over 5m
  condition:
    $udm and #city > 1
}
How it works: The $udm event variable represents a login event (event_type "USER_LOGIN"). We capture the user ID as $user and the city as $city. The match: $user over 5m groups events by the same user within a 5-minute window
cloud.google.com
. The condition then checks that we have at least one login event ($udm) and that the count of distinct cities (#city) is greater than 1 within that group
cloud.google.com
. In effect, if the same user account logs in from two different cities in quick succession (<5 minutes), the rule will trigger. This could signal a risky login (e.g. a VPN exit point change or a stolen session). Chronicle’s UDM provides the principal.location.city field if the log source includes geo-location for logins; many enterprise SSO/IdP logs do include city or at least IP which Chronicle can geo-resolve. You might refine this rule by also requiring the logins to be successful and from distant cities (if city names alone suffice), or use latitude/longitude if available. It’s a basic UEBA (User Entity Behavior Analytics) style detection.
Example 3: Data Exfiltration via Web (Large Outbound Transfer)
This rule monitors for potential data exfiltration by detecting unusually large outbound web uploads. It looks at web proxy or firewall logs (e.g. Zscaler Internet Access logs or next-gen firewall logs) for HTTP/HTTPS sessions where a huge amount of data was sent out. Such large transfers on web ports could indicate someone uploading data to an external site (e.g. a personal cloud drive or an attacker exfiltrating databases).
yaral
Copy
rule LargeOutboundDataTransfer {
  meta:
    author = "SecOps"
    description = "Possible data exfiltration – single outbound web session sending >1GB"
    severity = "LOW"
    rule_version = "1.0"
  events:
    $e.metadata.vendor_name in ("Zscaler", "Palo Alto Networks")
    $e.metadata.product_name in ("ZIA", "PAN-OS", "NGFW")
    $e.network.direction = "OUTBOUND"
    $e.target.port in (80, 443)
    $e.network.sent_bytes > 1000000000    // > 1,000,000,000 bytes (approx 1 GB)
  condition:
    $e
}
How it works: This is a single-event rule (no match section) that triggers on any event $e that meets all the criteria. We filter to vendors/products of interest – e.g., Zscaler Internet Access (vendor_name = "Zscaler", product_name = "ZIA") or a firewall (Palo Alto Networks NGFW/PAN-OS) – since these log web traffic. Then we require the network traffic direction to be outbound, the destination port 80 or 443 (web traffic)
googlecloudcommunity.com
, and the number of bytes sent (network.sent_bytes) to exceed 1 billion (roughly 1000 MB). If a single web session sent more than 1 GB out, $e is true and an alert is generated. We marked severity as "LOW" in meta because large transfers can be legitimate (backups, updates), so this is more of a hunting alert. However, it’s a useful indicator for potential data exfiltration attempts
googlecloudcommunity.com
. In practice you might adjust the threshold (1GB) up or down based on your normal traffic patterns
googlecloudcommunity.com
, or even incorporate a match window to sum bytes across multiple sessions. This example rule demonstrates how Chronicle can use network fields like network.sent_bytes and metadata fields to catch anomalies in data volume. (Adapted from a community example focusing on large outbound transfers
googlecloudcommunity.com
googlecloudcommunity.com
.)
Example 4: Policy Bypass Detection (Custom Rule Example)
Our custom example rule detects a possible policy bypass in web usage. Imagine your organization blocks access to certain website categories (like anonymizers, proxies, VPNs) via Zscaler. If a user manages to access those categories (perhaps due to a misconfiguration or using an alternate path), that may indicate an attempt to bypass security policy. This rule looks for allowed web access to any URL categorized as an anonymizer/proxy/VPN.
yaral
Copy
rule policy_bypass_possible {
  meta:
    author = "YourName"
    description = "Allowed web traffic to disallowed category (proxy/VPN) – possible policy bypass"
    rule_version = "1.0"
  events:
    $e.metadata.vendor_name = "Zscaler"
    $e.metadata.event_type = "NETWORK_HTTP"
    $e.principal.user.userid = $user
    $e.network.http.url = $url
    $e.security_result.action = "ALLOW"
    re.regex($url, `(?i)vpn|proxy|anonymizer`)
  condition:
    $e
}
How it works: We focus on Zscaler web logs (vendor_name = "Zscaler") and specifically HTTP/S events. We capture the user and URL for context. We then check that the security action was "ALLOW" (meaning the traffic was permitted, not blocked) and use a regex on the URL to see if it contains keywords like "vpn", "proxy", or "anonymizer" (common substrings for sites or services that enable bypassing filters). The condition triggers on any single event that matches, so essentially “user accessed something that looks like a proxy/VPN and it wasn’t blocked.” This could catch scenarios such as a user reaching a known proxy site that should have been filtered. In a real deployment, you might refine this rule by leveraging a category field if available in UDM (for instance, Zscaler logs often include a URL category or supercategory; Chronicle might map that to security_result.category or security_result.category_details
cloud.google.com
). If such a field exists, a more precise rule could be: $e.security_result.category_details = "ANONYMIZER" and $e.security_result.action="ALLOW". Our rule uses URL regex as a fallback. We also applied the recommended practice of putting simple filters first (vendor, event_type, user) and regex last
cloud.google.com
 for efficiency. This custom rule showcases how to use Chronicle to ensure your security policies (as reflected in logs) are effective – any unexpected “ALLOW” to risky categories can be flagged for review.
Further Reading and Resources
Writing effective Chronicle detection rules involves understanding both the log data and YARA-L syntax. Here are some recommended resources to deepen your knowledge and find additional examples:
Official YARA-L Documentation: Overview of the YARA-L 2.0 language
cloud.google.com
 and YARA-L 2.0 Syntax Reference
cloud.google.com
cloud.google.com
 on Google Cloud – these explain the language structure with more examples (single-event vs multi-event rules, using placeholders, etc.). Also review YARA-L Best Practices
cloud.google.com
cloud.google.com
 for tips on optimizing rules (filtering zero values, event type filters, regex usage, etc.).
Google Chronicle Sample Rules (GitHub): Google provides a public repository of example YARA-L rules covering many scenarios
cloud.google.com
. Browse the categories (malware, MITRE ATT&CK mappings, suspicious behaviors, etc.) to see how real detections are written. This is a great way to learn by example and even use some community rules as templates.
Ingestion & UDM Field Mappings: For details on bringing in data, see Chronicle’s docs for sources – e.g., Collect CrowdStrike Falcon logs (covers setting up feeds and what log types are supported, with field mappings)
cloud.google.com
 and Collect Zscaler Internet Access logs (how to configure Zscaler NSS/Webhook and mapping to UDM)
cloud.google.com
. Understanding how source fields translate to UDM will help you write correct event conditions in rules.
Blog Posts & Use-Case Guides: Explore third-party and Google Cloud blog posts for Chronicle. For example, SOC Prime’s blog provides a step-by-step Chronicle rule creation guide and additional context
socprime.com
socprime.com
. The Google Cloud Community has articles on building YARA-L rules (both single and multi-event) and tuning them. Notable reads: “Tuning YARA-L Rules in Chronicle SIEM” by Chris Martin (tips to reduce false positives and use outcome risk scoring)
medium.com
medium.com
, and “Building a Multi Event Rule – Joining Events” (community tutorial on multi-event logic)
cloud.google.com
cloud.google.com
. These resources offer practical insights beyond the official docs.
Chronicle Rule Writing Courses: Google Cloud Skills Boost and Chronicle documentation site have interactive labs and videos on detection engineering. If you prefer a guided experience, check out the “Building Rules to Find Threats (YARA-L Rule Demo)” video
cloudskillsboost.google
 or the Chronicle Codelabs that walk through example rule creation and retro-hunting.
With logs from CrowdStrike and Zscaler feeding into Chronicle and a solid understanding of YARA-L, you can now craft custom detection rules tailored to your organization’s needs. Start with the examples above, experiment with your own ideas, and continuously refine your rules following best practices. Chronicle’s speed and unified data model, combined with YARA-L’s flexibility, make for a powerful threat detection capability
socprime.com
cloud.google.com
. Good luck and happy threat hunting!






Sources





You said:
ok can you give me the rules for that both for all events you know or wanted one for detection

ChatGPT said:
To tailor the rules better, could you clarify what kind of detections you're most interested in?

For example:

Malware detection

Suspicious logins (multiple locations, brute force)

Policy violations (bypassed blocks, proxy use)

Data exfiltration (large uploads or downloads)

Lateral movement or privilege escalation

All of the above

Let me know which categories you’d like rules for, or if you want everything available for both CrowdStrike and Zscaler logs.







You said:
all the above , for chronicle for the dta from chronicel and zscaler and this can be also used for future for all source injectors

ChatGPT said:
Great, I’ll compile a comprehensive set of Chronicle detection rules (in YARA-L) that cover all major categories—malware detection, suspicious login behavior, policy violations, data exfiltration, and lateral movement—based on logs from CrowdStrike, Zscaler, and generalized for future data sources.

I’ll include rules that use standard UDM fields so they can be adapted across different log sources as long as they're normalized in Chronicle.

I'll update you as soon as the rules and supporting details are ready.

Research completed in 7m · 22 sources · 60 searches
Comprehensive Chronicle Detection Rules Across Log Sources

Chronicle YARA-L Detection Rules for Suspicious Activities
Below is a structured guide to detection rules in YARA-L 2.0 for Google Chronicle, organized by category of suspicious activity. Each rule includes the YARA-L syntax, its purpose, applicable log sources, and key UDM fields it uses. These rules leverage Chronicle’s Unified Data Model (UDM) so they can work across multiple data sources.
1. Malware Detection – Suspicious Process Execution
Malware often attempts to execute system binaries from unexpected locations or via abnormal parent processes. The following rule targets such behavior (e.g., a Windows svchost.exe running outside the System32 directory):
Windows svchost Executed from Unusual Path
yaral
Copy
rule suspicious_unusual_location_svchost_execution {
  meta:
    description = "Windows 'svchost' executed from an unusual location"
    author = "Security Team"
    yara_version = "YL2.0"
    rule_version = "1.0"

  events:
    $e1.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($e1.principal.process.command_line, `\bsvchost(\.exe)?\b`) nocase
    not re.regex($e1.principal.process.command_line, `\\Windows\\System32\\`) nocase

  condition:
    $e1
}
Description: Detects the Windows Service Host process (svchost.exe) being launched from an unusual path (not the standard C:\Windows\System32\), which is a common tactic used by malware to masquerade as a legitimate process
cloud.google.com
. Legitimate svchost should only run from the System32 directory.
Log Sources: Endpoint detection logs (e.g., CrowdStrike Falcon EDR) that record process executions. Specifically, any log source that populates event_type = "PROCESS_LAUNCH" in Chronicle UDM can trigger this rule
cloud.google.com
.
UDM Fields: Uses metadata.event_type to filter process launch events, and checks the process command-line (principal.process.command_line) for the presence of "svchost" outside the expected path
cloud.google.com
. (The rule uses a regex to include variations like svchost.exe
cloud.google.com
.)
2. Suspicious Logins – Impossible Travel & Brute-Force Attempts
Unusual authentication patterns, such as the same user logging in from distant locations in a short time or multiple failed logins followed by a success, can indicate account compromise attempts. Below are two rules addressing these scenarios:
Login from Multiple Cities (Impossible Travel)
yaral
Copy
rule DifferentCityLogin {
  meta:
    description = "User logged in from two different cities within 5 minutes"
    author = "Security Team"
    yara_version = "YL2.0"
    rule_version = "1.0"

  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.principal.user.userid = $user
    $e.principal.location.city = $city

  match:
    $user over 5m

  condition:
    $e and #city > 1
}
Description: Flags an “impossible travel” event where the same user account logs in from more than one city within a 5-minute window
cloud.google.com
. If a single $user has logins from two or more distinct cities in a short time, it’s likely impossible without a breach.
Log Sources: Authentication logs from identity providers or operating systems (for example, Active Directory domain controller logs, Okta/Azure AD SSO logs, etc.) that produce user login events with location metadata
cloud.google.com
. The rule is generalized via UDM, so any source mapped to USER_LOGIN events with a principal.location.city will work.
UDM Fields: Relies on metadata.event_type = "USER_LOGIN", the user’s ID (principal.user.userid), and the login location field (principal.location.city)
cloud.google.com
. The rule groups events by the userid over 5 minutes and triggers if the count of distinct city values (#city) is greater than 1
cloud.google.com
.
Brute-Force Login Attempts (Multiple Failures Then Success)
yaral
Copy
rule BruteForceThenSuccess {
  meta:
    description = "Multiple failed logins followed by a successful login"
    author = "Security Team"
    yara_version = "YL2.0"
    rule_version = "1.0"

  events:
    $fail.metadata.event_type = "USER_LOGIN"
    $fail.security_result.action = "BLOCK"
    $fail.principal.user.userid = $user

    $success.metadata.event_type = "USER_LOGIN"
    $success.security_result.action = "ALLOW"
    $success.principal.user.userid = $user

    // Ensure the failed attempt occurs before the success
    $fail.metadata.event_timestamp.seconds <= $success.metadata.event_timestamp.seconds

  match:
    $user over 15m

  condition:
    #fail > 4 and $success
}
Description: Detects a potential brute-force attack by looking for more than 4 failed login attempts followed by a successful login for the same user within a 15-minute window
cloudskillsboost.google
. This pattern — several "BLOCK" or failed authentications then an "ALLOW" — suggests an attacker may have guessed or cracked the password.
Log Sources: Any authentication log source that distinguishes login success vs failure. For example, Windows Security Event logs, enterprise SSO logs, or EDR authentication events can be used. The rule expects USER_LOGIN events with a field indicating outcome (allowed vs blocked) – many systems map failed logins to a security_result.action = "BLOCK" and successful logins to "ALLOW" in UDM
cloudskillsboost.google
.
UDM Fields: Key fields used are metadata.event_type = "USER_LOGIN", security_result.action (to identify failed vs successful attempts)
cloudskillsboost.google
, principal.user.userid for grouping by account, and metadata.event_timestamp for chronological correlation. The rule uses two event variables: $fail for failed logins and $success for a successful login, and checks that more than four fails occurred before a success for the same user (#fail > 4 and $success)
cloudskillsboost.google
.
3. Policy Violations – Proxy/VPN Access
Sometimes users may access sites that violate IT policy (e.g. proxy avoidance or VPN services) due to misconfigured or lenient rules. The following detection watches for web traffic to known proxy/VPN services that was allowed (when it likely should be blocked):
Access to Proxy/Anonymizer Sites Allowed
yaral
Copy
rule ProxyVPNAccessAllowed {
  meta:
    description = "Allowed web access to proxy/VPN anonymizer sites (possible policy violation)"
    author = "Security Team"
    yara_version = "YL2.0"
    rule_version = "1.0"

  events:
    $e.metadata.event_type = "NETWORK_HTTP"
    $e.security_result.action = "ALLOW"
    re.regex($e.security_result.category_details, `(?i)(Proxy|VPN|Anonymiz)`)

  condition:
    $e
}
Description: Triggers when a user accesses a website categorized as a proxy, VPN, or anonymizer while the action was allowed (not blocked) by the web gateway. This could indicate a policy oversight or a user bypassing security controls. For example, Zscaler or other web proxies label such sites in their URL category metadata (e.g., category containing "Proxy Avoidance and Anonymizers")
cloud.google.com
. If an event’s security_result.category_details contains terms like "Proxy" or "Anonymizer" but the action is "ALLOW", this rule will fire.
Log Sources: Primarily web proxy or secure web gateway logs (such as Zscaler Internet Access logs) that report web traffic events. These logs are ingested as NETWORK_HTTP events in Chronicle UDM
cloud.google.com
cloud.google.com
. The rule is designed to be general, so any web proxy/firewall providing URL category info and an allow/block action can feed it (e.g., BlueCoat, PAN-OS URL filtering logs mapped to UDM).
UDM Fields: Uses metadata.event_type = "NETWORK_HTTP" to identify web traffic events
cloud.google.com
. It checks security_result.action for "ALLOW" (meaning the traffic was permitted)
cloud.google.com
, and security_result.category_details for keywords that indicate the site belongs to a proxy/VPN category. The category_details field typically holds the human-readable category name from the product (for Zscaler, if an ipcat/category is present, it’s mapped into category_details
cloud.google.com
). This rule leverages that to catch policy violations even when not explicitly flagged by the product. (Note: “POLICY_VIOLATION” is a defined UDM category for blocked events
cloud.google.com
, but here we look for allowed traffic that should likely be flagged.)
4. Data Exfiltration – Large Outbound Transfers
Detecting large data transfers leaving the organization is crucial for spotting potential data exfiltration. The following rule looks for unusually high volumes of outbound data in a short period:
Large Volume Data Upload (Outbound)
yaral
Copy
rule LargeOutboundTransfer {
  meta:
    description = "Exfiltration suspect: Excessive outbound data volume in short time"
    author = "Security Team"
    yara_version = "YL2.0"
    rule_version = "1.0"

  events:
    $e.metadata.event_type = "NETWORK_HTTP"
    $e.network.sent_bytes = $bytes
    $e.target.ip = $dest

  match:
    $dest over 5m

  outcome:
    $total_bytes = sum($bytes)

  condition:
    $e and $total_bytes > 10000000  // >10 MB in 5 minutes
}
Description: Alerts on a large data upload to a single destination by any host – in this example, over 10 MB sent within 5 minutes. This threshold can be adjusted based on normal usage baselines. By grouping by the destination IP/host ($dest) over a 5-minute window, the rule catches both a single massive transfer or a burst of smaller transfers that sum up to an excessive total
cloud.google.com
. Such activity could indicate data exfiltration (for instance, an employee or malware transmitting a bulk of files to an external server).
Log Sources: Any logs that record network traffic with byte counts. This includes web proxy logs (e.g., Zscaler), firewall logs, or NetFlow records that are ingested into Chronicle. For instance, Zscaler Web Security logs populate network.sent_bytes for the size of HTTP/HTTPS requests
cloud.google.com
. EDR solutions like CrowdStrike Falcon also provide network connection details which Chronicle normalizes (though web proxies give clearer URL context). This rule is general across any NETWORK_HTTP or network flow events with byte fields.
UDM Fields: Key fields are the event type NETWORK_HTTP (indicating web/network activity)
cloud.google.com
, network.sent_bytes which measures the amount of data sent out (in bytes)
cloud.google.com
, and target.ip (used here to identify a unique destination for grouping). The rule uses an aggregate function sum($bytes) over the 5-minute window to compute total bytes sent
cloudskillsboost.google
. In the condition, $total_bytes > 10000000 acts as the trigger threshold. (The sent_bytes field is part of Chronicle’s UDM for network events, representing outbound data volume
cloud.google.com
.)
5. Lateral Movement & Privilege Escalation
This category covers patterns where an attacker moves laterally through the network or gains elevated privileges. The rules below help identify a host making multiple remote connections (possible lateral movement) and rapid promotion of a new account to admin (privilege escalation):
Multiple Host RDP Connections (Lateral Movement)
yaral
Copy
rule MultipleRDPConnections {
  meta:
    description = "One host initiating RDP sessions to many different hosts in a short time"
    author = "Security Team"
    yara_version = "YL2.0"
    rule_version = "1.0"

  events:
    $conn.metadata.event_type = "NETWORK_CONNECTION"
    $conn.target.port = 3389
    $conn.principal.asset.id = $srcHost
    $conn.target.ip = $dstHost

  match:
    $srcHost over 10m

  condition:
    $conn and #dstHost > 5
}
Description: Detects potential lateral movement via RDP (Remote Desktop Protocol). It triggers if a single source host ($srcHost) attempts RDP (port 3389) connections to more than five distinct destination hosts within 10 minutes
cloud.google.com
. In a typical environment, a server or user PC should not initiate RDP sessions to many different machines in a short span – such behavior might indicate an attacker using stolen credentials or a worm propagating.
Log Sources: Internal network logs that capture connection events are needed. This can be Windows event logs for RDP (if forwarded), EDR logs capturing network connections, or firewall logs monitoring internal traffic. For example, a CrowdStrike Falcon sensor might log an outbound connection event, or an internal firewall (if those logs are ingested) would log the connection to port 3389. In Chronicle UDM terms, any source that maps to event_type = "NETWORK_CONNECTION" with port/protocol details will work
cloud.google.com
.
UDM Fields: The rule uses metadata.event_type = "NETWORK_CONNECTION" to focus on network connection telemetry
cloud.google.com
. It then filters on target.port = 3389 to specifically catch RDP. The principal.asset.id (or .hostname) represents the source system initiating the connections, and target.ip is each destination host. We assign placeholders $srcHost and $dstHost to group by the source and track distinct targets. The condition #dstHost > 5 means more than five unique destination IPs were seen for that source in the time window (Chronicle counts distinct values for the placeholder)
cloud.google.com
.
Newly Created Admin Account (Privilege Escalation)
yaral
Copy
rule NewUserAddedToAdmins {
  meta:
    description = "New account creation followed by admin group addition (possible privilege escalation)"
    author = "Security Team"
    yara_version = "YL2.0"
    rule_version = "1.0"

  events:
    $create.metadata.event_type = "USER_CREATION"
    $create.target.user.userid = $user

    $priv.metadata.event_type = "GROUP_MODIFICATION"
    $priv.target.user.userid = $user
    re.regex($priv.target.group.name, `Admin`, nocase)

    // Ensure the account was created before being added to admin group
    $create.metadata.event_timestamp.seconds <= $priv.metadata.event_timestamp.seconds

  match:
    $user over 1h

  condition:
    $create and $priv
}
Description: Alerts on a two-step sequence indicative of privilege escalation: a new user account is created and then added to an administrative group (such as “Administrators” or “Domain Admins”) within a short period (here, 1 hour)
cloud.google.com
. In a normal scenario, new accounts are rarely granted high privileges immediately. This rule helps catch attackers creating backdoor admin users or misconfigured automated user provisioning that grants excessive rights.
Log Sources: Identity and account management logs are required. This could be Windows Active Directory Security logs (e.g., Event ID 4720 for user creation and 4728/4732 for group membership changes) if forwarded into Chronicle, or IAM system logs. Chronicle’s UDM will normalize these to events like USER_CREATION and GROUP_MODIFICATION. For example, CrowdStrike’s Falcon Identity Protection module or Azure AD logs could also feed such events. The key is that the data source provides both user creation events and group membership change events into Chronicle.
UDM Fields: Uses metadata.event_type to identify user creation and group modification events
cloud.google.com
. The target.user.userid field represents the account that was created and later added to the group (using the same $user placeholder to link them)
cloud.google.com
. We also utilize target.group.name (or a similar field) to check that the group name contains "Admin" (this catches groups like Administrators, Domain Admins, etc., case-insensitively). The timestamp condition ensures the creation event precedes the group-add event. In sum, the rule correlates a USER_CREATION with a GROUP_MODIFICATION for the same user, within 1 hour, to signal a rapid privilege escalation.
References & Best Practices: These YARA-L rules follow Google Chronicle’s recommended patterns for multi-event correlation and use of UDM fields. Refer to Chronicle’s official documentation for the [YARA-L 2.0 language syntax】
cloud.google.com
 and [Unified Data Model field definitions】
cloud.google.com
 for more details. It’s advisable to tune thresholds (e.g., time windows, byte sizes, count of events) to your environment to balance sensitivity and specificity. Always test new rules using Chronicle’s rule testing functionality before deploying to production
github.com
, and consider implementing outcome sections in rules to enrich alerts with context (affected user, host, etc.)
cloudskillsboost.google
.




Sources





You said:
this rules are simple can you give more rules with advance one for systmem level threats from crowdstrike and zscaler one also 

ChatGPT said:
To deliver more advanced rules focused on system-level threats, could you clarify what types of threats you're most interested in? For example:

Advanced malware behavior (e.g., process injection, reflective DLL loading)

Credential access or theft (e.g., LSASS access, token manipulation)

Persistence mechanisms (e.g., registry modifications, autoruns)

Network-based evasion or tunneling (e.g., DNS tunneling, domain fronting)

Abuse of living-off-the-land binaries (LOLBins)

Exploit attempts (e.g., exploitation of system services or known CVEs)

Let me know if you'd like a mix of all or prefer rules focused on one or two categories.







You said:
yes all

ChatGPT said:
Understood! I’ll conduct deep research to create a collection of advanced Chronicle detection rules targeting system-level threats. This will include:

Process injection and in-memory execution techniques

Credential dumping or LSASS access

Persistence via registry or scheduled tasks

Network evasion methods like DNS tunneling

Abuse of built-in system tools (LOLBins)

Exploit behavior against services or vulnerabilities

The rules will be tailored for CrowdStrike and Zscaler log sources and generalized to work with any UDM-compliant data source in Chronicle.

I’ll share the detailed guide and rules shortly.

Research completed in 11m · 36 sources · 60 searches
Advanced Chronicle Detection Rules for System-Level Threats

Advanced YARA-L 2.0 Rules for System-Level Threats
Process Injection & Reflective DLL Loading
YARA-L Rule:
php
Copy
rule process_injection_reflective_dll {  
  meta:  
    author = "Analyst"  
    description = "Detect process injection or reflective DLL loading"  
    yara_version = "YL2.0"  
    rule_version = "1.0"  

  events:  
    // Event for any process injection activity  
    $inj.metadata.event_type = "PROCESS_INJECTION"  
    // Event for suspicious module load (likely reflective DLL in memory)  
    $mod.metadata.event_type = "PROCESS_MODULE_LOAD"  
    $mod.target.file.full_path = ""      // Module loaded with no file path (memory only)  

  condition:  
    $inj or $mod  
}  
Description: This rule triggers when a process injects code into another process or loads a DLL reflectively (i.e. from memory without a file on disk). It leverages Chronicle’s UDM event types PROCESS_INJECTION (which indicates a process injection into another
cloud.google.com
) and PROCESS_MODULE_LOAD for modules loaded by a process. A reflective DLL injection often results in a module with no file path (loaded purely in memory)
reddit.com
crowdstrike.com
. The rule will flag any such injection events or memory-only module loads as potential code injection attacks. This behavior is frequently used by advanced malware and “fileless” attacks (e.g. shellcode injection or reflective DLL loading as used by Cobalt Strike, Kovter, NotPetya, etc.
crowdstrike.com
). Applicable Data Sources: Endpoint detection logs (e.g. CrowdStrike Falcon EDR) that report process injections or module loads, and any other UDM-normalized process execution feeds. In Chronicle, CrowdStrike detections of reflective DLL injection/injection appear as PROCESS_INJECTION events (sometimes with details like a reflectively loaded DLL opening LSASS
reddit.com
). Key UDM Fields: $event.metadata.event_type (values "PROCESS_INJECTION" or "PROCESS_MODULE_LOAD"), $event.principal.process[...] (injecting process info), $event.target.process[...] (target of injection) or $event.target.file.full_path (module path). The rule uses a regex-like match (full_path = "") to catch memory-only modules (no disk path). Sources: Chronicle UDM documentation for event types
cloud.google.com
; CrowdStrike on fileless attacks
crowdstrike.com
 (code injection and reflective DLL usage).
Credential Theft – LSASS Memory Access
YARA-L Rule:
php
Copy
rule lsass_credential_access {  
  meta:  
    author = "Analyst"  
    description = "Detect suspicious process accessing LSASS memory (credential dump attempt)"  
    yara_version = "YL2.0"  
    rule_version = "1.0"  

  events:  
    $e.metadata.event_type = "PROCESS_OPEN"  
    $e.target.process.file.name = "lsass.exe"  
    $e.principal.process.file.name != "lsass.exe"    // Exclude LSASS itself  

    // (Optional safe-listing examples)  
    not re.regex($e.principal.process.file.name, `(?i)^(MsMpEng\.exe|ProcMon\.exe)$`)  

  condition:  
    $e  
}  
Description: This rule detects when a process opens a handle to the LSASS process (Local Security Authority Subsystem Service), which is a common technique for credential dumping
redcanary.com
redcanary.com
. It looks for any PROCESS_OPEN event where the target process is lsass.exe and the actor (principal) is not LSASS itself. In practice, any user-land process attempting to read LSASS memory (via OpenProcess/ReadProcessMemory) is highly suspicious
redcanary.com
. The rule can be tuned by excluding known legitimate processes that access LSASS (e.g. antivirus or backup agents) to reduce false positives. By monitoring these cross-process access events, defenders can catch tools like Mimikatz and other credential dumping utilities which target LSASS
redcanary.com
. (Note: Chronicle’s UDM normalizes such events from EDR or Windows logs, e.g. Sysmon Event ID 10 for process access
redcanary.com
.) Applicable Data Sources: Endpoint security logs and OS telemetry that capture process handle opens. For example, CrowdStrike Falcon or Windows Sysmon logs (via Chronicle) report when a process tries to access lsass.exe. Any UDM-compatible EDR feed that populates metadata.event_type = "PROCESS_OPEN" and identifies LSASS as the target process will trigger this rule. Key UDM Fields: $event.metadata.event_type ("PROCESS_OPEN" indicates a process being opened
cloud.google.com
), $event.target.process.file.name (target process name, here lsass.exe), $event.principal.process.file.name (the process attempting access). The rule primarily hinges on detecting LSASS as the target and uses the principal’s process name for context (with optional regex to filter trusted tools). Sources: Red Canary’s analysis of LSASS dumping (emphasizing cross-process handle access to LSASS)
redcanary.com
; MITRE ATT&CK (OS Credential Dumping via LSASS Memory).
Persistence Techniques (Registry, Scheduled Tasks, Services)
YARA-L Rule:
php
Copy
rule persistence_registry_tasks_services {  
  meta:  
    author = "Analyst"  
    description = "Detect common persistence mechanisms: registry run keys, scheduled task creation, or new service installation"  
    yara_version = "YL2.0"  
    rule_version = "1.0"  

  events:  
    // Registry Run key creation (common persistence via HKLM/Run or HKCU/Run)  
    $reg.metadata.event_type = "REGISTRY_CREATION"  
    re.regex($reg.registry_key, `(?i)\\Windows\\CurrentVersion\\Run`)  

    // Scheduled task creation via schtasks.exe  
    $task.metadata.event_type = "PROCESS_LAUNCH"  
    re.regex($task.principal.process.command_line, `(?i)\bschtasks(\.exe)?\b`)  
    re.regex($task.principal.process.command_line, `(?i)\s/create\b`)  

    // New Windows service creation event  
    $svc.metadata.event_type = "SERVICE_CREATION"  
    $svc.target.service.name = $svcName            // capture service name (placeholder)  
    // Detect if service binary path is outside System32 (potentially malicious)  
    not re.regex($svc.target.service.binary_full_path, `(?i)\\Windows\\System32\\`)  

    // Service creation or config via sc.exe command  
    $sc.metadata.event_type = "PROCESS_LAUNCH"  
    re.regex($sc.principal.process.command_line, `(?i)\bsc(\.exe)?\b\s+(create|config)\b`)  

  condition:  
    $reg or $task or $svc or $sc  
}  
Description: This multi-trigger rule identifies several common persistence techniques attackers use to maintain foothold
redcanary.com
redcanary.com
:
Registry Run Key: Flags creation of registry keys under the typical autorun paths (e.g. HKLM\Software\Microsoft\Windows\CurrentVersion\Run). Malware often adds values here to launch on startup.
Scheduled Task: Flags invocation of the Windows Scheduled Tasks utility (schtasks.exe /create) to set up a persistent task
redcanary.com
. Attackers use scheduled tasks to execute payloads at system startup or regular intervals. (This specifically looks for the /create flag on schtasks.exe – Red Canary notes that Dridex and others create tasks in system directories using this method
redcanary.com
.)
Windows Service: Detects creation of a new service, either via the OS event (SERVICE_CREATION) or through use of the Service Control tool (sc create or sc config). Installing or modifying services is a known persistence tactic
redcanary.com
, since services run with high privileges and start automatically. The rule alerts on any new service, especially if the service’s binary is not in System32 (potentially an odd location for a service executable). It also monitors for sc.exe usage, as adversaries frequently leverage sc to register services
redcanary.com
 (“The use of sc.exe to... modify a service is a good indication of malicious use”
redcanary.com
).
By combining these detections with OR logic, any one of these persistence mechanisms will trigger the rule. In practice, you might separate them for tuning, but this showcases multiple persistence TTPs in one rule. Analysts should review such detections to confirm malicious intent (e.g. malware adding run keys vs. legitimate software installers). False positives can be reduced by excluding known admin activity or software deployments in the rule logic (e.g. via additional not conditions). Applicable Data Sources:
Registry Events: Windows Event logs or EDR logs that capture registry changes (e.g. Sysmon Event ID 13 or EDR telemetry) – normalized to UDM with event types like REGISTRY_CREATION.
Scheduled Tasks: Process execution logs from EDR or Sysmon (Event ID 1) showing schtasks.exe commands. Zscaler or other endpoint logs might also log admin tool usage.
Services: Windows Security logs (Service Control Manager events 7045 for new service) or EDR detections – ingested into Chronicle as SERVICE_CREATION or similar. Also, process execution logs for sc.exe usage.
Key UDM Fields: $event.metadata.event_type (multiple values: "REGISTRY_CREATION", "PROCESS_LAUNCH", "SERVICE_CREATION"), $event.registry_key (registry path created), $event.principal.process.command_line (to parse schtasks or sc.exe commands), $event.target.service.name and $event.target.service.binary_full_path (new service details). We leverage regex on strings like registry paths and command-line contents for flexible matching. Sources: MITRE ATT&CK Persistence techniques (Registry Run Keys T1547.001, Scheduled Task T1053.005, New Service T1543.003)
redcanary.com
redcanary.com
; Red Canary Threat Intel (scheduled tasks for Dridex
redcanary.com
, malicious service installation via sc.exe
redcanary.com
).
Network Evasion – DNS Tunneling & Domain Fronting
Rule 4a: DNS Tunneling Detection
php
Copy
rule dns_tunneling_suspected {  
  meta:  
    author = "Analyst"  
    description = "Detect potential DNS tunneling (high query volume to single domain)"  
    yara_version = "YL2.0"  
    rule_version = "1.0"  

  events:  
    $dns.metadata.event_type = "NETWORK_DNS"  
    $dns.principal.asset_id = $src     // source asset (client making DNS queries)  
    $dns.network.dns.question.name = $domain  

  match:  
    $src, $domain over 5m             // group events by source and domain over 5 minutes  

  condition:  
    $dns and count($dns.metadata.event_timestamp.seconds) > 50  
}  
Description: This detection looks for signs of DNS tunneling, where an abnormal number of DNS queries are made to a single domain (or subdomain) in a short time. Attackers using DNS tunneling will often generate a high volume of DNS requests to the same domain as they encode data in DNS queries
fidelissecurity.com
. This YARA-L rule groups DNS events by source host and queried domain over a 5-minute window. If more than 50 DNS queries to the same domain occur from one host in 5 minutes, the rule triggers (the threshold can be adjusted based on baseline traffic). Such an unusually high frequency suggests possible tunneling or data exfiltration via DNS
fidelissecurity.com
fidelissecurity.com
. Additionally, DNS tunneling often involves long or randomized subdomains (to carry payload data). While not explicitly shown in this rule, analysts should also watch for excessively long domain names or high-entropy domain strings in DNS queries
fidelissecurity.com
. In practice, one could extend the rule with regex patterns (e.g., detecting domains >50 characters or base64-like strings in subdomains
fidelissecurity.com
). Another indicator is a spike in DNS NXDOMAIN responses if malware queries many non-existent subdomains. Overall, this rule focuses on the traffic pattern aspect (volume/frequency), which is a strong tunneling indicator alongside payload analysis
fidelissecurity.com
fidelissecurity.com
. Applicable Data Sources: DNS logs from enterprise DNS servers or security tools (e.g. Zscaler DNS logs, internal DNS server logs) ingested into Chronicle. The logs must be normalized to NETWORK_DNS events in UDM. This could also catch DNS traffic from endpoint EDR logs if those report DNS queries. The rule is source-agnostic as long as queries are recorded; it can apply to cloud DNS logs, firewall DNS queries, etc. Key UDM Fields: $event.metadata.event_type = "NETWORK_DNS", $event.network.dns.question.name (the domain name queried), $event.principal.asset_id (client host identifier). The rule uses the match clause to correlate events by source and domain, and uses a count of events in the condition. In YARA-L, count($dns.metadata.event_timestamp.seconds) effectively counts the number of DNS query events in the group. The threshold “>50 in 5m” is an example trigger for suspicious volume. Sources: Fidelis Security on DNS tunneling detection – highlighting unusually high query rates to single domains
fidelissecurity.com
 and abnormal domain name lengths or patterns
fidelissecurity.com
; GIAC/Infosec research recommending analysis of DNS query frequency and payload for tunneling indicators
fidelissecurity.com
fidelissecurity.com
. Rule 4b: Domain Fronting Detection
php
Copy
rule domain_fronting_detect {  
  meta:  
    author = "Analyst"  
    description = "Detect possible HTTPS domain fronting (SNI vs Host header mismatch)"  
    yara_version = "YL2.0"  
    rule_version = "1.0"  

  events:  
    $http.metadata.event_type = "NETWORK_HTTP"  
    $http.network.tls.server_name = $sni        // TLS SNI (Server Name Indication)  
    $http.network.http.request.host = $host     // HTTP Host header (requested hostname)  
    $sni != ""  
    $host != ""  
    $host != $sni  

  condition:  
    $http  
}  
Description: This rule identifies domain fronting, a technique where the TLS SNI (the domain name in the TLS handshake) is different from the HTTP Host header inside the encrypted session
zscaler.com
. Adversaries use domain fronting to disguise malicious traffic by using a benign hostname for the TLS connection and a different, covert host in the HTTP request once the tunnel is established
zscaler.com
zscaler.com
. In Chronicle’s UDM, if logs (e.g. Zscaler Web Proxy logs) provide both the SNI (network.tls.server_name) and the HTTP Host header (network.http.request.host), this rule checks for any mismatch. A non-empty SNI that does not exactly match the Host header indicates a potential fronting attempt
zscaler.com
. For example, a TLS connection to cdn.example.com with an HTTP Host of malicious.site would trigger this rule. Such mismatches are rarely legitimate; they almost always signal domain fronting or misconfiguration. Zscaler’s own platform, for instance, specifically logs and alerts on “Domain Fronted Host Header” events when it sees this condition
zscaler.com
. This rule allows a SIEM analyst to catch those events generically. Domain fronting is often used to evade network filters by leveraging high-reputation domains (CDNs, cloud services) as cover traffic
zscaler.com
zscaler.com
. Detecting it helps uncover hidden C2 channels or data theft occurring under the guise of normal HTTPS traffic. Applicable Data Sources: Web proxy and firewall logs that record HTTP(S) transactions with hostname details. Zscaler Internet Access logs are ideal, as they include fields for the TLS SNI and HTTP Host and even have a built-in detection for mismatches
zscaler.com
. Any UDM-normalized source with NETWORK_HTTP events that captures both the server name (TLS) and the requested host can feed this rule. TLS interception must be in place (the proxy sees the Host header) for this detection to work. Key UDM Fields: $event.metadata.event_type = "NETWORK_HTTP", $event.network.tls.server_name (the domain requested in TLS handshake), $event.network.http.request.host (the Host header in the HTTP request). The rule simply compares these strings. (Field naming note: depending on the parser, the HTTP host header might appear as target.domain or request.host. Here we assume a field for the host header as network.http.request.host.) The condition $host != $sni flags the mismatch. Sources: Zscaler research on domain fronting – recommends comparing SNI and HTTP Host for mismatches
community.zscaler.com
zscaler.com
; Example case study of fronting via mismatched TLS and Host (Azure CDN example)
zscaler.com
.
Abuse of Living-Off-the-Land Binaries (LOLBins)
YARA-L Rule:
swift
Copy
rule suspicious_LOLBin_usage {  
  meta:  
    author = "Analyst"  
    description = "Detect suspicious use of common LOLBins (PowerShell, MSHTA, Rundll32, etc.)"  
    yara_version = "YL2.0"  
    rule_version = "1.0"  

  events:  
    // PowerShell with encoded command (often used to hide malicious scripts)  
    $ps.metadata.event_type = "PROCESS_LAUNCH"  
    re.regex($ps.principal.process.command_line, `(?i)\b(?:powershell|pwsh|powershell_ise)(\.exe)?\b`)  
    re.regex($ps.principal.process.command_line, `(?i)\-enc(?:odedCommand)?\s`)  

    // MSHTA executing a remote or script (mshta with http:// or https:// in args)  
    $hta.metadata.event_type = "PROCESS_LAUNCH"  
    re.regex($hta.principal.process.command_line, `(?i)\bmshta(\.exe)?\b`)  
    re.regex($hta.principal.process.command_line, `(?i)http[s]?:\/\/`)  

    // Rundll32 launching a DLL from an unusual path (not in System32)  
    $run.metadata.event_type = "PROCESS_LAUNCH"  
    re.regex($run.principal.process.command_line, `(?i)\brundll32(\.exe)?\b`)  
    not re.regex($run.principal.process.command_line, `(?i)\\Windows\\System32\\`)  

    // Regsvr32 usage with a URL or script (often used to execute scriptlets)  
    $reg.metadata.event_type = "PROCESS_LAUNCH"  
    re.regex($reg.principal.process.command_line, `(?i)\bregsvr32(\.exe)?\b`)  
    re.regex($reg.principal.process.command_line, `(?i)\/[si]\s`)    // using regsvr32 with /s or /i (silent install)  

  condition:  
    $ps or $hta or $run or $reg  
}  
Description: This rule monitors for suspicious invocations of several Living-Off-the-Land Binaries (LOLBins) – legitimate Windows programs often abused by attackers
crowdstrike.com
. It focuses on specific patterns that are uncommon in normal admin use but frequently seen in malware or post-exploitation activities:
PowerShell Encoded Commands: Flags PowerShell running with an encoded command (-EncodedCommand or -enc). Attackers often obfuscate PowerShell payloads using this flag to avoid detection. Legitimate use of -enc is rare outside of red-team or malware scenarios.
MSHTA with HTTP: Flags mshta.exe executing content from a URL. MSHTA (Microsoft HTML Application host) can run HTML/JS script hosted remotely – often used to fetch and execute malicious scriptlets or as part of phishing payloads. Seeing mshta followed by an http:// or https:// link is a strong indicator of malicious use (it suggests pulling a script from the web).
Rundll32 Unusual DLL Path: Flags rundll32.exe launching a DLL that is not in the Windows System32 directory. Rundll32 is used to execute DLL exports; malware abuses it to run malicious DLLs (often from temp or user directories). In typical use, rundll32 should invoke system DLLs from System32 – a path outside that (or a COM scriptlet) is suspect. (Example: The PrintNightmare exploit caused spoolsv.exe to spawn rundll32 loading a rogue DLL – a scenario which could be caught by rundll32 executing a non-standard DLL path
linkedin.com
.)
Regsvr32 Silent Install: Flags regsvr32.exe usage with /s or /i (registering a DLL or scriptlet) especially with unusual context (e.g., preceded by Office spawning regsvr32 as noted in Dridex cases
redcanary.com
). Regsvr32 can execute DLLs or even URL-based scriptlets (the “Squiblydoo” technique). This rule broadly watches for regsvr32 being invoked (often by malware or macro scripts) with typical switches used in malicious automation.
Each of these binaries is a known LOLBin included in the MITRE ATT&CK category Signed Binary Proxy Execution (T1218)
redcanary.com
crowdstrike.com
. Legitimate admin use of these patterns is infrequent, so any detection should be investigated. In practice, security teams maintain allow-lists for known good uses (e.g., some IT scripts may use PowerShell with encoded commands). The rule can be tuned by adding not conditions for specific command substrings or process lineage (e.g., if certain IT processes launch PowerShell in encoded form regularly). Applicable Data Sources: EDR process execution logs (CrowdStrike, Carbon Black, etc.) or Sysmon logs that capture command-line arguments. Specifically, logs from endpoint agents that record full process command lines are needed. This applies to any data source normalized into Chronicle’s UDM as PROCESS_LAUNCH events with command-line details (CrowdStrike Falcon, for example, provides these details which Chronicle can ingest). Key UDM Fields: $event.metadata.event_type = "PROCESS_LAUNCH", $event.principal.process.command_line (the full command-line of the process). The rule uses regex conditions on the command line to identify specific binary names and parameters. (It implicitly uses $event.principal.process.file.name via matching the binary name in the command line string). We use separate event variables ($ps, $hta, $run, $reg) to check multiple conditions and then a combined OR in the condition. This way, any one suspicious LOLBin usage triggers the rule. Sources: CrowdStrike on LOLBins (lists PowerShell, MSHTA, WMI, regsvr32, etc. as commonly abused utilities
crowdstrike.com
); Red Canary detection insights (e.g., Office spawning regsvr32 in Dridex infections
redcanary.com
). These binaries are frequently referenced in threat reports as tools for fileless malware execution
crowdstrike.com
.
Exploit Attempts – Service Exploitation & CVE Behaviors
YARA-L Rule:
bash
Copy
rule service_exploit_spooler_rundll32 {  
  meta:  
    author = "Analyst"  
    description = "Detect potential service exploitation (PrintNightmare example: spoolsv spawning rundll32)"  
    yara_version = "YL2.0"  
    rule_version = "1.0"  

  events:  
    $proc.metadata.event_type = "PROCESS_LAUNCH"  
    $proc.principal.process.file.name = "rundll32.exe"  
    $proc.principal.process.parent_process.file.name = "spoolsv.exe"  

  condition:  
    $proc  
}  
Description: This rule is an example for catching a known exploit pattern where a privileged service process spawns a suspicious child process. In particular, it’s tailored to the PrintNightmare (CVE-2021-34527) behavior: the Windows Print Spooler service (spoolsv.exe) unexpectedly launching rundll32.exe to execute malicious code
linkedin.com
. Under normal conditions, spoolsv.exe (and many service processes) do not create new instances of rundll32.exe or command shells, so this is a red flag. The rule looks for any process launch event where the parent process is spoolsv.exe and the new process is rundll32.exe. Upon a successful PrintNightmare exploitation, that exact sequence occurs (spoolsv runs a rogue DLL via rundll32)
linkedin.com
. This has a very low false-positive rate in most environments
community.fortinet.com
linkedin.com
. More generally, this rule exemplifies detecting service exploitation: you could adapt the logic to other services and binaries. For instance, detecting IIS worker process (w3wp.exe) spawning cmd.exe or powershell.exe would similarly indicate exploitation of a web service. Adversaries exploiting a service often cause it to spawn a “living-off-the-land” process or a command interpreter as part of the payload. By monitoring parent-child relationships involving critical system services, one can catch these post-exploit behaviors. In Chronicle, EDR logs that include parent process info (such as Falcon logs or Windows events) are used to populate the parent_process fields, enabling this detection. Applicable Data Sources: Endpoint and server logs that show process lineage. CrowdStrike Falcon’s process telemetry, Sysmon Event ID 1 (which includes parent process data), or Windows Security EID 4688 (if enhanced auditing is on) can all feed this. The data should be normalized so that spoolsv.exe appears as principal.process.parent_process.file.name for the child event. In Chronicle UDM, many EDR integrations (including CrowdStrike) populate the parent process fields for process launch events. This rule is Windows-centric (Print Spooler), but similar rules could apply to Linux daemons if those logs existed. Key UDM Fields: $event.metadata.event_type = "PROCESS_LAUNCH", $event.principal.process.file.name (the new process name), $event.principal.process.parent_process.file.name (the parent process name). This rule specifically filters on parent = spoolsv.exe and child = rundll32.exe. These fields come from the process tree data in the log source
linkedin.com
. (Note: Ensure the parser populates parent_process.file.name. Chronicle’s UDM does support parent_process info for process events.) Sources: Microsoft and community analyses of PrintNightmare – noting that on exploit, spoolsv.exe spawns rundll32.exe executing an attacker’s DLL
linkedin.com
. Similar patterns are seen in other service exploits (e.g., webshells causing IIS (w3wp.exe) to spawn cmd.exe). Monitoring service processes for abnormal children is a recommended detection strategy
logpoint.com
. The above rule demonstrates this for a high-profile CVE.






Sources





You said:
create me more rules for crowdstrike and zscaler

ChatGPT said:
Would you like more advanced rules like the ones I just shared (e.g., detecting exploits, LOLBins, DNS tunneling), or would you prefer additional rules focused on user behavior, malware detection, or web activity? Also, are you looking for specific use cases or techniques (e.g., phishing, ransomware behavior, insider threats)? Let me know your priorities so I can tailor the next batch effectively.







You said:
yes 

ChatGPT said:
Great, I’ll prepare another set of advanced Chronicle YARA-L detection rules focused on CrowdStrike and Zscaler log sources. This batch will include additional techniques such as phishing delivery, ransomware behavior, insider threats, and further system or network evasion tactics.

I’ll share the new rules and explanations shortly.

Research completed in 10m · 31 sources · 123 searches
Additional Advanced Chronicle Rules for CrowdStrike and Zscaler

Advanced YARA-L 2.0 Detection Rules for Chronicle SIEM
Below is a collection of advanced threat detection rules written in YARA-L 2.0 for Google Chronicle. These rules leverage CrowdStrike Falcon EDR (endpoint) logs and Zscaler Internet Access (web proxy/firewall) logs to cover various threat categories beyond basic system-level events. Each rule is grouped by threat category, with a description of its detection logic, applicable log source(s), and key Chronicle Unified Data Model (UDM) fields. The YARA-L syntax is provided in full for each rule.
Phishing and Initial Access
Phishing campaigns often deliver malicious documents or leverage Office macros for initial access. The following rules detect suspicious document download activity and malicious Office macro execution:
Suspicious Document Download (Macro-Enabled Office Files)
Description: Detects downloads of macro-enabled Office documents (e.g., .docm, .xlsm) via web traffic, which often indicate phishing lure delivery. Macro-enabled files downloaded from the internet are unusual and can be flagged as initial access attempts
detection.fyi
logpoint.com
. This rule monitors Zscaler web proxy logs for HTTP GET requests where the URL or filename ends in an Office macro-enabled extension. Such activity is considered suspicious, as threat actors commonly deliver malicious Office docs to trick users into enabling macros
logpoint.com
.
Log Source: Zscaler Web Proxy (HTTP traffic logs)
Key UDM Fields: metadata.event_type (e.g. NETWORK_HTTP), principal.user.userid (user initiating download), target.url (full URL of HTTP request), target.file.full_path or target.url (filename/path from URL), network.http.method (HTTP method)
yaral
Copy
rule Phishing_Doc_Download {
    meta:
        author = "SecOps Team"
        category = "Phishing/Initial Access"
        description = "Detect download of macro-enabled Office documents (possible phishing payload)"
    events:
        // $e: any web HTTP event with filename ending in macro-enabled extensions
        $e.metadata.event_type = "NETWORK_HTTP"
        $e.network.http.method = "GET"
        // Extract filename from URL (after last '/')
        $filename = re.extract($e.target.url, "[^/]+$")  
        // Filename ends with .docm, .xlsm, .pptm, etc.
        $filename = re.matches($filename, `(?i)\.(docm|dotm|xlsm|xltm|pptm|potm)$`)
    condition:
        $e
}
In this rule, the condition triggers on any single event ($e) that matches – i.e., a GET request for a file whose name matches common macro-enabled Office extensions. The use of regex ensures we catch files ending in .docm, .xlsm, .pptm, etc.
detection.fyi
. Such downloads are often associated with phishing emails and macro malware campaigns
logpoint.com
.
Malicious Office Macro Execution (Office Spawning Shell Process)
Description: Detects a Microsoft Office application (Word, Excel, PowerPoint) spawning a scripting or shell process (e.g., PowerShell, CMD, WScript). This behavior likely indicates a malicious macro executing after a user enabled it. When a user opens a malicious document and enables macros, the macro often launches PowerShell or WScript to download or run second-stage payloads
logpoint.com
. An alert that fires when Word or another Office app suddenly starts a new child process provides an early warning of this attack type
logpoint.com
. This rule correlates a parent process of WINWORD.EXE, EXCEL.EXE, or POWERPNT.EXE with a child process that is a known script interpreter or command shell.
Log Source: CrowdStrike Falcon EDR (process execution telemetry)
Key UDM Fields: metadata.event_type (e.g. PROCESS_LAUNCH), principal.process.parent_process.name (parent process name), principal.process.name (spawned process name), principal.process.command_line (child process command-line)
yaral
Copy
rule Office_Macro_Spawn_Shell {
    meta:
        author = "SecOps Team"
        category = "Phishing/Initial Access"
        description = "Office app spawning a shell or script process (possible malicious macro execution)"
        severity = "HIGH"
    events:
        // $proc: any process launch event where parent is an Office app and child is a script/shell
        $proc.metadata.event_type = "PROCESS_LAUNCH"
        $parentName = $proc.principal.process.parent_process.name
        $childName  = $proc.principal.process.name
        // Parent process is Word, Excel, or PowerPoint
        $parentName = any{ "WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE" }
        // Child process is a scripting or command interpreter (PowerShell, CMD, WScript, etc.)
        $childName  = any{ "powershell.exe", "powershell_ise.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe" }
    condition:
        $proc
}
This rule fires on a single EDR process event where an Office program (e.g. Word) launches a suspicious child process. It uses the UDM field principal.process.parent_process.name to identify the parent (Office application) and principal.process.name for the spawned process. If Word spawns PowerShell or WScript, it strongly suggests a malicious macro was enabled
logpoint.com
. Monitoring for Office spawning such processes is an effective way to catch macro malware early
logpoint.com
.
Ransomware Behavior
Ransomware attacks exhibit distinct behaviors like rapid file modifications (encryption) and disabling system recoveries. The rules below detect these patterns on endpoints:
Mass File Modification by Single Process
Description: Detects a single process performing mass file modifications in a short period – a hallmark of ransomware encrypting files. Ransomware often enumerates and encrypts numerous files, causing a massive increase in file renames or modifications within minutes
goldskysecurity.com
. This rule monitors file-write events and triggers if one process modifies an unusually high number of files in a small timeframe (indicative of bulk encryption). A process touching, for example, dozens of files in under a few minutes is unlikely during normal use and suggests ransomware activity
goldskysecurity.com
.
Log Source: CrowdStrike EDR or OS file monitoring logs (file creation/rename events)
Key UDM Fields: metadata.event_type (e.g. FILE_MODIFICATION), principal.process.name (process performing modifications), target.file.full_path (file path modified)
yaral
Copy
rule Ransomware_Mass_FileMod {
    meta:
        author = "SecOps Team"
        category = "Ransomware"
        description = "Mass file modifications by one process (potential ransomware encryption)"
        severity = "CRITICAL"
    events:
        // $f: file modification events filtered by same process
        $f.metadata.event_type = "FILE_MODIFICATION"
        $procName = $f.principal.process.name
        // Use a placeholder to group events by process name (assuming unique process instance by name here)
        $groupProc = $procName  
    match:
        // correlate events over a short window (e.g., 2 minutes) by process name
        $groupProc over 2m
    condition:
        // Trigger if more than 100 file modifications by the same process in 2 minutes
        #f > 100
}
In this rule, we look for an excessive number of FILE_MODIFICATION events (file writes/renames) by the same process within a 2-minute window. The condition #f > 100 means more than 100 such events occurred (i.e., the process modified 100+ files) in that period. This threshold can be tuned, but any sudden spike in file renames is a red flag for ransomware
goldskysecurity.com
. The rule uses $groupProc as a grouping key (the process name) in the match clause so that only events from one process are counted together.
Backup and Shadow Copy Deletion Commands
Description: Detects execution of backup deletion or Volume Shadow Copy removal commands often used by ransomware to disable system recovery. Many ransomware strains run built-in Windows utilities like vssadmin, wbadmin, or WMI to delete Shadow Copies and backups, inhibiting the victim’s ability to recover files
redcanary.com
. This rule looks for processes named vssadmin.exe, wbadmin.exe, wmic.exe, or bcdedit.exe with command-line arguments associated with shadow copy or backup deletion (e.g., "Delete Shadows", "delete systemstatebackup", or disabling recovery). Detecting such commands gives early warning of ransomware attempting to “inhibit system recovery” (MITRE ATT&CK T1490)
redcanary.com
.
Log Source: CrowdStrike EDR or Windows Process Execution logs (with command-line logging)
Key UDM Fields: principal.process.name (process image name), principal.process.command_line (full command line), metadata.event_type = PROCESS_LAUNCH (process execution events)
yaral
Copy
rule Ransomware_ShadowCopy_Deletion {
    meta:
        author = "SecOps Team"
        category = "Ransomware"
        description = "Volume Shadow Copy or backup deletion command (common ransomware tactic)"
        severity = "HIGH"
    events:
        $e.metadata.event_type = "PROCESS_LAUNCH"
        $procName = $e.principal.process.name
        $cmdLine  = $e.principal.process.command_line
        // Process is one of the known Windows backup management utilities
        $procName = any{ "vssadmin.exe", "wbadmin.exe", "wmic.exe", "bcdedit.exe" }
        // Command line contains typical backup/shadow removal keywords
        $cmdLine = any{
            re.contains($cmdLine, "(?i)delete\\s+shadows"),      // vssadmin delete shadows
            re.contains($cmdLine, "(?i)shadowcopy\\s+delete"),   // wmic shadowcopy delete
            re.contains($cmdLine, "(?i)delete\\s+systemstate"),  // wbadmin delete systemstatebackup
            re.contains($cmdLine, "(?i)recoveryenabled\\s+no")   // bcdedit disabling recovery
        }
    condition:
        $e
}
This rule triggers on a single process event where a backup/shadow utility is invoked with deletion parameters. For example, vssadmin.exe Delete Shadows /all /quiet or wmic shadowcopy delete would satisfy the condition. Security research shows that catching the string “vssadmin.exe Delete Shadows” in a command line is a highly reliable ransomware indicator
redcanary.com
. By monitoring these commands, one can detect ransomware attempts to erase backups “before they get totally out of hand”
redcanary.com
redcanary.com
. The key UDM fields are the process name and command line, which Chronicle EDR logs populate for process launch events.
Insider Threats
Insider threat detections focus on abnormal user behavior such as accessing sensitive data at odd hours or large-volume data exfiltration. These rules are generalized to flag unusual patterns in user activity:
After-Hours Sensitive Data Access
Description: Flags instances of users accessing sensitive resources outside of normal business hours. Regular employees have predictable working hours; if an account suddenly retrieves confidential data in the middle of the night or on weekends, it could indicate malicious intent or account compromise
searchinform.com
. This rule assumes that certain domains, URLs, or asset labels represent sensitive data stores (e.g., internal HR or finance systems, confidential document repositories). It triggers when a user accesses such resources during a defined “off-hours” window (e.g., late night). For adaptability, the rule could reference a reference list of sensitive asset identifiers or domains. Off-hours activity involving sensitive data is a known insider threat indicator
searchinform.com
.
Log Source: Zscaler Web Proxy (for cloud/app access) or relevant application logs
Key UDM Fields: principal.user.userid (user account), target.url or target.resource.name (accessed resource identifier), metadata.event_timestamp (time of event)
yaral
Copy
rule Insider_OffHours_Access {
    meta:
        author = "SecOps Team"
        category = "Insider Threat"
        description = "Sensitive data accessed during off-hours (potential insider threat)"
        severity = "MEDIUM"
    events:
        $e.metadata.event_type = "NETWORK_HTTP"           // web access events
        $user   = $e.principal.user.userid
        $domain = $e.target.domain
        // Define sensitive resources: e.g., match against a list of sensitive domains
        $domain = reference_list("SENSITIVE_DOMAINS")     // (List of sensitive data sites)
    condition:
        $e 
        and isOffHours($e.metadata.event_timestamp)       // Pseudo-function: event time outside business hours
}
Note: In the above rule, isOffHours(...) represents a check that the event timestamp falls outside of normal working hours (for example, not between 8 AM–6 PM local time). Chronicle’s rule syntax doesn’t have a built-in isOffHours function; instead, one could implement this via timestamp math or use Chronicle’s built-in detection scheduling. The key idea is to apply a time filter. When a sensitive domain (from a reference list of sensitive sites or categories) is accessed off-hours, the rule fires. Industry best practices highlight “accessing highly sensitive data after hours” as a red flag for insider threat
searchinform.com
. Applicable UDM fields include the user ID and resource domain, which help identify who accessed what. In Chronicle, principal.user.userid or email can identify the insider, and target.domain (for web logs) would identify the resource. Security teams can tune the off-hours window and sensitive resource list to their environment.
Excessive File Downloads by User
Description: Detects a user downloading an unusually large number of files or amount of data within a short period, which may indicate data theft by an insider. For example, an employee suddenly downloading dozens of confidential documents or gigabytes of data could be exfiltrating information. This rule monitors web proxy logs for file download events (e.g., HTTP GET responses with file content) and counts the number of downloads per user over a time window. If the count exceeds a threshold (e.g., >10 files in 5 minutes), an alert is generated. Such bulk data transfer to a user is a strong indicator of potential insider data exfiltration
searchinform.com
. The rule can be generalized to any log source with file access events normalized in Chronicle.
Log Source: Zscaler Web Proxy (file download logs) or any file access logs (file share, etc.)
Key UDM Fields: principal.user.userid (user performing downloads), target.file.full_path or target.url (file name or URL), network.bytes_out / network.sent_bytes (bytes sent to user – file size), metadata.event_type (e.g., NETWORK_HTTP)
yaral
Copy
rule Insider_Bulk_Downloads {
    meta:
        author = "SecOps Team"
        category = "Insider Threat"
        description = "Unusual volume of file downloads by a single user (possible data exfiltration)"
        severity = "MEDIUM"
    events:
        $e.metadata.event_type = "NETWORK_HTTP"
        $e.network.http.url = /.+/                       // any URL (placeholder to ensure $e is defined)
        $userid = $e.principal.user.userid
        // (Optionally filter by file type or size if needed:
        // e.g., $e.target.file.full_path ends with certain extensions or $e.network.bytes_out > X)
    match:
        $userid over 5m
    condition:
        #e > 10
}
This rule uses a 5-minute sliding window (match: $userid over 5m) to group web events by the same user. If more than 10 events (#e > 10) occur for one user in that window, it flags a potential incident. In practice, one might refine the filters – for instance, only count events where a file download occurred (perhaps indicated by response content type or file extensions in URL). The example above keeps it broad (any web events) for simplicity. The principle is to identify “large amounts of data being transferred” by one user to an external location, which is exactly the scenario described in insider threat guidance
searchinform.com
. Key fields are the user ID and possibly the byte counts (to measure data volume). In Chronicle UDM, network.sent_bytes could be aggregated (summed) in an outcome section to set a volume threshold (e.g., >100 MB in 5m). This rule can be adapted across different data sources since Chronicle normalizes file access events similarly (using principal.user, target.file, etc.).
Unusual Command-and-Control (C2) Traffic Patterns
Threat actors often establish C2 channels that exhibit abnormal network patterns. The rule below focuses on detecting beacon-like web traffic in Zscaler logs:
Beaconing to Unusual Host (Frequent Periodic Traffic)
Description: Identifies hosts making frequent, repeated connections to the same external server in a short timeframe – a pattern typical of malware beaconing to its C2 server. Legitimate user web browsing is more varied, whereas an automated beacon might phone home at regular intervals. This rule triggers when a single internal source (device or IP) communicates with the same destination domain or IP more than a threshold number of times within a given window (e.g. >20 requests in 5 minutes). Such high-frequency, repetitive traffic to one host is unlikely to be human-generated
netenrich.com
 and may indicate beaconing or data exfiltration channels. To reduce false positives, the destination can be checked against known benign services; our rule assumes we focus on uncategorized or rare domains that are more likely C2.
Log Source: Zscaler Web Proxy (HTTP/S requests logs) or DNS logs (for DNS beaconing detection)
Key UDM Fields: principal.asset.ip or principal.asset.id (source host), target.ip and target.domain (destination address), metadata.event_type (e.g., NETWORK_HTTP or NETWORK_DNS), network.application (protocol/application name), network.http.user_agent (client user agent string)
yaral
Copy
rule C2_Beaconing_Frequent {
    meta:
        author = "SecOps Team"
        category = "Command-and-Control"
        description = "Possible C2 beaconing: one source contacting same destination at high frequency"
        severity = "HIGH"
    events:
        $e.metadata.event_type = "NETWORK_HTTP"
        $src = $e.principal.asset.hostname        // source host
        $dest = $e.target.domain                  // destination domain (if empty, could use target.ip)
        // (Optionally filter out well-known domains by category or allowlist)
        // e.g., $e.security_result.category != "NETWORK_CATEGORIZED_CONTENT"
    match:
        $src, $dest over 5m
    condition:
        #e > 20
}
This rule groups web events by source host and destination and counts them over 5 minutes. If over 20 connections occur from one host to the same domain in that span, it’s flagged as suspicious. The rationale is that normal user browsing doesn’t hit the same server 20+ times in 5 minutes unless it’s streaming or a corporate app; but malware beacons might easily do so (e.g., beacon every 15 seconds = 20/minute). As an enrichment, one could require that the destination is not a popular domain (perhaps using security_result.category_details to skip categorized domains like CDN or email providers). This keeps focus on unusual external hosts. High-frequency events “>= 2 per second” or other non-human patterns have been cited as beaconing indicators
netenrich.com
 (our threshold averages ~0.067/sec, which is lower, catching slower beacons too). If desired, the rule can be extended to incorporate consistent packet sizes or regular time intervals, but those require advanced logic or retrospective analysis outside simple YARA-L conditions.
Application Misuse / Cloud Storage Abuse
Insiders or malware may abuse sanctioned applications or cloud storage services to exfiltrate data or perform unauthorized actions. The following rule targets cloud storage abuse, one common form of application misuse:
Excessive Data Upload to Cloud Storage
Description: Detects large-scale data uploads to cloud storage services (Google Drive, Dropbox, OneDrive, etc.), which could indicate unsanctioned use for data exfiltration. While cloud storage is often allowed, a sudden spike in the volume of data sent to such services by a user or host is suspicious. This rule monitors outbound web traffic to known cloud storage domains and accumulates the total bytes uploaded per user (or per asset) in a given period (e.g., 1 hour). If the volume exceeds a set threshold (e.g., >100 MB), it raises an alert. This generalized logic helps catch scenarios like an employee uploading a bulk of sensitive files to a personal cloud drive – a potential insider threat or policy violation. It aligns with the idea of flagging “large amounts of data transferred to an unauthorized location”
searchinform.com
.
Log Source: Zscaler Web Proxy (HTTP traffic, with byte counts)
Key UDM Fields: principal.user.userid (or principal.asset.id if monitoring by device), target.domain (cloud storage service domain), network.sent_bytes (bytes sent from client to cloud), network.http.method (e.g., PUT/POST for uploads), metadata.event_type = NETWORK_HTTP
yaral
Copy
rule CloudStorage_Data_Exfil {
    meta:
        author = "SecOps Team"
        category = "Application Misuse"
        description = "Unusually large data upload to cloud storage (possible data exfiltration)"
        severity = "HIGH"
    events:
        $e.metadata.event_type = "NETWORK_HTTP"
        $user   = $e.principal.user.userid
        $domain = $e.target.domain
        // Filter for known cloud storage domains (could use a reference list)
        $domain = any{ "drive.google.com", "dropbox.com", "onedrive.live.com", "box.com", "wetransfer.com" }
    match:
        $user over 1h
    outcome:
        $total_bytes = sum($e.network.sent_bytes)
    condition:
        $e and $total_bytes > 100000000   // >100,000,000 bytes (~95 MB) uploaded by one user in 1h
}
In this rule, we use a 1-hour window grouping by user. The outcome section aggregates the total bytes sent (network.sent_bytes) by that user to cloud storage services in the hour. The condition then checks if $total_bytes exceeds a threshold (100 million bytes in this example). If yes, that likely represents an anomalously large upload. The list of domains in the events filter can be maintained via a reference list for flexibility. Key UDM fields here include the destination domain (to identify it as a cloud storage provider) and the byte counts. Chronicle’s normalized fields network.sent_bytes (or network.bytes_out) represent data uploaded from the client side
cloud.google.com
. By monitoring these, organizations can catch misuse such as employees using personal cloud drives to siphon data. This rule is adaptable: it will automatically apply to any log source normalized into Chronicle that populates HTTP events with those domains and byte counts (e.g., other proxy logs or CASB logs), thus providing future-proof coverage.
Each of the above rules is written in YARA-L 2.0 and uses Chronicle’s Unified Data Model for broad compatibility. They are designed to be generalized detectors that can be tuned with environment-specific context (like reference lists for sensitive domains or allowlists for known good behavior). Together, these rules extend detection coverage into phishing initial access, ransomware behaviors, insider threats, C2 communications, and cloud application abuse – all sources of security risk that go beyond simple system-level event monitoring. By deploying these rules in Google Chronicle, security teams can spot these threat patterns in real time across massive log volumes, as supported by Chronicle’s scalable detection engine
redcanary.com
netenrich.com
. Sources: The detection logic above is informed by known threat behaviors and best practices from industry research. For example, malicious Office macros often spawn PowerShell or WScript processes
logpoint.com
logpoint.com
, ransomware routinely deletes shadow copies to prevent recovery
redcanary.com
 and causes surges in file renames
goldskysecurity.com
, insider threats are flagged by off-hour data access and bulk file transfers
searchinform.com
, and beaconing malware can be found by its abnormal network call patterns
netenrich.com
. Each rule’s conditions and thresholds should be validated and adjusted in your environment to balance detection sensitivity and precision.
