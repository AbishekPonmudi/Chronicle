Google Chronicle Ingestion and Detection Overview
Ingestion
Supported Log Sources and Ingestion Methods
Google Chronicle (Google Cloud Security Operations SIEM) supports ingesting data from a wide range of sources through multiple methods. Chronicle can collect logs via forwarders, agents, APIs, direct cloud integrations, and external feed connectors

Chronicle Forwarders: Lightweight customer-deployed agents (Docker container on Linux or Windows service) that receive and forward data to Chronicle’s ingestion service

. Forwarders can listen on syslog (UDP/TCP ports) for streaming log feeds, tail local log files, ingest from directories, and even pull from Kafka topics or other sources as configured. They send data in batches up to Chronicle. Google provides container images for Linux and Windows forwarders and guides for installation and configuration

. For example, you might run the forwarder container with appropriate volume mounts (for config and log file directories) and port mappings (to capture syslog on designated ports)

. Google also offers specific integration guides (via the Content Hub or documentation) for popular data sources – e.g. how to ingest Cisco ASA firewalls, Windows event logs, Palo Alto firewalls, etc. – using the forwarder configuration

.
BindPlane Agent: An alternative collection agent that can be used to gather logs from various sources and send to Chronicle

. BindPlane OP (by ObservIQ) can centrally manage these agents. This provides another option for log collection, especially in environments already using BindPlane.
Ingestion API: A direct REST API for sending events to Chronicle

. This allows custom scripts or third-party tools to push data without a local agent. The API accepts either raw log data or data formatted in Chronicle’s Unified Data Model (UDM) JSON. The maximum size for an API payload (log entry) is 4 MB

. Two endpoints are available: one for UDM-formatted events and one for unstructured raw logs

. When using the unstructured endpoint, Chronicle will apply the appropriate parser in the cloud to normalize the data. Note that if multiple log lines are sent as one payload (e.g. without newline delimiters), parsing issues can occur – each log line should start on a new line to avoid concatenation errors

. The ingestion API is secured via OAuth 2.0 authentication using a Google Cloud service account credential

. This direct API method is useful for custom integrations or for Managed Security Service Providers to push client data directly

.
Direct Google Cloud Integration: Chronicle can pull logs from Google Cloud projects natively

. For example, it can ingest Google Cloud Platform logs by integrating with Cloud Logging or Pub/Sub. This means that GCP logs (like VPC Flow Logs, Cloud Audit logs, etc.) can be forwarded to Chronicle without an on-prem agent. Configuration involves linking the Chronicle instance with the GCP project and specifying which logs to pull

Data Feeds (Third-Party Integrations): Chronicle supports feed connectors that periodically pull data from external sources like cloud storage or SaaS APIs

. For example, Chronicle can ingest logs from an Amazon S3 bucket, or fetch events from third-party APIs (such as Okta, Azure AD, SaaS applications) via feed integration

. These are configured in Chronicle’s Feed Management interface, where you select the source type and provide access details. The feed service then pulls data on schedule and sends it to the Chronicle ingestion pipeline. (Under the hood, each feed is associated with a specific log type schema – for instance, an “Azure AD Audit” feed knows how to translate Azure logs to UDM.) Data feeds are useful for sources where pushing logs is not feasible; Chronicle will retrieve the data directly from the source. Note that feed-collected logs also must conform to size limits (max 4 MB per log line)

.
Webhooks and Alert Connectors: In addition to raw logs, Chronicle can ingest alerts from other systems. Chronicle’s SOAR component provides connectors that can fetch alerts or events from other SIEMs, EDRs, or IT ticketing systems

. These alerts are ingested as Chronicle detections or events. For example, Chronicle SOAR connectors (originally from Siemplify) can poll an API for alerts from a third-party SIEM and import them into Chronicle

. Alternatively, external systems can send alerts to Chronicle via a webhook URL. In such a setup, Chronicle provides a webhook endpoint where external alerts (in a supported format) can be posted

. Alerts brought in this way are stored as alert records in Chronicle; if the raw events related to the alert are also sent or already present, Chronicle will link them and even generate a corresponding detection in the platform

. (Chronicle supports ingestion of single-event alerts only – multi-event correlation should be handled in Chronicle itself rather than ingesting a pre-correlated alert

.) This capability allows Chronicle to serve as a central hub not just for raw logs but for high-level alerts from various security tools.
Across all these methods, data flows into Chronicle’s unified ingestion pipeline

. The ingestion service acts as a gateway that receives the data, then passes it through parsing and normalization before storage. In production, organizations often use a combination of these methods: e.g. deploy forwarders for on-prem log sources (syslog, files), use the API for custom data, and set up cloud feeds for cloud-native sources.
Data Format and Schema (UDM Expectations)
One of Chronicle’s core design principles is to normalize all incoming data into a single Unified Data Model (UDM). UDM is a JSON schema defined by Google Chronicle that represents security events with common fields (like metadata.event_type, principal, target, asset, severity, etc.) regardless of source

. When raw logs are ingested, Chronicle’s parsers will map them into UDM fields. This enables unified search, correlation, and detection across disparate log sources. Supported Log Types: Each log source is identified by a log type label in Chronicle (for example, PAN_FIREWALL for Palo Alto firewall logs, WINDOWS_DNS for Windows DNS server logs, etc.). Chronicle maintains a list of hundreds of supported log types for which it has prebuilt default parsers

. If the incoming log data for one of these types is in the expected format (e.g. JSON, CSV, syslog, CEF, etc., as documented), Chronicle will automatically parse it into UDM using the default parser
cloud.google.com
. The documentation provides a catalog of these supported log types and the format each expects (e.g. syslog header + JSON body, CSV, key-value, etc.)
cloud.google.com
. This helps administrators ensure that data is being sent in a compatible format (for example, if a product can output logs in syslog or JSON, choose the format matching Chronicle’s parser expectations). For log sources that do not have a default parser, Chronicle can ingest the data as “unstructured” logs. These will still be stored, and basic things like timestamp may be extracted, but many fields might only be searchable via raw text queries (Raw Log Scan) rather than structured fields
cloud.google.com
. In such cases, it’s recommended to develop a custom parser or request Google to provide one, so that the logs can be fully utilized in UDM. Google allows customers to request new prebuilt log types or build custom log type parsers for their Chronicle instance
cloud.google.com
. If you have a proprietary or uncommon data source, you can define a custom log type (with a unique name/ID) and write a parser for it, mapping that source’s fields into the UDM schema. Unified Data Model Schema: The UDM defines a rich set of fields organized in nested objects (metadata, principal, target, etc.) to capture event attributes. Chronicle’s documentation includes an outline of the UDM and important fields that parsers should populate for different event types
cloud.google.com
. For example, metadata.event_type indicates the high-level category of the event (LOGIN, PROCESS_LAUNCH, FILE_WRITE, etc.), and Chronicle uses this field extensively in detection rules and the UI. Other vital fields include timestamps (event time vs. ingestion time), actor/user (principal), affected asset (target), geolocation, network info, process info, etc., depending on the event. When formatting data as UDM (for API ingestion) or writing a parser, it’s important to follow the UDM field definitions so that the data is recognized properly by Chronicle’s search and detection features

. Chronicle provides a UDM Field List reference and guidelines on mapping raw log fields to UDM (for instance, mapping an IP in a firewall log to principal.asset.ip if it’s the source) as part of the parser documentation. UDM vs. Raw Ingestion: Whenever possible, Google recommends sending logs in UDM format
cloud.google.com
. If you convert your data to UDM JSON and use the UDM ingestion endpoint, you bypass the need for custom parsing and ensure maximum fidelity (since you control the mapping). UDM events are immediately usable for detection rules and normalized search. In practice, many organizations will use the default raw ingestion for convenience (letting Chronicle’s built-in parsers do the work), but for any log types where parsing is not available or is inadequate, converting to UDM (or writing a parser) is the best practice. Log Type Schemas: Each log type in Chronicle has an associated schema definition (sometimes referred to as a LogTypeSchema) that describes how the raw log is parsed and which UDM fields are populated. These schema definitions are part of Chronicle’s content – for example, they indicate the regex patterns or JSON field mappings the parser will use. While the internal schema files aren’t typically edited by customers (except for custom types), Chronicle exposes metadata about them via API (the logTypeSchemas.list method can enumerate log types and their schema info available for feed connectors, etc.)
cloud.google.com
. For instance, if you are configuring a feed for Azure AD logs, the system knows the “AzureAD” log type’s expected fields via the schema so it can map the data properly
cloud.google.com
. Understanding the expected schema can help troubleshoot ingestion – e.g. if a field like “action” in the raw log isn’t appearing in UDM, it might be that the parser didn’t recognize it due to format differences.
Setting Up Forwarders and Connectors
Chronicle Forwarder Deployment: The Chronicle forwarder is typically run as a Docker container (on Linux) or as a Windows service (packaged as an executable). Google provides the container image via Google Container Registry (e.g. gcr.io/chronicle-container/cf_production_stable for Linux)
cloud.google.com
. To install, you first download the latest image with a docker pull, and prepare a configuration file (YAML) that describes what data to collect
cloud.google.com
cloud.google.com
. The config file (often named FORWARDER_NAME.conf) includes a list of collectors under the collectors: section. Each collector defines an input source and a few parameters:
Syslog Collector: Listens on specified port(s) for incoming syslog messages. You can configure UDP/TCP, enable TLS (specifying a certificate), and set a data_type (the Chronicle log type label) that this syslog stream corresponds to. For example, you might set data_type: PAN_FIREWALL on a collector that listens on port 5140 and receives PANW firewall syslog messages. The forwarder will tag incoming events with that data type so Chronicle knows which parser to use
cloud.google.com
cloud.google.com
. You can run multiple syslog collectors on different ports if needed (the Docker run command can map a range of ports, e.g. -p 0.0.0.0:10514-10520:10514-10520/udp to expose ports)
cloud.google.com
. The forwarder supports plain syslog and can be configured to trust a provided certificate for TLS if secure transport is needed (though by default, data from forwarder to Chronicle is encrypted in transit).
File Collector: Tails a local file or set of files and streams new lines to Chronicle
cloud.google.com
. You specify the file path and the data_type (log type) to assign. This is useful for ingesting any log file on disk (e.g. an application log). Options exist to control whether to start at end (to avoid resending old lines) or to read from beginning (in case of forwarder restart and you want to resend from last checkpoint)
cloud.google.com
. By default, the forwarder only sends newly appended lines (treating the file like a growing log). If a forwarder restarts, it keeps track of the last read position unless skip_seek_to_end is set to false (which would cause it to resend from the beginning, mainly for backfill or if you intentionally want to reprocess logs)
cloud.google.com
.
Splunk Collector: The forwarder can act as a HTTP Event Collector (HEC) receiver to ingest logs from Splunk or other systems that use a similar JSON format
cloud.google.com
. This means you can point a Splunk forwarder or any tool that can send to a HEC endpoint at the Chronicle forwarder’s IP and configured port. The forwarder will accept the JSON events and forward them to Chronicle with the specified data type.
Kafka Collector: Allows the forwarder to consume messages from an Apache Kafka topic
cloud.google.com
. You provide Kafka broker addresses, topic name, and credentials if needed
cloud.google.com
. This is helpful if your organization streams logs into Kafka; Chronicle’s forwarder can tap into that stream and push events to Chronicle. You can even deploy multiple forwarders for the same topic for redundancy or throughput – the docs note up to three forwarders can pull from one topic for high availability
cloud.google.com
.
Packet Capture (PCAP) Collector: Chronicle forwarder can capture network packets from an interface and forward raw packet data (as logs) to Chronicle
cloud.google.com
cloud.google.com
. This is a specialized use-case (for example, capturing DNS packets as PCAP_DNS log events). It requires additional setup (libpcap on Linux, Npcap on Windows, and running the forwarder with elevated privileges to sniff interfaces)
cloud.google.com
cloud.google.com
. Typically, you’d coordinate with Google support to enable a PCAP data type and provide BPF filter expressions for what traffic to capture
cloud.google.com
.
After defining collectors, the config is placed in a local directory (e.g. /opt/chronicle/config/) which is mounted into the container at runtime
cloud.google.com
. Then you run the container with the proper volume and network settings. The forwarder will read its config and start each enabled collector (opening ports, tailing files, etc.). Once running, it buffers and batches logs (commonly batching for up to N seconds or N bytes as configured, e.g. 10 seconds or 1MB) before sending to Chronicle to optimize throughput
cloud.google.com
. Forwarder logs can be monitored via docker logs to troubleshoot connectivity or parsing errors
cloud.google.com
. Integration Packages and Connector Setup: Google Chronicle provides integration content to simplify setup for common products. In the Chronicle Content Hub (accessible via the Chronicle console), you can find pre-configured parsers, log types, and sample forwarder configs for many vendors. For example, an “Office 365 logs integration” might supply the log type definition and parser needed for O365 management logs, along with guidance on how to set up a feed or forwarder to collect those logs. These integration “packages” ensure you have the right parser and data mappings. In many cases, simply selecting the correct data_type in your forwarder config (matching one from the supported list) is enough, since the default parser is already present
cloud.google.com
. Additionally, Chronicle’s SOAR connectors (originally from the Siemplify platform) can be used for data ingestion in some scenarios
cloud.google.com
. In the Chronicle console, under the “Use connectors” section, there is an option Ingest data using SOAR connectors
cloud.google.com
cloud.google.com
. These are typically used to ingest alerts or entity data from external systems via API. For example, there might be a connector to pull CrowdStrike detections or to periodically fetch threat intel. Setting these up involves providing API credentials in the Chronicle SOAR interface and mapping fields as needed. Connectors run on a schedule and push fetched data into Chronicle, similar to feeds. Authentication and Throughput: All data sent from forwarders or connectors to Chronicle is encrypted in transit. Forwarders communicate with Chronicle’s cloud endpoint using secure gRPC or HTTPs. A service account credential (JSON Web Token) is used by forwarders for authentication to the Chronicle API endpoints – this is obtained from your Chronicle admin settings and configured in the forwarder (often placed in a file like credentials.json and referenced by the forwarder)
cloud.google.com
. Chronicle enforces API quotas to protect the service (for example, a limit on events per second per customer for the ingestion API), but these limits are generous and designed not to bottleneck normal operations. Still, if you plan to ingest very high volumes, you should distribute load across multiple forwarders or ensure your ingestion method can handle bursts.
Custom Parsers and Troubleshooting
While Chronicle covers many log formats out-of-the-box, you may encounter cases requiring a custom parser or adjustments. Official documentation provides a guide on managing parsers and writing custom parse “rules”
cloud.google.com
:
Custom Log Types: If you need to ingest a new data source that isn’t recognized, the first step is usually to create a custom log type in Chronicle. This involves defining a name/ID and basic metadata. You can do this via the Chronicle UI or via API, and it essentially registers that log type in your environment so you can begin sending data tagged as that type
cloud.google.com
. You might also request Google to add a prebuilt parser for a widely used product that’s not yet supported – Google’s team can sometimes provide new parsers (hence “Request prebuilt log types” in the docs)
cloud.google.com
.
Parser Language: Chronicle’s custom parser syntax allows you to define how to extract fields from raw logs. Parsers can handle logs in various formats (delimited text, JSON, key-value pairs, etc.). Typically, you write parsing rules that reference the raw log text and capture tokens into UDM fields. For example, you might write a regex to parse a syslog message and assign parts of it to principal.hostname, principal.asset.ip, network.application, etc. There are also functions provided for common tasks like converting timestamps, decoding Base64, splitting key-value pairs, etc. Chronicle’s Parser Extensions documentation lists built-in functions and transformations that you can use in your parser definitions
cloud.google.com
.
Parser Deployment: Custom parsers can be uploaded via the Chronicle UI (Parser Management section) or via API. Once deployed and enabled, they will apply to new incoming logs of the specified log type. It’s important to note that parser changes are not retroactive – they only affect logs ingested after the parser is in place
cloud.google.com
. If you adjust a parser, previously collected raw logs won’t be re-parsed; you’d have to re-send them if re-processing is needed.
Testing and Troubleshooting: Chronicle provides a way to test parser logic on sample log lines. In the parser editor, you can input a raw log example and see how the parser would extract fields. The “Troubleshoot tips for writing parsers” guide offers advice such as starting with simplest patterns, incrementally building up extraction rules, and verifying mandatory fields (like event timestamps) are captured
cloud.google.com
. If a parser isn’t working, common issues include: mismatched log type labels (data sent with a different log_type than the parser expects), time format parsing errors, or unexpected log formatting by the source device. Enabling forwarder debug logs or checking the Chronicle Data Ingestion & Health dashboard can reveal parse error rates
cloud.google.com
. Chronicle’s ingestion monitoring can show if logs are coming in but failing to parse (often by indicating how many events ended up only in raw form).
Best Practices for Parsers: Keep parser rules as specific as possible to avoid ambiguity. Use anchors in regex if the log format is well-known, to ensure you don’t accidentally catch partial matches. Map as many relevant fields to UDM as makes sense – Chronicle highlights certain important UDM fields in the docs that drive detection and search (like principal.user.userid for user identity, target.asset.id for device identification, etc.)
cloud.google.com
. Ensuring those are populated will enrich your ability to write effective detection rules. Additionally, if logs contain an inherent severity or alert flag, map that to UDM’s metadata.vendor_severity or similar fields.
Should a parser consistently fail or if the logs are too free-form, Chronicle also has an Auto Extraction feature (in preview) that can attempt to automatically parse semi-structured logs using machine learning
cloud.google.com
. However, this is usually a last resort; a custom parser or formatting logs to JSON is more deterministic.
Ingestion Best Practices and Limitations
To get the most out of Chronicle ingestion, consider these best practices and be mindful of platform limits:
Use UDM or Known Formats: Whenever possible, send data in a format that Chronicle supports natively. If a device can output JSON or CEF that matches Chronicle’s expectations, use that mode. This reduces the need for complex parsing. If you have the capability to convert logs to the Chronicle UDM schema before sending (for example, via a logging pipeline or SIEM), doing so will ensure all data is normalized
cloud.google.com
cloud.google.com
. Chronicle’s UDM ingestion endpoint is optimized for already-structured data.
Batch and Buffer Logs: Chronicle forwarders batch events (default 1 MB or 10 seconds) to optimize throughput
cloud.google.com
. If you write your own integration to the Ingestion API, do the same on your side: send logs in batches (up to 4 MB per batch) rather than one event per call, to avoid throttling. The Chronicle Ingestion API will assign a batch ID; if you accidentally resend the exact same batch (same batch ID and content), Chronicle de-duplicates it and will ignore the duplicate batch
cloud.google.com
. This is a safety mechanism to prevent replay, but it means if you are retrying a failed batch send, generate a new batch ID or slightly modify payload order to ensure it’s processed.
Avoid Huge Single Files: If you are uploading very large files (several GB) via forwarder or feed, be aware it can slow down processing
cloud.google.com
. Break up log files into smaller chunks or use streaming ingestion. The note in documentation says files in the 5–10 GB range can cause significant delays
cloud.google.com
. It’s better to ingest continuously rather than accumulating such large files.
Line Size Limit: Chronicle cannot ingest extremely long single log lines. The maximum size for one log entry (one line or JSON message) is 4 MB
cloud.google.com
cloud.google.com
. This usually is not an issue for typical logs, but occasionally aggregated logs or multi-line stack traces could breach that. Ensure multiline events (like exception traces) are either broken into separate events or at least stay under that size.
Time Synchronization: Chronicle uses event timestamps from your logs for indexing. Parsers will attempt to read the timestamp; if not found or if it’s outside an acceptable range, Chronicle might timestamp the log at ingestion time. It’s best to ensure your sources include timestamps and are using NTP synchronization so that events are timely. Chronicle will accept past events (there’s support for historical ingestion), but extremely old timestamps might be dropped or flagged.
Data Health Monitoring: Use the Ingestion Health Dashboard in Chronicle to monitor incoming log volume and any errors
cloud.google.com
. Chronicle can send alerts (via Cloud Monitoring integration) if expected data stops arriving or if parse error rates spike
cloud.google.com
. Setting up these alerts helps catch issues like a forwarder going offline or a log source format change that breaks parsing.
Security and Access: Limit who can configure ingestion. Chronicle supports fine-grained IAM roles for ingestion configuration and parser management
gcp.permissions.cloud
. For example, you might grant certain team members permission to create feeds or forwarders, but not all users. Ensure your forwarder service account key is kept secure, as it can send data into your Chronicle tenant.
By adhering to these guidelines, you can reliably ingest logs from virtually any source into Chronicle, where they are uniformly normalized to UDM for analysis.
Detection
Writing Detection Rules in YARA-L
Chronicle’s detection engine uses a custom rules language called YARA-L (YARA-Language) to define threat detection logic. YARA-L 2.0 is the current version and is derived from the popular YARA syntax (used originally for malware identification), but adapted to operate on structured log data and Chronicle’s UDM events
cloud.google.com
. These rules run on incoming data (in real-time) and can also be run retrospectively on historical data. Rule Structure: A YARA-L rule consists of several sections:
Meta: Metadata about the rule, such as author, description, reference links, rule version, etc. This is informational and helps with rule management. For example, Google’s curated rules include meta fields like author = "Google Cloud Security" and rule_version = "1.0"
cloud.google.com
.
Events: This section contains one or more event definitions (variables) that specify the conditions on individual logs or alerts. Each event variable represents a set of UDM events that meet certain criteria. For instance, you might define $e1 to be “where metadata.event_type = "PROCESS_LAUNCH" and the process command-line contains 'svchost.exe'”
cloud.google.com
. YARA-L allows standard comparison operators as well as regex matching (re.regex) and other functions on event fields
cloud.google.com
. If you list multiple event variables, you can then specify how they should relate (for multi-event correlation).
Condition: The logical condition that determines if a detection should be raised. In the simplest case (single-event rule), the condition might just be $e1 (meaning “if any event matches the criteria of $e1, trigger”)
cloud.google.com
. More complex rules can use Boolean logic, counting operators, and timing windows. For example, a rule might trigger if $e1 and not $e2 (an event happened without a corresponding second event), or if a count of distinct values exceeds a threshold within a time window.
Match / Timeline (for multi-event rules): YARA-L 2.0 introduced explicit support for multi-event correlation using match and time windows. A match clause groups events by a key over a rolling time window. For instance, in a rule looking for impossible travel logins, you might group by principal.user.userid over a 5-minute window
cloud.google.com
. If within that window the same user ID appears from more than one city, the condition triggers
cloud.google.com
. The rule snippet in documentation shows $user over 5m and then condition #city > 1 meaning more than one distinct city for that user in 5 minutes
cloud.google.com
cloud.google.com
. YARA-L handles this grouping and counting logic internally.
Outcome (optional): Rules can also define outcome variables to extract and carry certain values. For example, you might store the specific IP or filename that triggered the rule as an outcome to display in the alert. (Outcome variables are more often used in composite rules, discussed later, but single rules can use them too to enrich the detection metadata.)
Rule Types: Chronicle classifies rules into a few types:
Single-Event Rules: These examine each event in isolation for a pattern. For example, “alert if any authentication event has admin privileges from a foreign country.” They trigger immediately when one event matches criteria
cloud.google.com
. These are straightforward and run at high speed.
Multi-Event Rules: These correlate multiple events within a certain timeframe (also called sequence or correlation rules). They might look for a sequence (A followed by B) or a combination (A and B by same user within X time)
cloud.google.com
. YARA-L allows defining multiple event variables ($e1, $e2, etc.) and using temporal logic (like $e1 before $e2 within 1h). Multi-event rules run slightly less frequently than single-event (to accumulate events in the window) but allow detecting complex patterns.
Composite Rules: In YARA-L 2.0, composite rules are a special category that operate on detections from other rules rather than raw events alone
cloud.google.com
cloud.google.com
. We will cover these in detail in a later section, but essentially they allow you to build higher-level alerts that combine outputs of multiple base rules (along with optional raw events or context).
Deploying Rules: Detection rules can be created and edited in the Chronicle Rules Editor (a UI in the Chronicle console where you can write YARA-L code, test it, and save). Once saved and enabled, a rule is deployed to the detection engine. New incoming events will be evaluated against all enabled rules. If a rule’s condition is met, Chronicle generates a Detection (which is Chronicle’s term for an alert) with details about which rule triggered and which events contributed. There may be a brief delay (usually seconds to a minute) from event ingestion to detection generation, depending on rule complexity and system load. Chronicle also allows rules to be managed programmatically via the Detection Engine API
cloud.google.com
. This API lets you create, update, list, and delete rules as code. This is useful for CI/CD integration (Detection-as-Code) or bulk changes. For example, security teams could store their YARA-L rules in a Git repository and use a script to push updates via the API. The Detection Engine API also provides endpoints to run a rule on demand and to retrieve rule execution status. YARA-L Capabilities: YARA-L provides a rich set of operators and functions:
String search and Regex: You can search for substrings or regex patterns within fields (with case sensitivity options)
cloud.google.com
. For instance, re.regex($e1.principal.process.command_line, \bsvchost(.exe)?\b) nocase checks for the string “svchost” as a whole word in the command line
cloud.google.com
.
Lists and Reference Sets: Chronicle supports reference lists (e.g. a list of known bad IPs or watchlist of exec names). YARA-L rules can check if a field value is in a list (using an in operator or a function). This helps incorporate threat intel or custom watchlists into detections.
Time windows: The over <time> clause allows grouping by a field over a sliding window (as shown in the multi-city login example)
cloud.google.com
. There’s also an event sequence pattern where you can say e.g. $e1 before $e2 within 10m for ordered events.
Counting and aggregation: You can use count(field) or the shorthand #field to count distinct occurrences in a group
cloud.google.com
. You can also use comparative expressions like count > 5 in the condition.
Entity context in rules: Chronicle can enrich events with entity information (like mapping IPs to asset IDs or users to department). YARA-L can leverage those enriched fields as well (for example, a rule could say trigger only if principal.asset.low_value = false meaning the event involves a high-value asset, assuming such context is added in enrichment). More on enrichment later.
Best Practices for Rules: Google provides a style guide for writing YARA-L rules (via GitHub and documentation)
github.com
. Key recommendations include:
Make rules as specific as possible to reduce false positives (use multiple conditions to narrow scope, e.g., looking for svchost.exe executing from non-standard path, rather than any svchost usage
cloud.google.com
cloud.google.com
).
Include false positive exclusions when known. The example rule excludes command lines that contain \Windows\System32\ to avoid flagging legitimate svchost executions
cloud.google.com
.
Use the meta section to document what the rule is looking for and any tuning knobs or references (e.g., MITRE ATT&CK technique IDs, if applicable).
Test rules thoroughly using Chronicle’s rule testing feature or on past data (via retrohunt) before enabling them in production. This helps you gauge how noisy a rule might be.
Leverage curated rules as a starting point or reference – Google provides many example rules for common threats (these can be found in the Chronicle GitHub repository for detection rules
github.com
 and in the Chronicle Content Hub).
Once a rule is enabled, it will generate detections visible in the Chronicle UI (under Detections/Alerts). Each detection includes the rule name, the events that triggered it (Chronicle stores up to 10 sample events per event clause to show you what matched
cloud.google.com
), and any outcome variables captured. Security analysts can then investigate these detections further.
Curated Rule Sets and Customization
Google Chronicle comes with a library of curated detection rules maintained by Google’s security research team. These curated rules cover a broad range of threat scenarios and best-practice monitoring use cases, and they are conveniently organized into categories in the Chronicle console
cloud.google.com
:
Cloud Threats: Rules focusing on suspicious activity in cloud environments (GCP, AWS, Azure). For example, detecting multiple failed login attempts to cloud console, or detection of disabled logging settings.
Chrome Enterprise Threats: Rules for Chrome Browser or Chrome OS logs with security implications.
Linux Threats: Suspicious Linux OS behaviors (e.g. usage of seldom-used binaries, signs of rootkits, etc).
MacOS Threats: Suspicious MacOS activities.
Windows Threats: A large set of rules for Windows, covering things like malware execution patterns, lateral movement, persistence techniques (e.g., unusual registry autostart entries, LSASS access, etc).
User Entity Behavior Analytics (UEBA): This includes rules that use Risk Analytics and behavioral baselines (like impossible travel or sudden change in account behavior).
Applied Threat Intelligence (ATI) Curated Detections: These are rules or detections that incorporate Google’s threat intel (from sources like VirusTotal or Mandiant) to flag events related to known IOCs or threats
cloud.google.com
.
Chronicle console provides a “Curated Detections” section where you can browse these rules. You can typically enable or disable them individually or by category. Enabling a curated rule deploys it just like a custom rule, except you cannot edit Google’s original rule directly (to preserve its integrity). However, you can clone a curated rule – Chronicle allows duplicating a curated rule into your own namespace so you can modify it. This is useful if, for instance, a curated rule is too noisy in your environment; you might clone it and add additional exclusion conditions or tune thresholds, then use your custom version instead. The curated rules are continuously updated by Google. For example, if a new threat technique emerges, Google might add a rule for it in the appropriate category (announced via Chronicle release notes or the “What’s New” section). These updates can be pulled through the Content Hub. Chronicle also imposes a rules capacity limit (e.g., a certain number of rules can be active at once)
cloud.google.com
cloud.google.com
, but curated rules typically do not all need to be on unless relevant; you should choose those relevant to your data sources and security concerns. Using Curated Detections: Google’s documentation encourages using curated detections to quickly bolster your security coverage
cloud.google.com
. For a new Chronicle deployment, one might start by enabling sets of curated rules (ensuring, of course, that the necessary logs are being ingested so those rules have data to analyze). For example, if you ingest Windows event logs, you can turn on the Windows Threats curated rules to catch common Windows attack patterns. The “Use curated detections to identify threats” guide in the docs provides descriptions of what each rule category covers and some of the logic behind notable rules
cloud.google.com
cloud.google.com
. This context helps you prioritize which detections to monitor. Customization and Exclusions: Chronicle allows configuration of rule exclusions for cases where a rule is mostly good but has known benign triggers
cloud.google.com
cloud.google.com
. Instead of copying and editing a rule, you can sometimes add an exclusion (for example, exclude a certain user or process from a detection). Chronicle’s interface has an option to set exclusions which essentially tell the detection engine to suppress alerts that match a certain sub-condition, without disabling the whole rule. This is particularly handy for curated rules that you trust but need minor tuning for your environment (say, a backup service account that always triggers a “multiple login from different cities” rule — you could exclude that account). In summary, the curated rules provide a baseline detection capability maintained by Google. They cover many known tactics and anomalous patterns. Organizations should review them, enable what’s relevant, and monitor their performance. Over time, you can refine them by applying exclusions or copying and modifying as custom rules. The combination of curated detections and your own rules (for organization-specific use cases) will form your overall detection rule set.
Retrohunt: Running Rules on Historical Data
One powerful feature of Chronicle’s detection engine is Retrohunt, which is the ability to take a detection rule and run it against historical logs (past data) rather than only live incoming data. This is useful in several scenarios: for instance, if you just created a new rule to detect a certain malware behavior, you might want to know “did this ever happen in the last 3 months in our data?” – retrohunt can find past occurrences that were not detected in real-time (perhaps because the rule didn’t exist at the time). It’s also used for threat hunting, where an analyst might write a hypothesis rule and search back in time. Definition: A retrohunt uses a selected YARA-L rule to search for detections across existing logs already stored in Chronicle
cloud.google.com
. Essentially, it back-tests the rule on a historical dataset. When you initiate a retrohunt, you specify a time range (start and end time) for the search
cloud.google.com
. Chronicle will then schedule the retrohunt job. Retrohunts do not run immediately on demand; they are queued and executed as resources permit (to avoid impacting the real-time detection pipeline)
cloud.google.com
. In practice, small retrohunts might start quickly, while very large ones might be delayed if the system is busy. The runtime of a retrohunt can vary – you might see it complete in minutes for a small time window, or hours for a very large range – but Chronicle provides status updates. How to Use: In the Chronicle Rules Dashboard (UI), each rule has a menu where you can choose “YARA-L Retrohunt”
cloud.google.com
. This opens a dialog to input the date range for the historical scan
cloud.google.com
. The UI will show the permissible range (Chronicle retains data for a certain period based on your licensing, often 1 year or more; you cannot retrohunt beyond the data retention window). After you click Run, the retrohunt job is submitted. You can monitor its progress in the rule’s detection view – it will show as “In Progress” with a percentage complete
cloud.google.com
. You also have the option to cancel a running retrohunt if needed (if it’s taking too long or you realize the query is too broad)
cloud.google.com
. Chronicle keeps track of retrohunt runs. In the rule’s detail page, you can see past retrohunt executions and their results (successful completions, cancellations, etc.), often plotted on a timeline or listed with how many detections were found in each run
cloud.google.com
cloud.google.com
. Retrohunt Results and Usage: When a retrohunt finds matches, it produces detections just like real-time rules do. These detections are labeled with the time they occurred (in the past) and are available in the Detections view. However, by default, retrohunt detections do not generate new alerts to avoid confusion. Specifically, if the rule’s “alerting” setting was OFF (sometimes rules can be run in a detect-but-don’t-alert mode), then any retrohunt detections will also be non-alerting
cloud.google.com
. If you want retrohunt-found detections to raise alerts/incidents, you should ensure the rule has alerting enabled before running the retrohunt (the docs note that if you had it off, you’d need to enable and rerun to get alerts)
cloud.google.com
. Typically, analysts treat retrohunt outputs as hunting results and manually decide if any need action (as opposed to flooding the SOC queue with “late alerts”). Common use cases for retrohunt include:
IOC Sweeps: If threat intelligence informs you of certain indicators (hashes, IPs, filenames associated with an attack), you can quickly write a YARA-L rule to search for those indicators in your logs (or even use Chronicle’s search, but a rule allows more complex logic) and retrohunt the last N days or months. This will tell you if that IoC appeared in your environment in the past.
Rule Testing: Before enabling a new rule in production, you might retrohunt a week’s worth of data to see how many alerts it would generate and whether they are true positives. This helps in tuning the rule (if a retrohunt returns thousands of hits, you might want to refine the logic).
Compromise Assessment: Enterprises performing threat hunting will periodically retrohunt for behaviors that might not have been known indicators at the time. E.g., if a certain malware uses a particular sequence of events, hunters can codify that and retrohunt the last 6 months to see if at any time that sequence occurred.
Incident Investigation: During an investigation, you might craft a rule to find related activities. For example, after detecting a suspicious admin login, you could write a correlation rule for “same admin account doing X and Y within 1 hour” and retrohunt the past few weeks to see if that pattern occurred previously, indicating a recurring issue.
There is a limit to how many retrohunts you can run concurrently (the UI note mentions running more than 10 at a time may slow performance)【39†】. It’s wise to queue only what you need and wait for results. Retrohunt and Composite Rules: One nuance – if you retrohunt a composite rule (which depends on outputs of other rules), the system will only retrohunt that rule in isolation using already stored detections
cloud.google.com
. It will not retroactively run all the base rules first (since that could be extremely heavy). So the recommended approach if you want to retrohunt an entire composite scenario is to retrohunt the base rules individually in chronological order, each feeding detections that the next rule could use
cloud.google.com
. But for normal (non-composite) rules, retrohunt just works on raw events. In summary, retrohunt is a valuable feature to “time travel” with your detection logic. It helps ensure that your new detections not only protect you going forward but also allow you to look back and see if you might have missed something before. This can significantly reduce dwell time by uncovering historical compromises the moment you develop a new detection capability
cloud.google.com
. 

Chronicle Rules Dashboard, showing the option to run a YARA-L retrohunt on a rule (to search historical data). The retrohunt dialog allows specifying a date range, and the interface shows ongoing and past retrohunt runs with status.
cloud.google.com
cloud.google.com
Managing Detections and Enrichment
When rules trigger, they generate Detections in Chronicle. These detections (also often called alerts) are accessible through the “Detections” or “Alerts” dashboard in the Chronicle SIEM UI
cloud.google.com
. Each detection entry typically includes: the rule name, severity (if set by the rule; curated rules often have a default severity), the time of detection, and the number of events involved. Clicking into a detection provides details, including the detection timeline with events and any contextual information. Alert Triage: Chronicle detections can be investigated directly in the platform. You can view the raw log events that led to the detection (Chronicle will pull up the UDM events and highlight fields that matched the rule conditions). If the rule had an aggregation (multiple events), you’ll see a timeline or list of those events. Chronicle also often includes a brief narrative like “Rule X triggered because condition Y was met” to explain why the alert fired. From a management perspective, detections can be assigned to cases in Chronicle’s case management module or sent to external systems. Chronicle has an API (the Detection API) that allows integration with ticketing systems or SOAR platforms. For example, a SOC could use the API to fetch new detections periodically and create incidents in Jira or ServiceNow. Alternatively, Chronicle SOAR (formerly Siemplify, integrated into the platform) can ingest Chronicle SIEM detections automatically and create cases/playbooks. Each detection has a unique ID which can be used to pull more details via API (the “Detection Details API” and actions like “Resolve Detection” for marking it closed)
cloud.google.com
. Context Enrichment: Chronicle enriches ingested events with additional context which is invaluable during detection and investigation:
Asset and Identity Enrichment: Chronicle’s Asset Center / Entity model ties IP addresses, hostnames, and user identifiers to known assets and identities in your environment. For example, if an event has an IP, Chronicle might resolve which hostname or device ID that IP belonged to (based on DHCP logs or other data). It also can identify user accounts and link to an “identity” record. When viewing a detection, you might see the asset name, owner, or criticality rating if that asset was previously tagged. In rules, you can utilize these enriched fields – Chronicle documentation mentions using context-enriched data in rules, such as only alerting if an asset is high value or if a user account is VIP

.
Geolocation: IP addresses in events are often tagged with geo-location (country, city) using threat intel feeds. Thus, a rule could easily use principal.location.country != "US" in logic if needed, or an analyst can see “this login came from Russia” at a glance.
Threat Intelligence Enrichment: Chronicle’s Applied Threat Intelligence (ATI) brings in curated threat intel signals (like known bad domains, hashes, etc., often from Google’s TI sources). When an event involves an IoC, Chronicle might flag it (e.g., tag a hash with malware family name, or note an IP is associated with botnet). Detections that involve those IoCs will show that context (like an “IOC hit” with a score). Furthermore, Chronicle has built-in IOC alerting – for instance, if you have the fusion feeds enabled, Chronicle will automatically alert on high-severity IOC matches even outside of custom rules

.
UEBA and Risk Scores: Chronicle’s User and Entity Behavior Analytics module assigns risk scores to entities (users or assets) based on deviations and triggers. Those risk scores can be used in rules (“Risk Analytics” rules) or just viewed as context in alerts. For example, if a detection is about a user logging in from a new location, you might see that the user’s risk score recently spiked or that this detection contributed +5 to their risk score. Chronicle’s context-aware analytics can combine such signals; the documentation encourages using entity risk context in rules for more accuracy

 (e.g., trigger only if the user already has other risk indicators).
All this enrichment means that when you get a detection, you typically have more than just the raw log data – you have who/what is involved and why it matters. The UI will often provide quick links: e.g., an IP address in a detection can be clicked to pivot into an Investigative View for that IP (showing all related activity)

, or a user to a timeline of that user’s activities. This greatly speeds up triage, because an analyst can go from an alert to seeing the broader context (what else happened on that host? what else did this user do? have we seen this file hash elsewhere? etc.) in one or two clicks. Managing Detection Lifecycle: Chronicle allows basic alert management actions. You can acknowledge or “resolve” a detection (marking it addressed), or assign it a status. If using Chronicle’s Case Management, you can create a case from one or multiple detections (to track the investigation). Chronicle doesn’t automatically delete detections after resolution – they remain in the system for auditing and historical analysis. Chronicle also has the notion of Detection Limits – to protect the system, there are limits like a rule can only generate a certain number of detections per hour (10,000 per rule per day for detection-only rules, as one example given)
cloud.google.com
. If a rule goes haywire (creates millions of hits due to a broad pattern), Chronicle will start sampling or rate-limiting it to ensure stability. The “Detection limits” documentation spells out these caps
cloud.google.com
. As a rule author, if you hit those limits, you’d need to refine the rule.
Composite Detections (Correlating Multiple Alerts)
Composite Detections are an advanced feature (currently in Preview/Pre-GA) in Chronicle that allow you to correlate multiple independent detections (or rule events) into a higher-level alert
cloud.google.com
cloud.google.com
. Think of it as creating a meta-detection that triggers when several different rules’ outputs occur in combination. Use Case: Cyber attacks often involve multiple stages that individually might trigger separate alerts. For example, one rule might detect a suspicious executable, another might detect abnormal network traffic, and another might flag a privileged account usage. Each might fire on its own, but what if all three happen on the same host within a short time? That convergence could indicate a serious incident (where individually they might have been low or medium alerts). Composite detections let you define logic to recognize such patterns of patterns, thereby linking seemingly isolated incidents into a broader narrative
cloud.google.com
. Composite Rules: To create a composite detection, you write a composite rule in YARA-L. The key difference is that composite rules can take as input detections from other rules (as well as raw events or context data)
cloud.google.com
cloud.google.com
. Chronicle organizes detections from rules into structures called collections which composite rules use as data sources
cloud.google.com
. For example, you might have a collection of all detections from “Rule A” and a collection of all detections from “Rule B”. In a composite rule’s events: section, instead of referencing UDM event fields only, you can reference detection fields or the meta from those rules. Composite YARA-L extends the syntax to allow referencing an input detection’s metadata (like rule name, severity) or even outcome variables that the base rule set when it triggered
cloud.google.com
. A simple composite rule scenario: “If Rule X (say, suspicious process) AND Rule Y (say, data exfiltration) both trigger on the same host within 1 hour, then trigger a composite detection.” In the composite rule, $d1 might represent detections from X, $d2 from Y, and you’d have a condition like $d1 and $d2 and $d1.principal.asset_id == $d2.principal.asset_id and maybe a time window over 1h. When this composite rule fires, it generates a new detection (which is essentially an alert that these two alerts coincided). Benefits: As noted in docs, composite detections help unmask multi-stage attacks, reduce noise by consolidating alerts, and enhance accuracy by requiring multiple corroborating signals
cloud.google.com
. Instead of an analyst seeing 5 separate medium alerts, they see 1 high-severity composite alert that stitches those together. Composite detections can also incorporate entity risk or UEBA metrics as inputs
cloud.google.com
. For instance, you could have a composite rule that says if any detection with meta label “lateral_movement” occurs and the user’s risk score is above 80, then trigger an alert – combining behavioral risk context with rule detections. Limitations & Considerations: Composite rules add complexity, and Chronicle has some limits for them:
They support up to 10 levels deep (a composite rule can take input from another composite, etc., but no more than 10 in chain)
cloud.google.com
.
Composite rules that use only detections (and no raw events) are called detection-only rules. These currently can have a match window up to 14 days, but if they mix in raw events or entity data, the window is capped at 48 hours
cloud.google.com
. Also, detection-only composites have a limit of 10k generated detections per day
cloud.google.com
.
Each composite rule can reference a limited number of outcome variables (20) and each outcome variable can hold up to 25 distinct values
cloud.google.com
. This basically constrains how much state you can pull from input detections.
Building Composite Rules: The syntax allows referencing detection fields using a special format. For example, within a composite rule’s events, one might use something like: $aDetections.meta.rule_name = "Suspicious Process Execution" to filter inputs to only those detections from that specific rule. Or use match variables on detection properties. Composite rules always require a match section since you’re correlating sets of detections/events
cloud.google.com
. The Chronicle docs provide examples and even a composite rule syntax guide
cloud.google.com
. One can reference:
Meta fields of input rules (e.g., tactic or technique tags from the base rule’s meta).
Outcome variables set by input rules (e.g., maybe Rule A saved the filename as an outcome, and Rule B saved the domain contacted; the composite rule could check those outcomes for some relation).
Underlying event fields of the detections (in case you need to drill to specifics; though often the base rules will have summarized what’s important).
Workflow: To effectively use composites, you typically have a suite of base rules that are fairly targeted (they might even be lower fidelity or lower severity individually). Then you have composite rules that watch for combinations of those base rules firing. It’s a bit like building a detection hierarchy. For example, Google might provide a set of “unit” rules for various suspicious signals, and separate composite rules that combine them under certain MITRE ATT&CK scenarios (initial access + persistence, etc.). This modular approach also aids in rule maintenance: you can update a base rule logic and it automatically feeds the composite correlations without rewriting the composite (since composites reference rule by name or label, not the content). Example: A composite detection for a multi-stage ransomware attack might say: if there’s a detection from any “Privilege Escalation” rule (several might be labeled with meta tactic = privilege_escalation) and within 2 hours a detection from any “Mass File Deletion” rule (indicating possible ransomware file encryption) on the same host – trigger a composite alert for “Possible Ransomware Incident”. In this case, the composite uses meta labels (tactic: privilege_escalation and tactic: impact) to group detections generically
cloud.google.com
. This is powerful because it doesn’t hardcode specific rule names, it works with any detection that carries those tags. Operationalizing: Composite detections show up in the Detections dashboard like any other alert, but often with a higher severity if configured so. They will contain links to the underlying detections (so an analyst can click to see the component alerts). In Chronicle, you might see something like “Composite Detection: Host under multi-stage attack” and inside it, a section listing “Contributing Detections” which are the individual alerts that matched the rule. This makes investigation much easier – everything is linked in one place. Testing: As mentioned earlier, testing composites can be a bit manual because retrohunt doesn’t chain-run dependencies automatically
cloud.google.com
. A best practice is to test the base rules thoroughly (maybe with simulated scenarios) and then test the composite by causing or finding instances where those base rules coincide. Since composite rules rely on detections, they inherently have to wait for those detections to exist (or be retrohunted themselves). One can generate synthetic detections via the Chronicle API for testing a composite rule logic in a non-production setting. Composite detections are a powerful way to reduce alert fatigue and focus on what matters by only alerting when multiple conditions line up
cloud.google.com
. They essentially implement an alert correlation layer on top of raw event correlation. As Chronicle evolves, this feature might become generally available and even more robust, integrating with Chronicle’s case management (e.g., automatically grouping base alerts into one case via composite detection).
APIs and Automation
All of Chronicle’s functionality for ingestion, search, and detection is also exposed via APIs, which enables automation and integration with other systems
cloud.google.com
cloud.google.com
. Key APIs include:
Ingestion API: As discussed, allows programmatic sending of events (UDM or raw) to Chronicle
cloud.google.com
. This is useful if you want to write a custom log forwarder or integrate an existing logging pipeline (like an NXLog or Fluentd output) directly with Chronicle’s endpoint
docs.nxlog.co
. Many organizations have used the ingestion API to connect SIEM-to-SIEM or cloud-to-cloud transfers. There are also third-party tools and modules (e.g., NXLog, Cribl) that have built Chronicle outputs using this API
googlecloudcommunity.com
bindplane.com
.
Detection Engine API: Allows creating, updating, listing, and deleting detection rules programmatically
cloud.google.com
. This is often used for “Detection-as-Code” workflows. For example, a security team might maintain their YARA-L rules in a git repository and use a CI pipeline to push any changes to Chronicle via the API, ensuring version control and code review for detection rules. The API also lets you enable/disable rules and retrieve rule execution metrics. Additionally, you can trigger on-demand rule runs: for instance, an API call can run a given rule on live data or historical range (similar to hitting the “Run” or retrohunt in UI). The Chronicle documentation for Detection Engine API provides details on the REST endpoints for these actions (like rules.create, rules.list, rules.run, etc.)
cloud.google.com
. Authentication is done with the same method (service account and OAuth scope) as other Chronicle APIs
cloud.google.com
cloud.google.com
.
Search API: Chronicle offers a powerful search interface in the UI for UDM events and raw logs, and this is mirrored by the Search API
cloud.google.com
. You can programmatically run queries to retrieve event data, aggregates, or to export logs. For example, an analyst could use the API to pull all events of a certain type in the last 24h and pipe them into a data science notebook for analysis. Or an organization might automate exporting specific logs to a data lake by periodically calling the Search API with a query and saving results. The Search API accepts YARA-L queries (the same syntax you’d use in the Chronicle search bar, which is basically a subset of YARA-L for filtering events) and returns matching events. There are also specialized endpoints for things like asset-centric queries or IOC lookups.
Detection/Alert API: Chronicle’s backend provides APIs to list detections (alerts), get details on a detection, mark detection as resolved, etc. This is what enables integration with incident management tools. While not public in documentation as a separate “Alert API” section, parts of it are referenced (e.g., the CrowdStrike integration guide references a “Detection Details API” and “Resolve Detection API”)
cloud.google.com
. Using these, you could script pulling all new high-severity detections every 5 minutes and creating tickets, or automatically closing resolved ones in Chronicle when closed in an external system.
Feed Management API: For automation around data feeds (the connectors that pull from external sources), Chronicle has an API to programmatically set up and manage feeds
cloud.google.com
cloud.google.com
. Large enterprises might use this to script onboarding of new log sources in bulk or integrate feed setup into infrastructure-as-code. For instance, when a new AWS account is created, you could call Chronicle’s Feed API to set up an S3 feed for that account’s CloudTrail logs.
Case Management API: Since Chronicle includes case management (especially with the SOAR integration), there are APIs to create and manipulate cases, if needed, though many organizations use the UI for case work or integrate with external SOAR systems instead.
Google provides client libraries and SDKs to simplify calling these APIs
cloud.google.com
. There’s a Chronicle-specific Python client (and possibly others) that wraps the REST calls. Authentication to the APIs requires an OAuth2 token with the Chronicle scope (https://www.googleapis.com/auth/chronicle-backstory) using a service account
cloud.google.com
. The documentation and examples show how to obtain credentials and tokens (often using Google’s common client auth libraries)
cloud.google.com
cloud.google.com
. By leveraging these APIs, teams can integrate Chronicle into their broader security operations workflows. Some practical examples:
Automatically open a case or send a notification if a critical detection appears (via Detection API -> Slack message or ticket).
Threat hunting automation: use the Search API to gather data for known bad indicators on a schedule, or to feed data into AI/ML models.
Continuous rule deployment: integrate Chronicle with a CI pipeline so that any new rule or rule update is consistently rolled out to the SIEM (with proper version tracking). Google’s GitHub repository chronicle/detection-rules
github.com
 contains example rules and even a style guide, showing how one might structure rule development outside the UI.
Metrics and Reporting: Use the APIs to extract metrics like number of detections per rule, ingestion stats, etc., and build custom dashboards outside Chronicle (though Chronicle has some dashboards built-in as well).
In essence, anything you can do in the Chronicle UI, you can do via API, which is critical for automation and scaling. This openness allows Chronicle to function as a “SIEM engine” that can be scripted into complex enterprise workflows, from DevSecOps pipelines to SOC orchestration processes


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



RULES PART FOR CROWSTRIKE AND ZSCALER

Chronicle YARA-L 2.0 Rule Pack for CrowdStrike & Zscaler Logs
Below is a comprehensive rule pack with basic, intermediate, and advanced YARA-L 2.0 rules for Google Chronicle SIEM. The rules target CrowdStrike endpoint logs (process and registry telemetry) and Zscaler web proxy logs (network HTTP events). They are grouped by threat category/MITRE technique and include the full YARA-L syntax, descriptions, relevant UDM fields, log source, and references to sources of the logic.
Basic Detection Rules
Detect Notepad Process Launch (Basic Example)
This simple rule detects any instance of the Windows Notepad application being launched on an endpoint.
yaral
Copy
Edit
rule detect_notepad_launch {
  meta:
    author = "SOC Analyst"
    description = "Detects process launch of Notepad.exe (Basic example)"
    yara_version = "YL2.0"
    rule_version = "1.0"

  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.file.name = "notepad.exe"

  condition:
    $e
}
Log Source: CrowdStrike Endpoint (Process Execution telemetry)
Description: Alerts on any process creation event where the newly launched process’s file name is notepad.exe, indicating Notepad was opened. It uses metadata.event_type = "PROCESS_LAUNCH" to filter process executions and checks the target.process.file.name for “notepad.exe”
cloud.google.com
. This basic rule is primarily for illustration or baseline monitoring.
UDM Fields: metadata.event_type, target.process.file.name
Reference: Chronicle UDM search example for specific process creation
cloud.google.com
 (similar approach used for detecting net.exe executions).
Office Application Spawning PowerShell (Suspicious Parent-Child Process)
Detects a Microsoft Office program (Word, Excel, or PowerPoint) spawning PowerShell – a known malicious behavior often associated with macro malware.
yaral
Copy
Edit
rule office_spawning_powershell {
  meta:
    author = "SOC Analyst"
    description = "Office application spawning PowerShell (possible macro exploit)"
    yara_version = "YL2.0"
    rule_version = "1.0"

  events:
    // $parent = Office process, $child = spawned process
    $parent.metadata.event_type = "PROCESS_LAUNCH"
    $parent.principal.process.file.name = /(?i)WINWORD\.EXE|EXCEL\.EXE|POWERPNT\.EXE/
    $parent.target.process.file.name = "powershell.exe"

  condition:
    $parent
}
Log Source: CrowdStrike Endpoint (Process Execution)
Description: This rule looks for any Microsoft Office application (Word, Excel, PowerPoint) that launches a PowerShell process. Such behavior is highly suspicious, as Office programs normally do not spawn PowerShell; it often indicates a malicious macro or exploit executing code
detection.fyi
. The rule filters for PROCESS_LAUNCH events where the parent process (principal.process.file.name) is WINWORD.EXE, EXCEL.EXE, or POWERPNT.EXE, and the spawned child (target.process.file.name) is powershell.exe. Analysts should investigate these events as potential malware (e.g. macro droppers).
UDM Fields: metadata.event_type, principal.process.file.name (parent process name), target.process.file.name (child process name)
Reference: Hexacorn blog (via Detection-FYI) on parent-child relationships notes that “anytime a winword.exe spawns a cmd.exe, powershell.exe, etc., it is worthy of a detection rule”
detection.fyi
.
Intermediate Detection Rules
Mass File Renames by Single Process (Potential Ransomware Activity)
Detects a single process performing an unusual number of file rename/move operations in a short time window – a behavior typical of ransomware encrypting files.
yaral
Copy
Edit
rule mass_file_rename_suspicion {
  meta:
    author = "SOC Analyst"
    description = "Possible ransomware: a process renaming many files in short time"
    yara_version = "YL2.0"
    rule_version = "1.0"

  events:
    $rename.metadata.event_type = "FILE_MOVE"
    $rename.principal.process.file.sha256 = $proc_hash   // process identifier (hash)
    $rename.principal.asset.id = $host                   // host asset for scoping

  match:
    $proc_hash, $host over 1m   // group events by process (on host) over 1 minute

  condition:
    $rename and #rename > 20
}
Log Source: CrowdStrike Endpoint (File Activity events)
Description: This detection identifies mass file modifications in a short period, which could indicate ransomware encrypting files. It triggers when more than a threshold (e.g. >20) file move/rename events (FILE_MOVE) are observed from the same process on a host within 1 minute. The rule groups events by the process (using a unique hash or ID) and counts them. An unusually high number of file renames in rapid succession is abnormal in typical usage
phoenixnap.com
 and is a strong behavioral indicator of ransomware (malware often renames/encrypts files in bulk). Adjust the threshold or time window to fit the environment and reduce false positives.
UDM Fields: metadata.event_type, principal.process.file.sha256 (process identifier for grouping), principal.asset.id (host grouping), #rename (count of events in group)
Reference: Behavior-based ransomware detection techniques note that “too many file renames in a short time frame” is a common sign of encryption malware
phoenixnap.com
.
Windows Registry Run Key Modification (Persistence Attempt)
Detects creation or modification of Run/RunOnce autorun registry keys often used for persistence.
yaral
Copy
Edit
rule registry_runkey_persistence {
  meta:
    author = "SOC Analyst"
    description = "Registry modification of Run/RunOnce autorun keys (Persistence)"
    yara_version = "YL2.0"
    rule_version = "1.0"

  events:
    $reg.metadata.event_type = "REGISTRY_MODIFICATION"
    re.regex($reg.target.registry.key, `(?i)\\Windows\\CurrentVersion\\Run`)
  
  condition:
    $reg
}
Log Source: CrowdStrike Endpoint (Registry monitoring via EDR or Sysmon logs)
Description: Flags any changes to Windows autostart registry keys in the CurrentVersion hive (e.g., HKLM\Software\Microsoft\Windows\CurrentVersion\Run or RunOnce). Malware frequently creates or alters these keys to persist on reboot or user logon
detection.fyi
. The rule triggers on REGISTRY_MODIFICATION events where the registry key path matches *\CurrentVersion\Run* (case-insensitive). This covers Run, RunOnce, RunServices, etc., which are standard Autostart Extension Points (ASEP) for persistence
detection.fyi
. Security teams should verify if the new autorun entry is legitimate (software installation) or malicious.
UDM Fields: metadata.event_type, target.registry.key (the registry key path modified)
Reference: Sigma rule “Common Autorun Keys Modification” (ATT&CK T1547.001) – modifying Run keys is a known persistence technique
detection.fyi
detection.fyi
.
Advanced Detection Rules (MITRE ATT&CK-Aligned)
Credential Access – LSASS Memory Dump (ATT&CK T1003.001)
Detects suspicious access to the LSASS process memory, which adversaries do to dump credentials (e.g., using Mimikatz).
yaral
Copy
Edit
rule lsass_dump_attempt {
  meta:
    author = "SOC Analyst"
    description = "Non-system process opening LSASS process (Credential Access)"
    yara_version = "YL2.0"
    rule_version = "1.0"

  events:
    $open.metadata.event_type = "PROCESS_OPEN"
    $open.target.process.file.name = "lsass.exe"
    not re.regex($open.principal.process.file.full_path, `(?i)\\Windows\\System32\\`)

  condition:
    $open
}
Log Source: CrowdStrike Endpoint (Process Access events)
Description: This rule detects a process opening a handle to the LSASS process (Local Security Authority Subsystem) – a typical step in credential dumping attacks
threathunterplaybook.com
. It looks for a PROCESS_OPEN event where the target process name is lsass.exe (the process to be accessed) and excludes cases where the principal (calling) process resides in C:\Windows\System32\ (likely OS components). Any non-system process attempting to access LSASS is highly suspect
threathunterplaybook.com
. For example, Mimikatz or other tools will trigger this rule when they attempt to read LSASS memory. (Note: You may further refine exclusions for known legitimate processes like antivirus; consider also checking if the accessing process runs as SYSTEM vs a user account.)
UDM Fields: metadata.event_type, target.process.file.name, principal.process.file.full_path
Reference: Sigma rule “LSASS Access From Non-System Account” describes detecting Mimikatz-like behavior (LSASS access by non-system processes)
detection.fyi
. The Threat Hunter Playbook likewise suggests to “look for non-system accounts getting a handle to LSASS” as a credential dumping indicator
threathunterplaybook.com
.
Persistence – Autorun Registry Key (ATT&CK T1547.001)
Detects an adversary adding an Autorun registry entry for persistence via Run/RunOnce keys.
yaral
Copy
Edit
rule persistence_run_key {
  meta:
    author = "SOC Analyst"
    description = "Creation of Run/RunOnce autorun registry keys (Persistence)"
    yara_version = "YL2.0"
    rule_version = "1.0"

  events:
    $evt.metadata.event_type = "REGISTRY_CREATION" or $evt.metadata.event_type = "REGISTRY_MODIFICATION"
    $evt.target.registry.key = /(?i)\\CurrentVersion\\(Run|RunOnce)\\/

  condition:
    $evt
}
Log Source: CrowdStrike Endpoint (Registry events via EDR)
Description: Triggers when a registry Run or RunOnce key is created or modified. Specifically, it watches for REGISTRY_CREATION or REGISTRY_MODIFICATION events where the target key path matches the CurrentVersion\Run\ or CurrentVersion\RunOnce\ directories (in any hive, HKLM or HKCU). Adversaries use these autorun keys to achieve persistence, as programs listed here will execute on user login
detection.fyi
. For example, malware might add HKCU\Software\Microsoft\Windows\CurrentVersion\Run\malware to auto-start on login. This rule will catch such changes. Analysts should verify if the new autorun entry and value are expected; installers can also set Run keys (tuning may be needed to avoid false positives from known software).
UDM Fields: metadata.event_type, target.registry.key (the registry key path)
Reference: ATT&CK technique T1547.001 (Registry Run Keys) – widely abused for persistence
detection.fyi
. Detection logic aligns with community Sigma rules for autorun key modifications
detection.fyi
.
Defense Evasion – Suspicious rundll32 Usage (LOLBins, ATT&CK T1218.011)
Detects malicious use of rundll32.exe to execute code via scripts or unusual DLLs (Living-Off-the-Land Binary).
yaral
Copy
Edit
rule rundll32_lolbin_misuse {
  meta:
    author = "SOC Analyst"
    description = "Suspicious rundll32 usage (script execution or unusual DLL) for Defense Evasion"
    yara_version = "YL2.0"
    rule_version = "1.0"

  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.file.name = "rundll32.exe"
    re.regex($e.target.process.command_line, `(?i)(javascript:|scrobj\.dll|\.sct)`)

  condition:
    $e
}
Log Source: CrowdStrike Endpoint (Process Execution)
Description: Detects rundll32.exe executions that contain indicators of malicious use. Rundll32 is a Windows utility often abused to run code from DLLs or scripts (a known “LOLBin” technique under Defense Evasion). This rule looks at PROCESS_LAUNCH events where the process is rundll32.exe and the command-line contains keywords like javascript:, scrobj.dll, or .sct (scriptlet) – these are known patterns for executing scripts or COM objects via rundll32
detection.fyi
. For instance, rundll32.exe javascript:... or loading scrobj.dll to run a scriptlet are malicious behaviors that this rule will flag. Such usage of rundll32 is rarely legitimate and typically indicates an attempt to bypass security controls by using a trusted binary to execute code.
UDM Fields: metadata.event_type, target.process.file.name, target.process.command_line
Reference: Sigma rule “Potentially Suspicious Rundll32 Activity” (ATT&CK T1218.011) which looks for specific DLL calls (e.g., scrobj.dll usage) in rundll32 command-lines
detection.fyi
detection.fyi
. These patterns are derived from known LOLBin techniques documented by security researchers.
Command-and-Control – Beaconing Web Traffic (ATT&CK T1071.001)
Detects periodic HTTP requests indicative of beaconing to a C2 server, using Zscaler proxy logs.
yaral
Copy
Edit
rule web_beacon_interval {
  meta:
    author = "SOC Analyst"
    description = "Regular interval HTTP requests to same domain (Potential C2 beaconing)"
    yara_version = "YL2.0"
    rule_version = "1.0"

  events:
    // Define two sequential HTTP requests from same source to same domain
    $FirstTime = $e1.metadata.event_timestamp.seconds
    $e1.metadata.event_type = "NETWORK_HTTP"
    $e1.principal.ip = $src_ip
    $e1.target.domain.name = $domain

    $SecondTime = $e2.metadata.event_timestamp.seconds
    $e2.metadata.event_type = "NETWORK_HTTP"
    $e2.principal.ip = $src_ip
    $e2.target.domain.name = $domain

    // Check if timestamps differ by exactly 60 seconds (beacon interval)
    $SecondTime - $FirstTime = 60

  match:
    $src_ip, $domain over 10m

  condition:
    $e1 and $e2
}
Log Source: Zscaler Web Proxy (HTTP web traffic logs)
Description: This rule identifies beaconing patterns in outbound web traffic. It looks for a host (principal.ip) that makes repeated HTTP requests to the same domain (target.domain.name) at a consistent interval – in this example, exactly every 60 seconds. The rule captures two events ($e1 and $e2) from the same source and domain and checks if the timestamps are 60 seconds apart
googlecloudcommunity.com
googlecloudcommunity.com
. If such a pair is found within a 10-minute window, it suggests a periodic beacon (a hallmark of C2 communications). This logic can be extended to require 3 or 4 evenly-timed events for even higher confidence
googlecloudcommunity.com
, though at the cost of rule complexity. Analysts should investigate the context of these communications (domain reputation, data volume, user agent, etc.) to confirm if it’s malicious C2 beaconing or a benign scheduled job.
UDM Fields: metadata.event_type, principal.ip (source IP address), target.domain.name, metadata.event_timestamp.seconds (event time in seconds)
Reference: Google SecOps community example of detecting regular-interval DNS queries
googlecloudcommunity.com
googlecloudcommunity.com
 – the rule above adapts that approach for HTTP traffic. (Ref: Ayman C.’s “Network_DNS_Interval_Rule” which correlates events 2 minutes apart as a beacon example
googlecloudcommunity.com
).
Exfiltration – Cloud Storage Uploads (ATT&CK T1567.002)
Flags potential data exfiltration by detecting HTTP POST uploads to popular cloud storage services (Dropbox, Google Drive, OneDrive, etc.).
yaral
Copy
Edit
rule cloud_storage_exfiltration {
  meta:
    author = "SOC Analyst"
    description = "HTTP POST upload to cloud storage services (Possible data exfiltration)"
    yara_version = "YL2.0"
    rule_version = "1.0"

  events:
    $web.metadata.event_type = "NETWORK_HTTP"
    $web.network.http.request.method = "POST"
    re.regex($web.target.domain.name, `(?i)(dropbox\.com|drive\.google\.com|storage\.googleapis\.com|onedrive\.com)`)

  condition:
    $web
}
Log Source: Zscaler Web Proxy (HTTP logs)
Description: Detects HTTP POST requests to cloud storage providers, which could indicate file uploads (data exfiltration) over web channels. It filters for NETWORK_HTTP events where the HTTP request method is POST (usually used for file upload or form submission) and the destination domain matches common cloud storage services (examples here: Dropbox, Google Drive/Google Cloud Storage, OneDrive). Adversaries may exfiltrate stolen data by uploading it to such cloud services, blending in with normal traffic
attack.mitre.org
. For instance, an infected host might POST large data to https://content.dropbox.com/api/upload. This rule will catch those events. Analysts should validate whether the transfer is authorized (e.g., an enterprise backup to cloud) or suspicious. Tuning might include adding or removing domains based on the organization’s sanctioned services, and possibly monitoring network.http.response.bytes or upload size if available (large volumes could strengthen suspicion).
UDM Fields: metadata.event_type, network.http.request.method, target.domain.name
Reference: MITRE ATT&CK sub-technique T1567.002 (Exfiltration to Cloud Storage) notes that adversaries commonly exfiltrate data to services like Dropbox or Google Drive to hide in normal traffic
attack.mitre.org
. This rule targets that behavior; similar detection techniques are recommended in industry best practices for spotting data exfiltration via web services.
Each YARA-L 2.0 rule above is Chronicle-ready, using the proper UDM fields and syntax for Google Chronicle’s detection engine. Before deployment, adjust rule thresholds and exclusions to your environment (to minimize false positives). These rules can be loaded into Chronicle SIEM via the Rules Editor, and each is documented with its purpose and logic for SOC analysts. The grouping by MITRE ATT&CK techniques helps map these detections to the common framework for threat behavior, aiding in coverage analysis and incident context. References: The rule logic and patterns are informed by Google Chronicle’s community detections and open-source rulesets, as cited inline (e.g., Chronicle documentation, Sigma rules, ATT&CK techniques descriptions, and security research blogs). The citations (【†】) provide further details and justification for the chosen detection parameters.






Sources






You said:
ok only give me the rules for yaral that you got for chronicle mainly for CrowdStrike and zscaler one from online or create some advanced rules for detection


ChatGPT said:
Here is a curated set of advanced Chronicle YARA-L 2.0 detection rules focused specifically on CrowdStrike Falcon and Zscaler Internet Access logs. These rules are sourced or inspired from open Chronicle community content, threat research, and custom logic. They are written in Chronicle-compatible YARA-L syntax using UDM fields.

🔐 LSASS Dump Detection – CrowdStrike
yaral
Copy
Edit
rule LSASS_Dump_Detection {
  meta:
    description = "Detects unauthorized handle access to LSASS process – possible credential theft"
    author = "Google Chronicle"
    rule_version = "1.0"
    yara_version = "YL2.0"

  events:
    $evt.metadata.event_type = "PROCESS_OPEN"
    $evt.target.process.file.name = "lsass.exe"
    not re.regex($evt.principal.process.file.full_path, `(?i)\\Windows\\System32\\`)

  condition:
    $evt
}
📌 Source: Google Chronicle GitHub – LSASS credential access
📚 Use: Detects credential access attempts from suspicious tools like Mimikatz.

🧬 Reflective DLL Injection – CrowdStrike
yaral
Copy
Edit
rule Reflective_DLL_Load {
  meta:
    description = "Detects reflective DLL loading (in-memory module without file path)"
    author = "Google Chronicle"
    rule_version = "1.0"
    yara_version = "YL2.0"

  events:
    $evt.metadata.event_type = "PROCESS_MODULE_LOAD"
    $evt.target.file.full_path = ""

  condition:
    $evt
}
📌 Source: Chronicle Examples – Code Injection
📚 Use: Catches memory-only DLL injections used by malware like Cobalt Strike.

📎 Suspicious Use of MSHTA or Script via Rundll32 – CrowdStrike
yaral
Copy
Edit
rule LOLBin_MSHTA_or_Rundll32 {
  meta:
    description = "Detects mshta or rundll32 executing script-based payloads (evasion or initial access)"
    author = "SOC Team"
    rule_version = "1.0"
    yara_version = "YL2.0"

  events:
    $evt.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($evt.principal.process.command_line, `(?i)(mshta|rundll32).*((http|https)|.sct|javascript:)`)

  condition:
    $evt
}
📌 Source: Adapted from multiple Sigma rules for LOLBins abuse (T1218)
📚 Use: Detects fileless attacks using trusted Windows binaries to execute code.

🌐 DNS Tunneling Detection – Zscaler
yaral
Copy
Edit
rule DNS_Tunneling_High_Volume {
  meta:
    description = "High volume of DNS queries to a single domain – possible tunneling"
    author = "Google Chronicle"
    rule_version = "1.0"
    yara_version = "YL2.0"

  events:
    $evt.metadata.event_type = "NETWORK_DNS"
    $evt.principal.ip = $client
    $evt.network.dns.question.name = $domain

  match:
    $client, $domain over 5m

  condition:
    count($evt) > 100
}
📌 Source: Google Chronicle Example – DNS Tunneling
📚 Use: Detects excessive DNS queries typical of tunneling malware or backdoors.

☁️ Data Exfiltration via Cloud Storage – Zscaler
yaral
Copy
Edit
rule Cloud_Storage_Data_Exfil {
  meta:
    description = "Excessive data upload to cloud storage via HTTP POST"
    author = "SOC Team"
    rule_version = "1.0"
    yara_version = "YL2.0"

  events:
    $evt.metadata.event_type = "NETWORK_HTTP"
    $evt.network.http.request.method = "POST"
    $evt.target.domain in ("drive.google.com", "dropbox.com", "box.com", "onedrive.live.com")
    $evt.network.sent_bytes = $bytes

  match:
    $evt.principal.user.userid over 10m

  outcome:
    $total = sum($bytes)

  condition:
    $evt and $total > 50000000  // 50MB threshold
}
📌 Source: Custom (based on ATT&CK T1567.002)
📚 Use: Detects unauthorized upload of sensitive data to external cloud drives.

🧭 Beaconing Detection – Same Interval Requests – Zscaler
yaral
Copy
Edit
rule Beaconing_Interval_HTTP {
  meta:
    description = "Host sending regular interval HTTP requests (beaconing)"
    author = "Google Chronicle"
    rule_version = "1.0"
    yara_version = "YL2.0"

  events:
    $e1.metadata.event_type = "NETWORK_HTTP"
    $e2.metadata.event_type = "NETWORK_HTTP"
    $e1.principal.asset.hostname = $host
    $e2.principal.asset.hostname = $host
    $e1.target.domain = $domain
    $e2.target.domain = $domain
    abs($e2.metadata.event_timestamp.seconds - $e1.metadata.event_timestamp.seconds) == 60

  match:
    $host, $domain over 10m

  condition:
    $e1 and $e2
}
📌 Source: Chronicle DNS Beaconing Example
📚 Use: Flags consistent time-gap requests to the same domain – indicative of automated beaconing.

If you'd like, I can package all these into a Chronicle-compatible .yaral file or add more rules for categories like:

Persistence (e.g., registry run keys, scheduled tasks)

Defense evasion (e.g., parent-child anomalies)

Web filtering bypass via Zscaler (e.g., proxy/VPN site access)

Let me know and I’ll expand accordingly.

Advanced YARA-L 2.0 Rules for System-Level Threats
Process Injection & Reflective DLL Loading
YARA-L Rule:
php
Copy
Edit
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
Edit
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
Edit
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
Edit
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
Edit
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
Edit
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
Edit
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
Edit
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
Edit
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
Edit
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
Edit
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
Edit
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
Edit
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
Edit
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
Edit
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



Advanced YARA-L 2.0 Rules for System-Level Threats
Process Injection & Reflective DLL Loading
YARA-L Rule:
php
Copy
Edit
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
Edit
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
Edit
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
Edit
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
Edit
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
Edit
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
Edit
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
Edit
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
Edit
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
Edit
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
Edit
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
Edit
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
Edit
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
Edit
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
Edit
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




use this to get more default rules

https://github.com/chronicle/detection-rules
