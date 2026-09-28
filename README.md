# Wazuh-Shuffle SOC Pipeline

An automated, defense-in-depth pipeline for a small-to-mid Windows infrastructure (up to ~40 endpoints), built entirely on self-hosted, open-source components: **Wazuh** (SIEM/XDR), **Sysmon** (endpoint telemetry), **YARA** (local signature detection), **Shuffle** (SOAR orchestration), and a **locally hosted Ollama LLM** (incident summarization). Detection and containment happen automatically, based on fixed rules and thresholds, never on LLM judgment. The LLM is used only to summarize confirmed incidents for the SOC.


**Privacy-first by design.** No file content, alert data, or telemetry leaves the local network at any point in the pipeline. VirusTotal lookups query only file hashes, never file content. The Ollama server has no outbound internet access after initial model setup, and its inference API is reachable exclusively from the Shuffle server.


## Architecture Overview

This project has two main parts: `visibility & enrichment`, and `automated detection & active-response`.
Wazuh is the SIEM/XDR core. Endpoint visibility is enriched by Sysmon and GPO Audit Policies, which feed Wazuh with advanced telemetry (process creation, PowerShell execution, network connections). Automated detection and active-response are handled by YARA and Shuffle, which operate independently of each other: YARA detects and contains threats locally, on the endpoint, while Shuffle handles the cases that need external enrichment or cross-alert correlation before a containment decision can be made.


## Module Breakdown

| # | Module | Covers | README |
|---|---|---|---|
| 1 | **Wazuh Deployment** | All-in-one Wazuh Manager/Indexer/Dashboard sizing, install method, network ports | [`01_README.md`](./01_Wazuh_Infrastructure_Deployment/01_README.md) |
| 2 | **Endpoint Visibility & Telemetry** | GPO advanced audit policy, Sysmon deployment, Wazuh agent rollout, centralized `agent.conf` | [`02_README.md`](./02_Endpoint_Visibility_&_Telemetry_Enrichment/02_README.md) |
| 3 | **YARA Detection & Active Response** | Valhalla rule feed, `yara.bat` Wazuh↔YARA bridge, FIM configuration, local quarantine on YARA match | [`03_README.md`](./03_YARA%20Malware_Detection_&_Active-Response/03_README.md) |
| 4 | **Shuffle SOAR Integration** | VirusTotal enrichment, multi-stage attack correlation, Ollama-generated SOC reports, quarantine confirmation loop | [`04_README.md`](./04_SOAR_Orchestration&AI_Analysis/04_README.md) |

Each module README documents its own hardware sizing, trade-offs, and — where relevant — a Proof of Concept with screenshots.


## Design Principles

- **Triage is deterministic, never LLM-based.** The malware/clean/unknown/error classification (VirusTotal threshold check) and the attack-chain correlation (shared hash, file, process lineage, destination IP) are both pure logic. The LLM is invoked after a verdict already exists. Its only job is turning structured data into a readable narrative, never producing the verdict itself.
- **Analysis stays local.** Ollama has no outbound internet access once provisioned. VirusTotal is the only external call anywhere in the pipeline, and it only ever gets a file hash, never file content.
- **Three detection and response lines are followed.** The first line is YARA: a signature match is quarantined synchronously by the agent itself, no round-trip to Shuffle needed. The second line is Shuffle acting on a confirmed VirusTotal hash match, for files YARA didn't catch. The quarantine action is done through the same Wazuh Active Response mechanism, just triggered remotely via API instead of locally. The third line is Shuffle's own correlation engine, for files with no signature match and no VirusTotal detection: it cross-references the file's activity against other alerts from the same endpoint to catch multi-stage attack behavior. This evidence is circumstantial rather than 100% confirmation, so this line stops at a report and hands the decision to a human analyst instead of acting automatically.
- **Error handling depends on what's downstream.** Nodes that raise on failure (the Indexer query, the correlation engine) are configured to send their error via a different email path as a SOC alert. By default Shuffle nodes that raise errors stop their outgoing connection from firing and go silent unless the failures are explicitly routed to the SOC. Nodes whose only output is the SOC email itself (the quarantine dispatcher, the YARA report generator) catch their own failures instead and still send that email, with the error in their corresponding fields.

## Platforms & Tools

| Component | Role | Version / Notes |
|---|---|---|
| Wazuh | SIEM / XDR, FIM, Active Response engine | 4.14.3, all-in-one, Ubuntu 22.04.5 LTS |
| Sysmon | Kernel-level endpoint telemetry (process, network, hashing) | SwiftOnSecurity config, deployed via GPO |
| YARA | Local signature-based file scanning | Rules synced from the Valhalla API (Nextron Systems) |
| Shuffle | SOAR orchestration | 2.2.1, self-hosted via Docker Compose |
| Ollama | Local LLM inference for incident summarization | `llama3:latest`, CPU inference, no GPU |
| VirusTotal | External hash-reputation lookup | Public API, hash-only queries |

