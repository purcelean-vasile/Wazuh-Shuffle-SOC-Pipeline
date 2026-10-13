"""
Node: VirusTotal Verdict.
 
Determines whether a file flagged by Wazuh's FIM (File Integrity
Monitoring) module is a confirmed malware sample, based on a VirusTotal
hash lookup performed by the preceding node in this workflow.
 
This node performs classification only; it does not take any remediation
action. The Shuffle workflow's conditional branches (configured on the
canvas) route execution downstream based on the "verdict" field:
    - "malware": routed to the quarantine sub-workflow (Subflow 1).
    - "clean" / "unknown": routed to the behavioral correlation
      sub-workflow (Subflow 2).
    - "error": routed to the behavioral correlation sub-workflow (Subflow 2),
    same target as clean/unknown.
    
Requires these Shuffle variables:
    $exec.all_fields.agent.id / .name / .syscheck.path
    $virustotal_enrichment.body.data.attributes.last_analysis_stats.malicious
    $virustotal_enrichment.status
"""

import json

MALICIOUS_THRESHOLD = 4  # detections >= this value are treated as confirmed malware

agent_id             = r"""$exec.all_fields.agent.id"""
agent_name           = r"""$exec.all_fields.agent.name"""
file_path            = r"""$exec.all_fields.syscheck.path"""
malicious_count_raw  = r"""$virustotal_enrichment.body.data.attributes.last_analysis_stats.malicious"""
vt_status_code_raw   = r"""$virustotal_enrichment.status"""


# ═══════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════
try:
    # Shuffle variable substitution is always text-based; convert
    # defensively in case either value arrives as non-numeric text.
    try:
        vt_status_code = int(vt_status_code_raw.strip())
    except (ValueError, AttributeError):
        vt_status_code = 0
 
    try:
        malicious_count = int(malicious_count_raw.strip())
    except (ValueError, AttributeError):
        malicious_count = 0
 
    # Verdict is derived from the HTTP status code first, not merely from
    # whether "malicious_count" happened to parse. Previously, any non-200
    # response (401/403 auth failure, 429 rate limit, 5xx VT outage) fell
    # through to "clean" by default, because a missing malicious_count
    # parsed as 0 - a scan that never ran looked identical to a scan that
    # came back with zero detections. That silent misclassification is
    # the bug this branch fixes.
    error_reason = ""
 
    if vt_status_code == 200:
        # A 404 is distinct from "0 detections": 404 means the hash was
        # never submitted to VT (could still be a novel sample), while 0
        # detections means the hash is known and confirmed clean. Both
        # ultimately route to correlation, but the report should not
        # conflate them.
        verdict = "malware" if malicious_count >= MALICIOUS_THRESHOLD else "clean"
    elif vt_status_code == 404:
        verdict = "unknown"
    else:
        # 401/403 (invalid or expired API key), 429 (rate limited), 5xx
        # (VT unavailable), or 0 (status field failed to parse) - the
        # lookup did not complete, so the file cannot be classified.
        verdict = "error"
        if vt_status_code == 401 or vt_status_code == 403:
            error_reason = f"VirusTotal auth failure (HTTP {vt_status_code}) - check API key."
        elif vt_status_code == 429:
            error_reason = "VirusTotal rate limit exceeded (HTTP 429)."
        elif vt_status_code == 0:
            error_reason = "VT status code missing or non-numeric - enrichment node may have failed."
        else:
            error_reason = f"Unexpected VirusTotal response (HTTP {vt_status_code})."
 
    result = {
        "status":          "ok",
        "verdict":         verdict,
        "malicious_count": malicious_count,
        "vt_status_code":  vt_status_code,
        "threshold":       MALICIOUS_THRESHOLD,
        "agent_id":        agent_id,
        "agent_name":      agent_name,
        "file_path":       file_path,
        # Always present (empty string when verdict != "error"), so the
        # downstream email node can reference $...verdict_node.error
        # unconditionally regardless of which failure path produced it.
        "error":           error_reason,
    }
 
    # Printed output becomes this node's result, consumed by the
    # workflow's conditional branches and by downstream sub-workflows.
    print(json.dumps(result, default=str))
 
except Exception as e:
    # Reached only for unexpected failures outside the status-code logic
    # above (e.g. json.dumps itself failing). Kept as a final safety net,
    # not the primary source of "error" verdicts anymore.
    print(json.dumps({
        "status":          "error",
        "error":           str(e),
        "verdict":         "error",
        "malicious_count": 0,
        "vt_status_code":  0,
        "threshold":       MALICIOUS_THRESHOLD,
        "agent_id":        agent_id,
        "agent_name":      agent_name,
        "file_path":       file_path,
    }))
    raise
