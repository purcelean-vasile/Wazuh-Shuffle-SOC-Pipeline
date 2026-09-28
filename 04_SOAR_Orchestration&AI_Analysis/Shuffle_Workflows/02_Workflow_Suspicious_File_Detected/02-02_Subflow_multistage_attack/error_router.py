"""
Node: Error Router (Subflow 2 - Multistage Attack Correlation).

Node 2 (Related Alerts Query) and Node 3 (Attack Chain Correlation) are
the only nodes on this branch that raise on failure - Shuffle then
exposes the exception message on <node_name>.message.error. This node's
only job is to identify which of the two failed and forward that detail,
unchanged, to the shared Error Email node.

Requires these Shuffle variables:
    $related_alerts_query.message.error
    $attack_chain_correlation.message.error
"""

import json

related_alerts_error = r"""$related_alerts_query.message.error"""
attack_correlation_error = r"""$attack_chain_correlation.message.error"""

# Checked in execution order: if Node 2 failed, Node 3 never ran, so its
# error field is empty - only one of the two can be non-empty at a time.
if related_alerts_error and related_alerts_error.strip():
    failed_node = "Related Alerts Query"
    error_text  = related_alerts_error
elif attack_correlation_error and attack_correlation_error.strip():
    failed_node = "Attack Chain Correlation"
    error_text  = attack_correlation_error
else:
    failed_node = "Unknown"
    error_text  = "No error details captured."

print(json.dumps({
    "failed_node": failed_node,
    "error_text":  error_text,
}))