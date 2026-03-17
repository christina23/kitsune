"""
Prompt templates for the Threat Detection Agent
"""

# JSON formatting instructions specifically for Anthropic
JSON_FORMAT_INSTRUCTIONS_ANTHROPIC = (
    "CRITICAL: Your response must be ONLY a valid JSON object.\n"
    "Do not include ANY text before or after the JSON.\n"
    "Do not use markdown code blocks or backticks.\n"
    "Do not include explanations or comments outside the JSON.\n"
    "Start your response with { and end with }"
)

# Threat Intelligence Extraction
THREAT_INTEL_EXTRACTION_PROMPT = """\
You are a senior threat intelligence analyst specializing in \
extracting precise, actionable intelligence from security reports.

CRITICAL INSTRUCTIONS:
- Extract EXACT names, codes, and identifiers from the source \
text - do not paraphrase or generalize
- For threat actors, use the EXACT designation \
(e.g., "UNC6395", "APT29", "Lazarus Group")
- For MITRE TTPs, extract the exact technique IDs mentioned \
(format: T####.###)
- For MITRE TTPs: prefer sub-technique IDs (T####.###) over parent \
(T####) when the report provides enough specificity. E.g. prefer \
T1059.001 (PowerShell) over T1059.
- Only include TTPs directly evidenced in the text — do not infer \
beyond what is stated.
- For IOCs, extract specific values (IPs, domains, file hashes, \
file names)
- For targeted systems, be specific (e.g., "Salesforce instances", \
"Office 365 tenants", not just "cloud services")
- For key behaviors, describe specific TTPs and attack methods mentioned

Return ONLY valid JSON in this exact format:
{
  "threat_actor": "exact actor name from text or null",
  "campaign_name": "exact campaign name from text or null",
  "mitre_ttps": ["T1005", "T1020.001"],
  "iocs": {
    "ips": ["1.2.3.4"],
    "domains": ["malicious.com"],
    "hashes": ["abc123def456"],
    "files": ["malware.exe"],
    "urls": ["http://bad.com/path"]
  },
  "attack_description": "detailed description of the attack methodology",
  "targeted_systems": ["specific systems/platforms mentioned"],
  "key_behaviors": ["specific attack techniques and behaviors"]
}

Extract information PRECISELY as written in the source. Do not add \
interpretations."""

# SPL Rule Generation
SPL_GENERATION_PROMPT = """\
You are a senior detection engineer creating high-fidelity \
Splunk SPL detection rules.

THREAT CONTEXT:
- Threat Actor: {threat_actor}
- Campaign: {campaign_name}
- MITRE ATT&CK TTPs: {mitre_ttps}
- Attack Description: {attack_description}
- Key Behaviors: {key_behaviors}
- Targeted Systems: {targeted_systems}
- IOCs Available: {iocs}

REQUIREMENTS FOR HIGH-QUALITY RULES:
1. Create 4-6 DISTINCT detection rules covering different attack phases
2. Use specific field names and log sources appropriate to the targeted systems
3. Include statistical analysis (stats, rare, outlier detection) where \
appropriate
4. Incorporate specific IOCs when available
5. Add contextual comments explaining detection logic
6. Use proper Splunk functions (eval, rex, lookup, etc.)
7. Include time-based analysis for behavioral detection

Rule naming convention: "[Actor]_[Behavior]_[System]_Detection"

{json_format_section}

Return ONLY this JSON structure:
{{
  "rules": [
    {{
      "name": "UNC6395_Data_Exfiltration_Salesforce_Detection",
      "description": "Detects abnormal data exfiltration from Salesforce \
instances",
      "rule_content": "index=salesforce sourcetype=salesforce:api | \
stats sum(bytes_out) as total_bytes by user | where total_bytes > \
1000000000",
      "mitre_ttps": ["T1020", "T1074"]
    }},
    {{
      "name": "UNC6395_Credential_Access_Cloud_Detection",
      "description": "Identifies potential credential harvesting activities",
      "rule_content": "index=cloud_logs (action=login OR action=auth) \
| stats count by src_ip user | where count > 100",
      "mitre_ttps": ["T1110", "T1078"]
    }}
  ]
}}"""

# Sigma Rule Generation
SIGMA_GENERATION_PROMPT = """\
You are a senior detection engineer specializing in Sigma rule development.

THREAT CONTEXT:
- Threat Actor: {threat_actor}
- Campaign: {campaign_name}
- MITRE ATT&CK TTPs: {mitre_ttps}
- Attack Description: {attack_description}
- Key Behaviors: {key_behaviors}
- Targeted Systems: {targeted_systems}
- IOCs Available: {iocs}

SIGMA RULE REQUIREMENTS:
1. Create 4-6 DISTINCT Sigma rules for different detection angles
2. Use appropriate log sources (process_creation, network_connection, \
file_event, etc.)
3. Include specific selection criteria based on the threat behavior
4. Add proper MITRE ATT&CK tags (attack.t####)
5. Set appropriate severity levels (critical, high, medium)
6. Include condition logic (1 of selection, all of them, etc.)
7. Add relevant false positive filters where appropriate

{json_format_section}

Return ONLY this JSON structure:
{{
  "rules": [
    {{
      "name": "UNC6395 Cloud Data Exfiltration Detection",
      "description": "Detects potential data exfiltration from cloud services",
      "rule_content": "title: UNC6395 Cloud Data Exfiltration\\nid: \
abc123\\nstatus: experimental\\nlogsource:\\n  service: cloudtrail\
\\ndetection:\\n  selection:\\n    eventName: GetObject\\n    \
requestParameters.bucketName: '*sensitive*'\\n  condition: \
selection\\nlevel: high\\ntags:\\n  - attack.t1020",
      "mitre_ttps": ["T1020"]
    }},
    {{
      "name": "UNC6395 Suspicious Authentication Pattern",
      "description": "Identifies abnormal authentication patterns \
indicative of credential abuse",
      "rule_content": "title: UNC6395 Auth Pattern\\nid: def456\
\\nlogsource:\\n  product: azure\\ndetection:\\n  selection:\
\\n    EventID: 4625\\n  condition: selection\\nlevel: medium",
      "mitre_ttps": ["T1078"]
    }}
  ]
}}"""
