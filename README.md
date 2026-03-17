# Kitsune

Quick like a fox and full of wisdom, Kitsune is an AI agent that automatically generates detection rules from threat intelligence reports using multiple LLM providers.

## Features

- **Multi-LLM Support**: Works with Anthropic Claude and OpenAI GPT models
- **Multiple Rule Formats**: Generates both Splunk SPL and Sigma detection rules
- **Robust JSON Handling**: Special handling for Anthropic's response format with automatic fixing
- **Validated IOC Extraction**: Regex-based extraction and validation for IPs, domains, hashes, URLs, and file names — merges LLM output with regex findings and deduplicates
- **Validated TTP Extraction**: MITRE ATT&CK technique IDs are validated against regex patterns, confidence-scored (1.0 if found verbatim in text, 0.85 if LLM-only, 0.7 if regex-only), and deduplicated; sub-techniques preferred over parent IDs
- **Coverage Gap Analysis**: After rule generation, compares extracted techniques against the generated rules and reports which TTPs have no detection coverage, with priority (high/medium/low) and recommended data sources
- **Author Attribution**: Automatically attributes rules based on the source
- **Error Recovery**: Fallback mechanisms ensure you always get usable output
- **Redis Store**: Optional persistent IOC and detection rule store backed by Redis, with actor/TTP indexing and trend analytics
- **Search UI**: Streamlit app for querying the store across IOCs, rules, actors, trends, and coverage gaps
- **REST API**: FastAPI backend with Scalar and Swagger interactive docs

## Web Interfaces

Kitsune includes a search UI and REST API for querying the Redis store interactively.

| Interface | URL | Description |
|-----------|-----|-------------|
| **Search UI** | `http://localhost:8501` | Streamlit app — search IOCs, rules, actors, trends, and coverage. API doc links are in the collapsible left sidebar. |
| **Scalar API Docs** | `http://localhost:8000/scalar` | Interactive API reference with Python `requests` code examples and built-in dark/light mode. |
| **Swagger UI** | `http://localhost:8000/docs` | Classic Swagger UI with dark mode toggle and try-it-out support. |

### Running the interfaces

```bash
# Terminal 1 — REST API (required by the UI)
uvicorn api:app --reload --port 8000

# Terminal 2 — Search UI
streamlit run app.py
```

> **Note:** Set `REDIS_URL` in your `.env` (e.g. `REDIS_URL=redis://localhost:6379`) before starting the API, otherwise query endpoints will return 503.

## Project Structure

```
kitsune/
├── main.py           # Main entry point
├── agent.py          # Core ThreatDetectionAgent class (LangGraph workflow)
├── models.py         # Pydantic data models (ThreatIntelligence, DetectionRule, CoverageGap, AgentState)
├── ioc_parser.py     # Regex IOC + TTP extraction, validation, and confidence scoring
├── coverage.py       # Coverage gap analysis (techniques vs generated rules)
├── config.py         # Configuration settings
├── llm_factory.py    # LLM provider factory
├── utils.py          # Utility functions
├── prompts.py        # Prompt templates
├── api.py            # FastAPI REST API (Scalar + Swagger docs)
├── app.py            # Streamlit search UI
├── Dockerfile        # Container image definition
├── docker-compose.yml# Orchestrates Redis, API, and UI services
├── pyproject.toml    # Python project metadata and dependencies (Poetry)
├── poetry.lock       # Pinned dependency versions
├── .env              # Environment variables (copy from .env.copy)
└── output/           # Generated detection rules (created by running `main.py`)
    ├── anthropic/
    └── openai/
```

## Installation

### Docker (recommended)

The easiest way to run Kitsune — no Python environment needed.

1. **Clone the repository**:
```bash
git clone <repository-url>
cd kitsune
```

2. **Configure environment variables**:
```bash
cp .env.copy .env
# Edit .env — add your ANTHROPIC_API_KEY and/or OPENAI_API_KEY
```

3. **Build and start all services**:
```bash
docker compose up --build
```

That's it. Services start in order (Redis → API → UI):

| Service | URL |
|---------|-----|
| Search UI | http://localhost:8501 |
| Scalar API Docs | http://localhost:8000/scalar |
| Swagger UI | http://localhost:8000/docs |

To stop: `docker compose down`
To stop and wipe Redis data: `docker compose down -v`

---

### Local (manual)

1. **Clone the repository**:
```bash
git clone <repository-url>
cd kitsune
```

2. **Install dependencies**:
```bash
poetry install --no-root
poetry env activate
source ~/.venv/bin/activate
```

3. **Configure environment variables**:
```bash
cp .env.copy .env
# Edit .env with your API keys
source .env
```

4. **Start Redis** (if not already running):
```bash
docker run -d --name kitsune-redis -p 6379:6379 redis:alpine
```

5. **Start the API and UI** (two terminals):
```bash
# Terminal 1
uvicorn api:app --reload --port 8000

# Terminal 2
streamlit run app.py
```

## Configuration

### Environment Variables

- `LLM_PROVIDERS`: Comma-separated list of providers (e.g., "anthropic,openai")
- `ANTHROPIC_API_KEY`: Your Anthropic API key
- `OPENAI_API_KEY`: Your OpenAI API key
- `ANTHROPIC_MODEL`: Anthropic model to use (default: `claude-sonnet-4-6`)
- `OPENAI_MODEL`: OpenAI model to use (default: `gpt-4o-mini`)
- `INTEL_URL`: URL of the threat intelligence report to process
- `RULE_FORMAT`: Output format - "spl", "sigma", or "both"
- `REDIS_URL`: Redis connection URL (default: `redis://localhost:6379`) — enables persistent store, search UI, and API
- `REDIS_KEY_PREFIX`: Namespace prefix for Redis keys (default: `kitsune`)

### Example .env file

```bash
LLM_PROVIDERS=anthropic,openai
ANTHROPIC_API_KEY=...
OPENAI_API_KEY=...
INTEL_URL=https://example.com/threat-report
RULE_FORMAT=sigma
REDIS_URL=redis://localhost:6379
```

## Quick Start

### Basic Setup

1. Unzip repo
2. Run `poetry env activate`
3. Copy last line's output from above, something like `source '~/.venv/bin/activate'`
4. Run `poetry install --no-root`
5. Run `python main.py`

<details>
<summary>Expected Output</summary>

Upon running `main.py`, you should see this output upon successful run (takes a min):

```
============================================================
THREAT DETECTION AGENT
============================================================
Using providers: anthropic, openai
Processing URL: https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift
Rule formats: sigma
============================================================
Generating rules with provider: ANTHROPIC
============================================================
[ANTHROPIC] Generating Sigma rules...
Fetched 10606 characters from URL
Extracted threat intel for: UNC6395
Generated 6 Sigma rules
[ANTHROPIC] Wrote 6 Sigma rule file(s) to output/anthropic:
  - UNC6395_OAuth_Token_Abuse_Salesforce_Detection.txt
  - UNC6395_Bulk_Data_Export_Salesforce_Detection.txt
  - UNC6395_Credential_Harvesting_Search_Detection.txt
  - UNC6395_Abnormal_API_Access_Pattern_Detection.txt
  - UNC6395_Cross_Platform_Token_Reuse_Detection.txt
  - UNC6395_Third_Party_App_Privilege_Escalation_Detection.txt
============================================================
Generating rules with provider: OPENAI
============================================================
[OPENAI] Generating Sigma rules...
Fetched 10606 characters from URL
Extracted threat intel for: UNC6395
Generated 6 Sigma rules
[OPENAI] Wrote 6 Sigma rule file(s) to output/openai:
  - UNC6395_Data_Exfiltration_Salesforce_Detection.txt
  - UNC6395_OAuth_Token_Abuse_Salesforce_Detection.txt
  - UNC6395_Credential_Access_Cloud_Detection.txt
  - UNC6395_Sensitive_Data_Search_Salesforce_Detection.txt
  - UNC6395_Anomalous_User_Activity_Salesforce_Detection.txt
  - UNC6395_Excessive_API_Calls_Salesforce_Detection.txt
============================================================
RULE GENERATION COMPLETE!
============================================================
Output directory: output/
Check each provider subdirectory for generated rules.
```
</details>

## Usage

### Basic Usage

```bash
python main.py
```

This will:
1. Process the URL specified in `INTEL_URL`
2. Use all providers listed in `LLM_PROVIDERS`
3. Generate rules in the format specified by `RULE_FORMAT`
4. Save outputs to `output/<provider>/`

### Programmatic Usage

```python
from agent import ThreatDetectionAgent

agent = ThreatDetectionAgent(llm_provider="anthropic")

url = "https://example.com/threat-report"
rules = agent.generate_detections(url, rule_format="spl")

for rule in rules:
    print(f"Rule: {rule.name}")
    print(f"Author: {rule.author}")
    print(f"MITRE TTPs: {', '.join(rule.mitre_ttps)}")
    print(f"Content:\n{rule.rule_content}\n")
```

### Custom Configuration

```python
from agent import ThreatDetectionAgent

agent = ThreatDetectionAgent(
    llm_provider="openai",
    llm_model="gpt-4",
    temperature=0.2,
    api_keys={"openai": "your-api-key"}
)
```

## Output Format

Generated rules are saved as text files in the output directory:

```
output/
├── anthropic/
│   ├── UNC6395_Data_Exfiltration_Detection.txt
│   └── UNC6395_Credential_Harvesting_Detection.txt
└── openai/
    └── ...
```

Each rule file contains:
- Rule metadata (name, author, date, description)
- MITRE ATT&CK TTPs
- Detection logic (SPL or Sigma format)

## Error Handling

The agent includes multiple layers of error handling:

1. **JSON Extraction**: Robust parsing that handles malformed responses
2. **Retry Logic**: Automatic retries with exponential backoff
3. **Fallback Rules**: Basic rules generated if LLM fails
4. **Provider Isolation**: Failures in one provider don't affect others

## Extending the Agent

### Adding a New LLM Provider

1. Update `models.py`:
```python
class LLMProvider(Enum):
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    NEWPROVIDER = "newprovider"  # Add your provider
```

2. Update `config.py`:
```python
LLMProvider.NEWPROVIDER: {
    "model": os.getenv("NEWPROVIDER_MODEL", "default-model"),
    "api_key_env": "NEWPROVIDER_API_KEY",
    "max_tokens": 4096,
}
```

3. Update `llm_factory.py` to handle the new provider.

### Customizing Prompts

Edit `prompts.py` to modify the extraction and generation prompts:

```python
CUSTOM_PROMPT = """Your custom prompt template here...
{variable_to_inject}
..."""
```

## Troubleshooting

### Common Issues

1. **JSON Parsing Errors with Anthropic**:
   - The agent includes special handling for Anthropic's responses
   - Check `utils.extract_json_from_text()` for the extraction logic

2. **No Rules Generated**:
   - Check that the URL is accessible
   - Verify API keys are valid
   - Enable debug mode: `DEBUG=true python main.py`

3. **Rate Limiting**:
   - Adjust retry delays in `config.Settings`
   - Use fewer providers simultaneously

4. **Redis / API unavailable**:
   - Ensure Redis is running: `docker run -d --name kitsune-redis -p 6379:6379 redis:alpine`
   - Confirm `REDIS_URL` is set in `.env` and the API was started from the `kitsune/` directory
   - Run the API as: `cd kitsune && uvicorn api:app --reload --port 8000`
