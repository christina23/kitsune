# Kitsune

Quick like a fox and full of wisdom, Kitsune is an AI agent that automatically generates detection rules from threat intelligence reports using multiple LLM providers.

## Features

- **Multi-LLM Support**: Works with Anthropic Claude and OpenAI GPT models
- **Multiple Rule Formats**: Generates Splunk SPL and Sigma detection rules
- **Validated IOC/TTP Extraction**: Regex + LLM extraction with confidence scoring, deduplication, and MITRE ATT&CK validation
- **Coverage Gap Analysis**: Compares extracted techniques against generated rules and reports undetected TTPs with priority and recommended data sources
- **Redis Store**: Optional persistent IOC and detection rule store with actor/TTP indexing and trend analytics
- **Search UI**: Streamlit app for querying across IOCs, rules, actors, trends, and coverage gaps
- **REST API**: FastAPI backend with Scalar and Swagger interactive docs

## Web Interfaces

| Interface | URL | Description |
|-----------|-----|-------------|
| Search UI | `http://localhost:8501` | Streamlit app — search IOCs, rules, actors, trends, and coverage |
| Scalar API Docs | `http://localhost:8000/scalar` | Interactive API reference with Python code examples |
| Swagger UI | `http://localhost:8000/docs` | Classic Swagger UI with try-it-out support |

## Project Structure

```
kitsune/
├── main.py               # Main entry point
├── api.py                # FastAPI REST API
├── app.py                # Streamlit search UI
├── core/                 # Core library package
│   ├── __init__.py
│   ├── agent.py          # ThreatDetectionAgent class (LangGraph workflow)
│   ├── models.py         # Pydantic data models
│   ├── ioc_parser.py     # IOC + TTP extraction, validation, and confidence scoring
│   ├── coverage.py       # Coverage gap analysis
│   ├── config.py         # Configuration settings
│   ├── llm_factory.py    # LLM provider factory
│   ├── utils.py          # Utility functions
│   ├── prompts.py        # Prompt templates
│   ├── intel_store.py    # Redis-backed threat intel store
│   └── enrichment.py     # Rule and event enrichment helpers
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
└── output/               # Generated detection rules (created on first run)
    ├── anthropic/
    └── openai/
```

## Installation

### Docker (recommended)

```bash
git clone <repository-url>
cd kitsune
cp .env.copy .env
# Edit .env — add ANTHROPIC_API_KEY and/or OPENAI_API_KEY
docker compose up --build
```

Services start in order (Redis → API → UI). To stop: `docker compose down`
To stop and wipe Redis data: `docker compose down -v`

### Local

```bash
git clone <repository-url>
cd kitsune
poetry install --no-root
source $(poetry env info --path)/bin/activate
cp .env.copy .env
# Edit .env with your API keys
docker run -d --name kitsune-redis -p 6379:6379 redis:alpine
uvicorn api:app --reload --port 8000   # Terminal 1
streamlit run app.py                   # Terminal 2
```

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `LLM_PROVIDERS` | Comma-separated providers | `anthropic,openai` |
| `ANTHROPIC_API_KEY` | Anthropic API key | — |
| `OPENAI_API_KEY` | OpenAI API key | — |
| `ANTHROPIC_MODEL` | Anthropic model | `claude-sonnet-4-6` |
| `OPENAI_MODEL` | OpenAI model | `gpt-4o-mini` |
| `INTEL_URL` | Threat report URL to process | — |
| `RULE_FORMAT` | Output format: `spl`, `sigma`, or `both` | — |
| `REDIS_URL` | Redis connection URL | `redis://localhost:6379` |
| `REDIS_KEY_PREFIX` | Namespace prefix for Redis keys | `kitsune` |

## Usage

```bash
python main.py
```

Processes `INTEL_URL`, generates rules via all configured `LLM_PROVIDERS` in `RULE_FORMAT`, and saves output to `output/<provider>/`.

### Programmatic Usage

```python
from core.agent import ThreatDetectionAgent

agent = ThreatDetectionAgent(llm_provider="anthropic")
rules = agent.generate_detections("https://example.com/threat-report", rule_format="sigma")

for rule in rules:
    print(rule.name, rule.mitre_ttps)
```

## Extending

### Adding a New LLM Provider

1. Add the provider to `LLMProvider` enum in `core/models.py`
2. Add model/key config in `core/config.py`
3. Handle the new provider in `core/llm_factory.py`

### Customizing Prompts

Edit `core/prompts.py` to modify extraction and generation prompt templates.
