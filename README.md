# Kitsune

Quick like a fox and full of wisdom, Kitsune is an AI agent that automatically generates detection rules from threat intelligence reports using multiple LLM providers.

## Features

- **Multi-LLM Support**: Works with Anthropic Claude and OpenAI GPT models
- **Multiple Rule Formats**: Generates Splunk SPL and Sigma detection rules
- **Validated IOC/TTP Extraction**: Regex + LLM extraction with confidence scoring, deduplication, and MITRE ATT&CK validation
- **Coverage Gap Analysis**: Compares extracted techniques against generated rules and reports undetected TTPs with priority and recommended data sources
- **Baseline Sigma Corpus**: Loads a local directory or private GitHub repo of sigma rules at startup; every analyze job checks new rules against the full corpus via TLSH fuzzy matching before ingesting
- **GitHub PR Integration**: Propose accepted novel rules to a upstream sigma repo as a pull request; sync merged PRs back into the store automatically
- **Redis Store**: Optional persistent IOC and detection rule store with actor/TTP indexing and trend analytics
- **Search UI**: Streamlit app for querying across IOCs, rules, actors, trends, and coverage gaps
- **REST API**: FastAPI backend with Scalar and Swagger interactive docs

## Web Interfaces

| Interface | URL | Description |
|-----------|-----|-------------|
| Search UI | `http://localhost:8501` | Streamlit app — search IOCs, rules, actors, trends, and coverage |
| Scalar API Docs | `http://localhost:8000/scalar` | Interactive API reference with Python code examples |
| Swagger UI | `http://localhost:8000/docs` | Swagger UI with dark-mode toggle and try-it-out support |

## Project Structure

```
kitsune/
├── main.py               # CLI entry point
├── api.py                # FastAPI REST API
├── app.py                # Streamlit search UI
├── core/                 # Core library package
│   ├── __init__.py
│   ├── agent.py          # ThreatDetectionAgent class (LangGraph workflow)
│   ├── models.py         # Pydantic data models
│   ├── ioc_parser.py     # IOC + TTP extraction, validation, and confidence scoring
│   ├── coverage.py       # Coverage gap analysis with TLSH fuzzy matching
│   ├── sigma_repo.py     # Baseline sigma corpus loader + in-memory singleton
│   ├── github_pr.py      # GitHub PR client for proposing/syncing rules
│   ├── config.py         # Configuration settings
│   ├── llm_factory.py    # LLM provider factory
│   ├── utils.py          # Utility functions
│   ├── prompts.py        # Prompt templates
│   ├── intel_store.py    # Redis-backed threat intel store
│   └── enrichment.py     # Rule and event enrichment helpers
├── tests/                # Test suite
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
| `RULE_FORMAT` | Output format: `spl`, `sigma`, or `both` | `sigma` |
| `REDIS_URL` | Redis connection URL | `redis://localhost:6379` |
| `REDIS_KEY_PREFIX` | Namespace prefix for Redis keys | `kitsune` |
| `USER_AGENT` | HTTP User-Agent for fetching intel URLs | `kitsune/1.0` |
| `SIGMA_REPO_PATH` | Local directory of baseline sigma rules (recursive) | — |
| `SIGMA_REPO_URL` | GitHub HTTPS URL to clone/pull baseline rules from | — |
| `SIGMA_REPO_BRANCH` | Branch to use when cloning via `SIGMA_REPO_URL` | `main` |
| `GITHUB_TOKEN` | GitHub PAT for PR integration (`pip install PyGithub` required) | — |
| `GITHUB_REPO` | Target repo for rule PRs in `owner/repo` format | — |
| `GITHUB_BRANCH` | Base branch for rule PRs | `main` |

## Usage

### Run the pipeline

```bash
python main.py
```

Processes `INTEL_URL`, generates rules via all configured `LLM_PROVIDERS` in `RULE_FORMAT`, and saves output to `output/<provider>/`.

### CLI Modes

`main.py` accepts a `--mode` flag for additional operations (all store-backed modes require Redis):

| Mode | Description | Required flags |
|------|-------------|----------------|
| `run` | Generate detection rules from `INTEL_URL` (default) | — |
| `query` | Query IOCs and rules from the store | `--actor` and/or `--ttp`; optional `--ioc-type` |
| `trends` | Show top trending TTPs by ingestion frequency | optional `--top N` (default 10) |
| `actor-summary` | Print IOC/TTP/campaign summary for a threat actor | `--actor` |
| `enrich-rule` | Print enrichment data for a stored rule | `--rule-name` |
| `flush` | Delete all keys from the store | — |

```bash
# Query IOCs for a specific actor and TTP
python main.py --mode query --actor apt28 --ttp T1059 --ioc-type domain

# Show top 20 trending TTPs
python main.py --mode trends --top 20

# Summarise a threat actor
python main.py --mode actor-summary --actor apt28

# Flush all store data
python main.py --mode flush
```

### Programmatic Usage

```python
from core.agent import ThreatDetectionAgent

agent = ThreatDetectionAgent(llm_provider="anthropic")
rules = agent.generate_detections("https://example.com/threat-report", rule_format="sigma")

for rule in rules:
    print(rule.name, rule.mitre_ttps)
```

## Baseline Sigma Corpus

Kitsune can load a directory of existing sigma rules at startup and use them as a baseline for every analyze job. This means:

- Phase 1 coverage analysis checks new LLM-generated rules against the full corpus, not just what's already in Redis
- Rules that are near-duplicates of baseline rules (TLSH distance < 150) are deduplicated and not re-ingested into Redis
- Only genuinely novel rules are stored, keeping the Redis store focused on incremental improvements

### Local directory

```bash
SIGMA_REPO_PATH=/path/to/sigma/rules   # directory is scanned recursively for .yml files
```

### Private GitHub repo

```bash
SIGMA_REPO_URL=https://github.com/org/sigma-rules.git
pip install gitpython
```

The repo is cloned to `~/.cache/kitsune/sigma_repo` on first startup and pulled on each reload.

## GitHub PR Integration

Accepted novel rules can be proposed back to the upstream sigma repo as pull requests. Merged PRs are synced back into Redis and the baseline corpus automatically.

### Setup

```bash
GITHUB_TOKEN=ghp_...
GITHUB_REPO=owner/sigma-rules
pip install PyGithub
```

### Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /baseline/stats` | Rule count, TTPs covered, and load timestamp for the current corpus |
| `POST /baseline/reload` | Hot-reload the corpus from disk/GitHub without restarting |
| `POST /rules/propose-pr` | Open a PR to the upstream repo with specified rule IDs |
| `GET /github/sync` | Pull merged kitsune PRs, ingest rules into Redis, reload baseline |

## Extending

### Adding a New LLM Provider

1. Add the provider to `LLMProvider` enum in `core/models.py`
2. Add model/key config in `core/config.py`
3. Handle the new provider in `core/llm_factory.py`

### Customizing Prompts

Edit `core/prompts.py` to modify extraction and generation prompt templates.
