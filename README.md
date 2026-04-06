# Kitsune [kitsu-nay] キツネ

> A LangGraph workflow for crafting detections against emerging tradecraft.

Kitsune reads a threat report URL, extracts IOCs and MITRE ATT&CK techniques, checks them against your baseline sigma corpus, and generates new detection rules for gaps in coverage. Think of it like a CI/CD pipeline for detections — a fixed sequence of stages where the LLM handles the heavy lifting (intel extraction, rule generation) and routing is mostly deterministic.

```
[Fetch report]  →  [Extract IOCs + TTPs]  →  [Gap analysis vs. baseline]
                                                          ↓
                                                   [Generate rules]
                                                          ↓
                                                   [Validate rules]
                                                          ↓
                                            [Pause: engineer review]
                                                 ↙           ↘
                                           [Approve]       [Reject]
                                              ↓
                                        [Open draft PR]
                                              ↓
                                          [PR merged]
                                              ↓
                                   [Sync + TLSH re-index baseline]
```

Near-duplicate rules are skipped before anything gets written — candidates are TLSH-matched against the full corpus so only genuinely novel coverage lands in your store.

## Table of Contents

- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [Configuration](#configuration)
- [API](#api)
- [Extending](#extending)
- [Maintainers](#maintainers)
- [License](#license)

## Background

Most detection-engineering teams already maintain a sigma repo. Kitsune treats
that repo as the source of truth: before generating anything, it TLSH-matches
candidate rules against the full baseline corpus so you don't end up with
near-duplicate rules cluttering the store. Only novel rules get ingested into
Redis and proposed as PRs.

Supports Anthropic Claude and OpenAI GPT models; outputs Sigma or SPL.

## Install

### Docker (recommended)

```bash
git clone <repository-url>
cd kitsune
cp .env.copy .env
# add ANTHROPIC_API_KEY and/or OPENAI_API_KEY
docker compose up --build
```

Services come up in order: Redis → API → UI. `docker compose down -v` wipes
Redis data.

### Local

```bash
git clone <repository-url>
cd kitsune
poetry install --no-root
source $(poetry env info --path)/bin/activate
cp .env.copy .env
docker run -d --name kitsune-redis -p 6379:6379 redis:alpine
uvicorn api:app --reload --port 8000   # terminal 1
streamlit run app.py                   # terminal 2
```

## Usage

### Generate rules from a report

```bash
INTEL_URL=https://example.com/threat-report python main.py
```

Rules are written to `output/<provider>/` and ingested into Redis.

### CLI modes

`main.py --mode <name>` for store-backed operations (all require Redis):

| Mode | Description | Required flags |
|------|-------------|----------------|
| `run` | Generate rules from `INTEL_URL` (default) | — |
| `query` | Query IOCs/rules | `--actor` and/or `--ttp`; optional `--ioc-type` |
| `trends` | Top trending TTPs by ingestion | optional `--top N` |
| `actor-summary` | IOC/TTP/campaign summary for an actor | `--actor` |
| `enrich-rule` | Enrichment data for a stored rule | `--rule-name` |
| `flush` | Delete all keys from the store | — |

```bash
python main.py --mode query --actor apt28 --ttp T1059 --ioc-type domain
python main.py --mode trends --top 20
python main.py --mode actor-summary --actor apt28
```

### Programmatic

```python
from core.agent import ThreatDetectionAgent

agent = ThreatDetectionAgent(llm_provider="anthropic")
rules = agent.generate_detections("https://example.com/threat-report", rule_format="sigma")
```

### Web interfaces

| Interface | URL |
|-----------|-----|
| Streamlit UI | `http://localhost:8501` |
| Scalar docs | `http://localhost:8000/scalar` |
| Swagger | `http://localhost:8000/docs` |

The Streamlit UI has per-rule include/exclude checkboxes for review,
a "what should be improved?" prompt that steers regeneration under
Sigma/SPL format constraints, an AMA-style `/ask` box, and a per-tactic
coverage heatmap with MITRE ATT&CK Navigator layer export.

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `LLM_PROVIDERS` | Comma-separated providers | `anthropic,openai` |
| `ANTHROPIC_API_KEY` | Anthropic API key | — |
| `OPENAI_API_KEY` | OpenAI API key | — |
| `ANTHROPIC_MODEL` | Anthropic model | `claude-sonnet-4-6` |
| `OPENAI_MODEL` | OpenAI model | `gpt-4o-mini` |
| `INTEL_URL` | Threat report URL | — |
| `RULE_FORMAT` | `spl`, `sigma`, or `both` | `sigma` |
| `REDIS_URL` | Redis connection URL | `redis://localhost:6379` |
| `REDIS_KEY_PREFIX` | Namespace prefix | `kitsune` |
| `USER_AGENT` | HTTP User-Agent for fetches | `kitsune/1.0` |
| `SIGMA_REPO_PATH` | Local dir of baseline rules (recursive) | — |
| `SIGMA_REPO_URL` | HTTPS URL to clone baseline from | — |
| `SIGMA_REPO_BRANCH` | Branch for `SIGMA_REPO_URL` | `main` |
| `GITHUB_TOKEN` | PAT for PR integration | — |
| `GITHUB_REPO` | Target repo `owner/repo` | — |
| `GITHUB_BRANCH` | Base branch for PRs | `main` |

### Baseline sigma corpus

Point `SIGMA_REPO_PATH` at a local directory, or `SIGMA_REPO_URL` at a git
repo (`pip install gitpython`). Remote repos are cloned to
`~/.cache/kitsune/sigma_repo` and pulled on reload. Kitsune prefers a private
repo when both are configured.

Phase 1 coverage runs against the full corpus — new rules within TLSH
distance < 150 of an existing rule are skipped, not re-ingested.

### GitHub PR integration

```bash
GITHUB_TOKEN=ghp_...
GITHUB_REPO=owner/sigma-rules
pip install PyGithub
```

Accepted rules are batched into one draft PR per analyze job, branch name
`feature/added-{N}-rules-for-{theme}`, labeled `kitsune-generated`. Merged
PRs sync back into Redis and reload the baseline.

MITRE actor enrichment: each rule gets one `attack.g####` tag per actor
(Redis-cached from the MITRE CTI STIX bundle, 7d TTL), falling back to
`actor.<slug>` only when no group mapping exists.

## API

| Endpoint | Description |
|----------|-------------|
| `GET /stats` | IOCs, actors, sigma rules, AI-generated rule counts |
| `GET /baseline/stats` | Rule count, TTPs, load timestamp for current corpus |
| `POST /baseline/reload` | Hot-reload corpus from disk/GitHub |
| `POST /rules/propose-pr` | Open a PR with specified rule IDs |
| `GET /github/sync` | Pull merged kitsune PRs, ingest into Redis, reload baseline |
| `GET /coverage/by-tactic` | Per-tactic coverage with uncovered-with-IOCs lists |
| `GET /coverage/navigator` | ATT&CK Navigator v4.5 layer JSON |
| `POST /ask` | Natural-language search; routes to the right store query |

## Extending

**New LLM provider:** add it to `LLMProvider` in `core/models.py`, configure
the model/key in `core/config.py`, and handle it in `core/llm_factory.py`.

**Prompts:** extraction and generation templates live in `core/prompts.py`.

## Maintainers

[@christina23](https://github.com/christina23)

## License

No license file yet — all rights reserved until one is added.
