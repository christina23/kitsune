# Kitsune

Quick like a fox and full of wisdom, Kitsune is an AI agent that automatically generates detection rules from threat intelligence reports using multiple LLM providers.

## Features

- **Multi-LLM Support**: Works with Anthropic Claude, OpenAI GPT, and Perplexity models
- **Multiple Rule Formats**: Generates both Splunk SPL and Sigma detection rules
- **Robust JSON Handling**: Special handling for Anthropic's response format with automatic fixing
- **Validated IOC Extraction**: Regex-based extraction and validation for IPs, domains, hashes, URLs, and file names — merges LLM output with regex findings and deduplicates
- **Validated TTP Extraction**: MITRE ATT&CK technique IDs are validated against regex patterns, confidence-scored (1.0 if found verbatim in text, 0.85 if LLM-only, 0.7 if regex-only), and deduplicated; sub-techniques preferred over parent IDs
- **Coverage Gap Analysis**: After rule generation, compares extracted techniques against the generated rules and reports which TTPs have no detection coverage, with priority (high/medium/low) and recommended data sources
- **Author Attribution**: Automatically attributes rules based on the source
- **Error Recovery**: Fallback mechanisms ensure you always get usable output

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
├── pyproject.toml    # Python dependencies (for poetry)
├── poetry.lock       # Poetry lock file
├── .env.copy         # Environment variables (copy)
└── output/           # Generated detection rules (created by running `main.py`)
    ├── anthropic/
    ├── openai/
    └── perplexity/
```

## Installation

1. **Clone the repository**:
```bash
git clone <repository-url>
cd kitsune
```

2. **Install dependencies**:
```bash
Run `poetry install`, assuming you already have Poetry installed.
If you prefer pip, can also install via `pip install -r requirements.txt`
```

3. **Configure environment variables**:
```bash
cp .env.copy .env
# Edit .env with your API keys
```

## Configuration

### Environment Variables

- `LLM_PROVIDERS`: Comma-separated list of providers (e.g., "anthropic,openai,perplexity")
- `ANTHROPIC_API_KEY`: Your Anthropic API key
- `OPENAI_API_KEY`: Your OpenAI API key
- `PERPLEXITY_API_KEY`: Your Perplexity API key
- `INTEL_URL`: URL of the threat intelligence report to process
- `RULE_FORMAT`: Output format - "spl", "sigma", or "both"

### Example .env file

```bash
LLM_PROVIDERS=anthropic,openai
ANTHROPIC_API_KEY=...
OPENAI_API_KEY=...
INTEL_URL=https://example.com/threat-report
RULE_FORMAT=spl
```

## Usage

### Basic Usage

```bash
python main.py
```

This will:
1. Fetch the URL specified in `INTEL_URL`
2. Extract threat intelligence (IOCs + MITRE TTPs) using the configured LLM(s)
3. Validate and confidence-score IOCs and TTPs with regex
4. Generate detection rules in the format specified by `RULE_FORMAT`
5. Run coverage gap analysis and print any uncovered techniques to the console
6. Save rule files to `output/<provider>/`

### Override settings without editing `.env`

```bash
# Use a single provider and a specific URL
LLM_PROVIDER=anthropic INTEL_URL=https://example.com/threat-report python main.py

# Generate both SPL and Sigma rules
RULE_FORMAT=both python main.py

# Enable debug output on errors
DEBUG=true python main.py
```

### Console output

A successful run prints:

```
Fetched 12345 characters from URL
Extracted threat intel for: APT29 (8 IOCs, 6 TTPs)
Generated 5 SPL rules

[COVERAGE GAPS] 2 uncovered technique(s):
  [HIGH] T1059.001 (execution)
    Data sources needed: Sysmon (EventID 1), PowerShell Script Block Logging
  [MEDIUM] T1071.001 (command-and-control)
    Data sources needed: Proxy Logs, Network Flow Logs
```

Techniques are considered covered if a generated rule references the exact sub-technique ID or its parent (e.g. a rule tagging `T1059` covers `T1059.001`).

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
├── openai/
│   └── ...
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
    PERPLEXITY = "perplexity"
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

## License

[Your License Here]

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Support

For issues or questions, please create an issue in the repository.
