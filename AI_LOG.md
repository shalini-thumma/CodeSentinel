# AI Usage Log

## Project

CodeSentinel

## AI-Assisted Development

AI assistance was used during implementation to help design and generate the project structure, static-analysis modules, FastAPI integration, Streamlit interface, tests, and documentation.

## Optional Product AI Feature

CodeSentinel optionally supports an OpenAI-compatible LLM endpoint for reviewing existing static-analysis findings.

AI review is not required for basic analysis:

- Static security, gap, quality, and loose-end analysis runs without an API key.
- The application sends only bounded source excerpts around existing findings.
- Common credential assignments and known secret formats are redacted before sending.
- The AI provider cannot add findings, remove findings, or change finding severity.
- Provider failures fall back to static findings.
- API credentials are read only from environment variables and are never written to repository files or reports.

The optional provider configuration variables are:

- `CODESENTINEL_AI_API_KEY`
- `CODESENTINEL_AI_BASE_URL`
- `CODESENTINEL_AI_MODEL`
