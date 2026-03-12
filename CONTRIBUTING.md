# Contributing to AgentSeal

Thank you for your interest in contributing! This guide covers how to set up your development environment, our code style, and the pull request process.

---

## Getting Started

### Prerequisites

- Python 3.10+ (for Python package)
- Node.js 18+ (for JS package)
- Git

### Python Setup

```bash
# Clone the repository
git clone https://github.com/agentseal/agentseal.git
cd agentseal

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in development mode
pip install -e "./python[all]"

# Run the tests
cd python && python -m pytest tests/ -v
```

### Verify it works

```bash
agentseal scan --prompt "You are a test assistant" --model ollama/llama3.1:8b
```

### JavaScript Setup

```bash
cd js
npm install
npm run build
npm test
```

---

## What can I contribute?

### New attack probes

The probes are defined in `python/agentseal/probes/` (Python) and `js/src/probes/` (JS). If you've found a new attack technique that AgentSeal doesn't test for, we'd love to add it.

### Better detection

Detection methods are in `python/agentseal/detection/` (Python) and `js/src/detection/` (JS). Improvements to n-gram matching, canary detection, or new detection approaches are welcome.

### New connectors

Model connectors are in `python/agentseal/connectors/` (Python) and `js/src/providers/` (JS). If you use a provider we don't support, add a connector for it.

### Bug fixes

Found a bug? Fix it and submit a PR. If you're not sure how to fix it, open an issue first.

---

## Code Style

- **Python**: Follow PEP 8.
- **Line length**: 100 characters max.
- **Type hints**: Use type annotations for function signatures.
- **Docstrings**: Required for public classes and functions.

---

## Pull Request Process

1. **Fork** the repository and create a branch from `main`:
   ```bash
   git checkout -b feat/your-feature
   ```

2. **Make your changes** with clear, focused commits.

3. **Write tests** for new functionality.

4. **Push** your branch and open a pull request against `main`.

5. **Describe** your changes in the PR:
   - What does this change?
   - How was it tested?
   - Any breaking changes?

### Commit messages

Use clear, imperative-mood messages:

- `Add Unicode homoglyph detection for extraction probes`
- `Fix n-gram scoring for short prompts`
- `Add Google Gemini connector`

---

## Reporting Issues

- Use [GitHub Issues](https://github.com/agentseal/agentseal/issues) for bugs and feature requests.
- Include reproduction steps, expected vs actual behavior.
- For security vulnerabilities, please email hello@agentseal.org instead of opening a public issue.

---

## License

By contributing, you agree that your contributions will be licensed under the [FSL-1.1-Apache-2.0](LICENSE) license.
