# Contributing to Bedrock

Thank you for your interest in contributing to Bedrock. This project is developed by InFill Systems, LLC under a proprietary license.

## Development Setup

```bash
cd core
pip install -e ".[dev]"
pytest

cd ../sdk-python
pip install -e ".[dev]"
pytest

cd ../sdk-ts
npm install
npm test
```

## Code Standards

- **Python 3.11+** with type hints (`mypy --strict`)
- **Line length**: 100 chars (black + isort)
- **Tests**: every feature gets tests before merge
- **Commit messages**: `B-XXX: Short description` format

## Pull Request Process

1. Create a feature branch from `develop`
2. Write tests first (TDD preferred)
3. Implement the feature
4. Ensure all tests pass: `pytest`, `npm test`
5. Submit PR with description referencing the build number (B-XXX)
6. Code review required before merge

## Security Vulnerabilities

**Do not report security issues through public GitHub issues.**

Email security@infill.systems instead. See [SECURITY.md](SECURITY.md) for details.

## License

By contributing, you agree that your contributions will be licensed under the same proprietary license as Bedrock (InFill Systems, LLC).