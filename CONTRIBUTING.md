# Contributing to Netsleuth

Thank you for considering contributing to Netsleuth! We welcome contributions from the community and are happy to review your pull requests.

## Code of Conduct

Please be respectful and constructive in your interactions. We follow a code of conduct that ensures a welcoming environment for everyone.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

* Use a clear and descriptive title
* Describe the exact steps to reproduce the problem
* Provide specific examples to demonstrate the steps
* Describe the behavior you observed and what behavior you expected
* Include screenshots if applicable
* Include environment details (OS, Python version, etc.)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

* A clear and descriptive title
* A detailed description of the suggested enhancement
* Examples of how this enhancement would be used
* Explanation of why this enhancement would be useful

### Pull Requests

* Fill in the required template
* Follow the Python style guide (PEP 8)
* Include tests for new functionality
* Update documentation as needed
* Add an entry to CHANGELOG.md
* Ensure all tests pass and there are no linting errors

## Development Setup

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/netsleuth.git`
3. Install dependencies: `uv pip install -e .[dev]`
4. Install pre-commit hooks: `pre-commit install`
5. Create a branch: `git checkout -b feature/your-feature-name`

## Coding Standards

* Use type hints for all function parameters and return values
* Write docstrings for all public functions and classes
* Follow PEP 8 style guidelines
* Keep functions small and focused
* Write meaningful commit messages

### Commit Message Format

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

Types include:
* `feat`: A new feature
* `fix`: A bug fix
* `docs`: Documentation changes
* `style`: Code style changes (formatting, etc.)
* `refactor`: Code refactoring
* `test`: Adding or updating tests
* `chore`: Maintenance tasks

## Testing

* Write unit tests for new functionality
* Ensure all existing tests pass
* Aim for high test coverage
* Test with multiple Python versions (3.10, 3.11, 3.12)

Run tests with:
```bash
pytest tests/ -v --cov=src/netsleuth
```

## Documentation

* Update README.md for user-facing changes
* Add API documentation for new modules
* Include usage examples
* Keep documentation up-to-date with code changes

Build documentation locally:
```bash
sphinx-build -b html docs/source docs/build
```

## Code Review Process

1. All submissions require review
2. We use GitHub pull requests
3. At least one maintainer must approve
4. Automated checks must pass

## Questions?

Feel free to open an issue with the "question" label if you have any questions about contributing.

Thank you for contributing to Netsleuth! 🎉
