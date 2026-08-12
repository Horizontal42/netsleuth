# Changelog

All notable changes to Netsleuth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- DevContainer configuration for consistent development environment
- Pre-commit hooks for linting, formatting, and security checks
- Comprehensive CI/CD pipeline with GitHub Actions
- Issue templates for bug reports and feature requests
- Pull request template
- CONTRIBUTING.md guide
- Internationalization support (i18n) for multiple languages
- Monitoring module with OpenTelemetry integration
- Sphinx documentation structure
- Python 3.10, 3.11, 3.12 support in CI

### Changed
- Updated pyproject.toml with comprehensive tool configurations
- Enhanced project structure for better maintainability

### Fixed
- Improved error handling patterns
- Better type hints throughout the codebase

### Security
- Added Bandit security scanning
- Added pip-audit for dependency vulnerability checks
- Automated security scanning in CI pipeline

## [0.1.0] - 2024-08-12

### Added
- Initial release of Netsleuth
- Network diagnostics capabilities
- CLI interface
- Multiple export formats
- Basic testing framework

[Unreleased]: https://github.com/netsleuth/netsleuth/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/netsleuth/netsleuth/releases/tag/v0.1.0
