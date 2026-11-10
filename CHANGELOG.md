# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-07

### Added

- Multi-Layer Detection — Combines 30+ heuristic patterns, keyword lists, and delimiter analysis in under 1 ms.
- Smart Sanitization — Strips or escapes dangerous segments while preserving legitimate user intent.
- Risk Scoring — Returns normalized 0-1 score with per-signal breakdown for policy decisions.
- Rich Reports — Immutable Report objects contain explanations, matched patterns and suggested fixes.
- Laravel Middleware — One-line middleware automatically inspects configurable request keys for prompts.
- Optional LLM Audit — Secondary validation via OpenAI or compatible APIs using defensive system prompts.
- Zero Dependencies — Core works with zero extensions; AI auditor is loaded only when configured.
- Configurable Rules — Publishable config lets you tune thresholds, enable/disable detectors, and add custom patterns.
