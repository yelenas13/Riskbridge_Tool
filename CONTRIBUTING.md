# Contributing

1. Fork the repository and create a feature branch.
2. Add or update tests for behavior changes.
3. Run `pytest -q` before opening a pull request.
4. Do not introduce random or fabricated fallback security data.
5. New scanner integrations must normalize into the RiskBridge common schema rather than changing the scoring engine.
6. Document any scoring-model change and explain why the weight or threshold changed.
