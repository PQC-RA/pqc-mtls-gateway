# Developer convenience targets.
# See .pre-commit-config.yaml and .github/workflows/checks.yml.
.PHONY: hooks lint

## hooks: install the git pre-commit hook (requires pre-commit on PATH)
hooks:
	@pre-commit install

## lint: run all static checks on demand (same set the pre-commit hook + CI enforce)
lint:
	@pre-commit run --all-files
