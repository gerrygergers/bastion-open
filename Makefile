.PHONY: build scan test selftest check fix-dry
# Everything resolves relative to this dir; run from a clone on any Linux box.

build:
	docker compose build scanner

scan:
	docker compose run --rm scanner

test:
	python3 -m pytest tests/ -q

selftest:
	python3 scripts/selftest.py

check: test selftest   # no-network, no-root verification

fix-dry:               # what WOULD the policy apply? changes nothing
	docker compose --profile fix run --rm fixer --dry-run
