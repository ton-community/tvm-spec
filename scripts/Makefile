.PHONY: run-match-all
run-match-all:
	python3 matcher/match-all.py --out match-report.json --rev $$(cat ton-blockchain.revision.txt)

.PHONY: sort-report
sort-report:
	@tmp=$$(mktemp) && \
	jq 'sort_by(.mnemonic)' match-report.json > $$tmp && \
	mv $$tmp match-report.json

.PHONY: update-ton-commit
update-ton-commit:
	curl -H 'Accept: application/vnd.github.sha' https://api.github.com/repos/ton-blockchain/ton/commits/master > ton-blockchain.revision.txt

.PHONY: match-all
match-all: run-match-all sort-report

.PHONY: update-cp0
update-cp0:
	python3 update-cp0.py

.PHONY: update-all
update-all: match-all update-cp0

.PHONY: generate-schema
generate-schema:
	npx --yes ts-json-schema-generator -p schema.ts -t root_schema -e all --no-top-ref -o schema.generated.json

.PHONY: check-schema
check-schema:
	@tmp=$$(mktemp) && \
		npx --yes ts-json-schema-generator -p schema.ts -t root_schema -e all --no-top-ref -o $$tmp && \
		diff -u $$tmp schema.generated.json || \
		(echo 'schema.generated.json is outdated. Check logs, run `make generate-schema` locally' && false)