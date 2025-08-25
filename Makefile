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
