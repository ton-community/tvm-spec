sort-report:
	@tmp=$$(mktemp) && \
	jq 'sort_by(.mnemonic)' match-report.json > $$tmp && \
	mv $$tmp match-report.json