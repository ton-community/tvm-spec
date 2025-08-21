sort-report:
	@tmp=$$(mktemp) && \
	jq 'sort_by(.category, .mnemonic)' match-report.json > $$tmp && \
	mv $$tmp match-report.json