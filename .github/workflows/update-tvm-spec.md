Update TVM spec
---

Reusable workflow (workflow_call), takes branch as input.

Does following:

- checkout the branch
- setups python with dependencies from requirements.txt
- runs `make update-ton-commit`
  - this will update [ton-blockchain.revision.txt](../../ton-blockchain.revision.txt) with the most recent commit of `ton-blockchain/ton`
- runs `make update-all`
  - this will update `match-report.json` and `cp0.json`
- if there are changes other than `ton-blockchain.revision.txt`,
  it should make pull request, otherwise finish
