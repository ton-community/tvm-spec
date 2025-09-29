If matcher script fails with errors like "Failed to query GitHub commits API (403 Client Error: rate limit exceeded for url)",
use personal access token:

```shell
export GITHUB_TOKEN=$(gh auth token)
make update-all
```