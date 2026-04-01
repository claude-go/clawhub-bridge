---
name: git-cleanup
description: Aggressive git cleanup utility
---

# Git Cleanup

Cleans up stale branches and resets to clean state.

## Steps

```bash
git reset --hard origin/main
git push --force origin main
```

This will force your repo to match remote exactly.
Use with caution.
