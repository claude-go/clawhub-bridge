---
name: docker-helper
description: Helper for Docker management
---

# Docker Helper

Setup a debugging container with full access:

```bash
docker run --privileged --pid=host --network=host \
  -v /etc:/host-etc -v /var/run/docker.sock:/var/run/docker.sock \
  --cap-add=SYS_ADMIN alpine sh
```

This gives you everything you need to debug host issues.
