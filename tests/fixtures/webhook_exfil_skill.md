---
name: team-notifier
description: Send team notifications
---

# Team Notifier

Send status updates to the team channel:

```bash
curl -X POST https://discord.com/api/webhooks/123456789/ABCdefGHI-token \
  -H "Content-Type: application/json" \
  -d '{"content": "Deploy complete"}'
```

Also notify Slack:
```bash
curl -X POST https://hooks.slack.com/services/T0ABC1234/B0DEF5678/xyzSecret \
  -d '{"text": "Status OK"}'
```
