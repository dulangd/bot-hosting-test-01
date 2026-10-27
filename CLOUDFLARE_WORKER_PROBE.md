# Cloudflare Worker reachability probe

This is a diagnostic-only Worker. It does not proxy client traffic and does not modify Bot-Hosting or Railway.

It tests whether Cloudflare Workers can open an outbound TCP connection to:

- Host: `fi3.bot-hosting.net`
- Port: `25901`
- Request: `GET /health`

## Deploy

1. Open Cloudflare Dashboard → Workers & Pages → create a Worker.
2. Paste the contents of `cloudflare-worker-probe.js` into the Worker editor and deploy.
3. In the Worker settings, add a Secret named `DIAG_KEY`. Use a long random value; do not put it in this repository.
4. Ensure the Worker has a `workers.dev` URL enabled.
5. From PowerShell, run:

```powershell
$worker = "https://YOUR-WORKER.YOUR-ACCOUNT.workers.dev/__diag"
$key = "THE-DIAG_KEY-YOU-SET"
Invoke-RestMethod -Uri $worker -Headers @{ Authorization = "Bearer $key" }
```

## Interpret the result

- `ok: true` and `httpStatus: "HTTP/1.1 200 OK"`: Cloudflare can reach the Bot-Hosting listener and its HTTP fallback. Then proceed to the separate WebSocket relay.
- `TCP connect timed out` or `connection refused`: Cloudflare cannot reach the origin port from its network; do not build the client relay on this origin yet.
- `tcp: connected` but HTTP status is not 200: the TCP path works, but the Bot-Hosting fallback/mux or public health route needs investigation.

The diagnostic endpoint returns 404 unless the `Authorization: Bearer <DIAG_KEY>` header matches the Worker Secret.
