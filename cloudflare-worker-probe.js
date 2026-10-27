import { connect } from "cloudflare:sockets";

const ORIGIN_HOST = "fi3.bot-hosting.net";
const ORIGIN_PORT = 25901;
const MAX_HEADER_BYTES = 32 * 1024;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function withTimeout(promise, ms, message) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(message)), ms);
    }),
  ]).finally(() => clearTimeout(timer));
}

function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function findHeaderEnd(bytes) {
  for (let i = 0; i <= bytes.length - 4; i++) {
    if (
      bytes[i] === 13 &&
      bytes[i + 1] === 10 &&
      bytes[i + 2] === 13 &&
      bytes[i + 3] === 10
    ) {
      return i + 4;
    }
  }
  return -1;
}

async function readHttpHeaders(reader, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;
  let data = new Uint8Array(0);

  while (data.length <= MAX_HEADER_BYTES) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new Error("origin HTTP response timed out");

    const result = await withTimeout(
      reader.read(),
      remaining,
      "origin HTTP response timed out",
    );
    if (result.done || !result.value) {
      throw new Error("origin closed before returning HTTP headers");
    }

    data = concatBytes(data, result.value);
    const end = findHeaderEnd(data);
    if (end >= 0) {
      return decoder.decode(data.slice(0, end));
    }
  }

  throw new Error("origin HTTP headers exceeded size limit");
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname !== "/__diag") {
      return new Response("not found", { status: 404 });
    }

    if (
      !env.DIAG_KEY ||
      request.headers.get("Authorization") !== "Bearer " + env.DIAG_KEY
    ) {
      return new Response("not found", { status: 404 });
    }

    let socket;
    try {
      socket = connect(
        { hostname: ORIGIN_HOST, port: ORIGIN_PORT },
        { allowHalfOpen: true },
      );

      const opened = await withTimeout(
        socket.opened,
        8000,
        "TCP connect timed out after 8 seconds",
      );

      const writer = socket.writable.getWriter();
      await writer.write(
        encoder.encode(
          "GET /health HTTP/1.1\r\n" +
            "Host: " + ORIGIN_HOST + ":" + ORIGIN_PORT + "\r\n" +
            "Connection: close\r\n\r\n",
        ),
      );
      writer.releaseLock();

      const reader = socket.readable.getReader();
      const headers = await readHttpHeaders(reader, 8000);
      const statusLine = headers.split("\r\n", 1)[0];
      const ok = /^HTTP\/1\.[01] 200(?: |$)/.test(statusLine);

      return Response.json(
        {
          ok,
          tcp: "connected",
          origin: ORIGIN_HOST + ":" + ORIGIN_PORT,
          originAddress: opened.remoteAddress ?? null,
          httpStatus: statusLine,
          check: "Cloudflare Worker TCP socket -> Bot-Hosting /health",
          next: ok
            ? "Cloudflare can reach the Bot-Hosting listener; proceed to the WebSocket relay test."
            : "TCP works, but the public HTTP fallback/mux did not return HTTP 200.",
        },
        { status: ok ? 200 : 502 },
      );
    } catch (error) {
      return Response.json(
        {
          ok: false,
          origin: ORIGIN_HOST + ":" + ORIGIN_PORT,
          error: String(error?.message ?? error),
          next:
            "Do not deploy the client relay yet. First determine why Cloudflare cannot reach the Bot-Hosting TCP listener or HTTP fallback.",
        },
        { status: 502 },
      );
    } finally {
      if (socket) {
        try {
          await socket.close();
        } catch {
          // The socket may already have failed or closed.
        }
      }
    }
  },
};
