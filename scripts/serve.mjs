import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = fileURLToPath(new URL("..", import.meta.url));
const root = resolve(projectRoot, "docs");
const port = Number(process.env.PORT || 4173);

const mimeTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
};

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url || "/", `http://${request.headers.host || "localhost"}`);
    const requested = decodeURIComponent(url.pathname === "/" ? "/index.html" : url.pathname);
    const relative = normalize(requested).replace(/^(\.\.[/\\])+/, "").replace(/^[/\\]+/, "");
    const path = join(root, relative);

    if (!path.startsWith(root)) {
      response.writeHead(400);
      response.end("Bad request");
      return;
    }

    const fileStat = await stat(path);
    if (!fileStat.isFile()) {
      throw new Error("Not a file");
    }

    const body = await readFile(path);
    response.writeHead(200, {
      "Content-Type": mimeTypes[extname(path)] || "application/octet-stream",
      "Cache-Control": "no-store",
    });
    response.end(body);
  } catch {
    response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    response.end("Not found");
  }
});

server.listen(port, "127.0.0.1", () => {
  console.log(`Threat Profile: http://127.0.0.1:${port}`);
});
