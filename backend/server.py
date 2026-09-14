from __future__ import annotations

import json
import mimetypes
import os
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.agent import OpsPilot


ROOT = Path(__file__).resolve().parents[1]
pilot = OpsPilot()


class Handler(BaseHTTPRequestHandler):
    server_version = "OpsPilot/0.1"

    def _json(self, status: int, payload: object) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 65536:
            raise ValueError("Request body is too large.")
        if not length:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _authorized(self) -> bool:
        expected = os.getenv("OPS_PILOT_AUTH_TOKEN")
        return not expected or self.headers.get("Authorization") == f"Bearer {expected}"

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/api/health":
            self._json(HTTPStatus.OK, {"ok": True, "service": "ops-pilot", "version": "0.1"})
            return
        if path == "/api/metrics":
            self._json(HTTPStatus.OK, pilot.metrics())
            return
        if path == "/api/investigations":
            self._json(HTTPStatus.OK, pilot.store.list_investigations())
            return
        if path == "/api/knowledge":
            self._json(HTTPStatus.OK, pilot.kb.documents)
            return
        if path.startswith("/api/investigations/"):
            investigation_id = path.rsplit("/", 1)[-1]
            investigation = pilot.investigations.get(investigation_id)
            if investigation:
                self._json(HTTPStatus.OK, investigation)
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "Investigation not found"})
            return
        if path.startswith("/api/audit/"):
            investigation_id = path.rsplit("/", 1)[-1]
            self._json(HTTPStatus.OK, pilot.store.audit_events(investigation_id))
            return
        if path == "/" or path == "/index.html":
            self._serve(ROOT / "frontend" / "index.html")
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if not self._authorized():
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "Bearer authentication required."})
            return
        try:
            if path == "/api/investigate":
                incident = str(self._body().get("incident", "")).strip()
                if len(incident) < 8:
                    self._json(HTTPStatus.BAD_REQUEST, {"error": "Describe the incident in at least 8 characters."})
                    return
                if len(incident) > 2000:
                    self._json(HTTPStatus.BAD_REQUEST, {"error": "Keep the incident description under 2000 characters."})
                    return
                self._json(HTTPStatus.OK, pilot.investigate(incident))
                return
            if path.startswith("/api/investigations/") and path.endswith("/approve"):
                investigation_id = path.split("/")[-2]
                self._json(HTTPStatus.OK, pilot.approve(investigation_id, actor=self.headers.get("X-Actor", "demo-user"), role=self.headers.get("X-Role", "incident_commander"), idempotency_key=self.headers.get("Idempotency-Key")))
                return
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
            return
        except PermissionError as error:
            self._json(HTTPStatus.FORBIDDEN, {"error": str(error)})
            return
        except ValueError as error:
            self._json(HTTPStatus.CONFLICT, {"error": str(error)})
            return
        except KeyError:
            self._json(HTTPStatus.NOT_FOUND, {"error": "Investigation not found"})
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

    def _serve(self, path: Path) -> None:
        if not path.exists():
            self._json(HTTPStatus.NOT_FOUND, {"error": "Asset not found"})
            return
        body = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", mimetypes.guess_type(str(path))[0] or "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        print(f"[{self.log_date_time_string()}] {format % args}")


def main() -> None:
    address = ("127.0.0.1", int(os.getenv("OPS_PILOT_PORT", "8080")))
    print(f"OpsPilot running at http://{address[0]}:{address[1]}")
    ThreadingHTTPServer(address, Handler).serve_forever()


if __name__ == "__main__":
    main()
