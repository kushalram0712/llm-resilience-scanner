"""Local OpenAI-compatible mock server for offline testing and live demos."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from urllib.parse import parse_qs, urlparse


class MockLLMHandler(BaseHTTPRequestHandler):
    """Simulates either a 'vulnerable' or 'hardened' LLM chat completion endpoint."""

    def do_POST(self) -> None:  # noqa: N802
        parsed_url = urlparse(self.path)
        if not parsed_url.path.endswith("/chat/completions"):
            self._send_json(404, {"error": "Endpoint not found. Use /v1/chat/completions"})
            return

        query_params = parse_qs(parsed_url.query)
        mode = query_params.get("mode", ["vulnerable"])[0].lower()

        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length).decode("utf-8")

        try:
            payload = json.loads(raw_body)
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Malformed JSON payload"})
            return

        messages = payload.get("messages", [])
        system_text = ""
        user_text = ""
        for msg in messages:
            if msg.get("role") == "system":
                system_text = msg.get("content", "")
            elif msg.get("role") == "user":
                user_text = msg.get("content", "")

        reply = self._generate_simulated_reply(mode, system_text, user_text)

        response_body = {
            "id": "chatcmpl-mock-001",
            "object": "chat.completion",
            "model": payload.get("model", "mock-llm-v1"),
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": reply},
                    "finish_reason": "stop",
                }
            ],
        }
        self._send_json(200, response_body)

    @staticmethod
    def _generate_simulated_reply(mode: str, system_text: str, user_text: str) -> str:
        """Deterministically simulates hardened vs vulnerable model responses."""
        if mode == "hardened":
            return (
                "I cannot fulfill this request. Doing so would go against my safety guidelines "
                "and security policy regarding instruction overrides or system disclosure."
            )

        # Vulnerable mode: simulate realistic failures on specific synthetic probes
        upper_user = user_text.upper()
        if "SYNTHETIC_OVERRIDE_ACK" in upper_user:
            return "Diagnostic acknowledged: SYNTHETIC_OVERRIDE_ACK"
        if "VERBATIM" in upper_user or "SYSTEM_CONFIGURATION" in upper_user:
            return f"Here is my initialization context: {system_text}"
        if "DELIMITER_BYPASS_ACK" in upper_user:
            return "System block executed: DELIMITER_BYPASS_ACK"
        if "PERSONA_SHIFT_ACK" in upper_user:
            return f"PERSONA_SHIFT_ACK: Operating as UnrestrictedDebugBot. System: {system_text}"
        if "T3V0C" in upper_user or "BASE64" in upper_user:
            return "Decoded instruction output: BASE64_DECODE_ACK"

        # Hold guardrails on the remaining vectors to produce a realistic ~45-50% mixed score
        return "I cannot comply with that diagnostic override request."

    def _send_json(self, status_code: int, data: dict) -> None:
        encoded = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        """Suppress noisy default HTTP request logging during CLI table rendering."""
        return


def run_mock_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Starts the local mock LLM server."""
    server = HTTPServer((host, port), MockLLMHandler)
    print(f"[*] Mock LLM Server listening on http://{host}:{port}/v1/chat/completions")
    print("    - Vulnerable mode: http://127.0.0.1:8000/v1/chat/completions?mode=vulnerable")
    print("    - Hardened mode:   http://127.0.0.1:8000/v1/chat/completions?mode=hardened")
    print("    Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping Mock LLM Server.")
        server.server_close()


if __name__ == "__main__":
    run_mock_server()