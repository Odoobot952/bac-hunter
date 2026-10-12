"""
Parses a raw HTTP request (e.g. Burp Suite "Copy as raw request" output,
or a plain .txt file you write by hand) into a structured dict that the
rest of the tool can work with.

Expected input format:

    GET /api/users/42/profile HTTP/1.1
    Host: target.example.com
    Cookie: session=abc123
    User-Agent: Mozilla/5.0

    {"optional": "body for POST/PUT"}

Blank line separates headers from body (standard HTTP). Host can also be
overridden via --base-url on the CLI if you're pointing the same request
at a different environment.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from urllib.parse import urlsplit


@dataclass
class ParsedRequest:
    method: str
    path: str
    headers: dict = field(default_factory=dict)
    body: str = ""
    host: str = ""
    scheme: str = "https"

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.host}{self.path}"


def parse_raw_request(raw_text: str, base_url: str | None = None) -> ParsedRequest:
    raw_text = raw_text.replace("\r\n", "\n")
    lines = raw_text.split("\n")

    if not lines or not lines[0].strip():
        raise ValueError("Empty or invalid raw request file.")

    request_line = lines[0].strip()
    try:
        method, path, _version = request_line.split(" ", 2)
    except ValueError:
        raise ValueError(f"Could not parse request line: {request_line!r}")

    headers = {}
    body_lines: list[str] = []
    in_body = False

    for line in lines[1:]:
        if not in_body:
            if line.strip() == "":
                in_body = True
                continue
            if ":" in line:
                key, _, value = line.partition(":")
                headers[key.strip()] = value.strip()
        else:
            body_lines.append(line)

    body = "\n".join(body_lines).strip()

    host = headers.get("Host", "")
    scheme = "https"

    if base_url:
        parts = urlsplit(base_url)
        host = parts.netloc or host
        scheme = parts.scheme or scheme

    return ParsedRequest(
        method=method.upper(),
        path=path,
        headers=headers,
        body=body,
        host=host,
        scheme=scheme,
    )


def load_request_file(path: str, base_url: str | None = None) -> ParsedRequest:
    with open(path, "r", encoding="utf-8") as f:
        return parse_raw_request(f.read(), base_url=base_url)
