"""Bounded, synchronous retrieval of untrusted research-source content."""

import html
import ipaddress
import re
import socket
import ssl
import time
import zlib
from html.parser import HTMLParser
from typing import Any, Callable, Dict, Iterable, Optional, Sequence
from urllib.parse import urljoin, urlparse

import httpx
import httpcore


DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_BYTES = 1_000_000
DEFAULT_MAX_REDIRECTS = 3
PROCESSING_CHECK_INTERVAL = 64 * 1024
ALLOWED_CONTENT_TYPES = ("text/html", "text/plain")

Resolver = Callable[[str], Sequence[str]]


def _exception_chain(exc: BaseException) -> Iterable[BaseException]:
    """Yield an exception and its public cause/context chain."""
    seen = set()
    current: Optional[BaseException] = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = current.__cause__ or current.__context__


def _classify_request_exception(exc: BaseException) -> str:
    """Return a stable, sanitized category for an HTTPX request failure."""
    if isinstance(exc, httpx.TimeoutException):
        return "Request timed out."
    if any(isinstance(item, ssl.SSLError) for item in _exception_chain(exc)):
        return "TLS or certificate verification failed."
    if isinstance(exc, httpx.ConnectError):
        return "Connection failed."
    if isinstance(exc, (httpx.ReadError, httpx.WriteError)):
        return "Read/write transport failure."
    return "Network request failed."


class _PinnedNetworkStream(httpcore.NetworkStream):
    """Network stream backed by a socket connected to one literal IP."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock

    def read(self, max_bytes: int, timeout: Optional[float] = None) -> bytes:
        try:
            self._sock.settimeout(timeout)
            return self._sock.recv(max_bytes)
        except socket.timeout as exc:
            raise httpcore.ReadTimeout(str(exc)) from exc
        except OSError as exc:
            raise httpcore.ReadError(str(exc)) from exc

    def write(self, buffer: bytes, timeout: Optional[float] = None) -> None:
        try:
            while buffer:
                self._sock.settimeout(timeout)
                written = self._sock.send(buffer)
                buffer = buffer[written:]
        except socket.timeout as exc:
            raise httpcore.WriteTimeout(str(exc)) from exc
        except OSError as exc:
            raise httpcore.WriteError(str(exc)) from exc

    def close(self) -> None:
        self._sock.close()

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> httpcore.NetworkStream:
        try:
            self._sock.settimeout(timeout)
            tls_socket = ssl_context.wrap_socket(
                self._sock,
                server_hostname=server_hostname,
            )
        except socket.timeout as exc:
            self.close()
            raise httpcore.ConnectTimeout(str(exc)) from exc
        except OSError as exc:
            self.close()
            raise httpcore.ConnectError(str(exc)) from exc
        return _PinnedNetworkStream(tls_socket)

    def get_extra_info(self, info: str) -> Any:
        if info == "socket":
            return self._sock
        if info == "client_addr":
            return self._sock.getsockname()
        if info == "server_addr":
            return self._sock.getpeername()
        if info == "ssl_object" and isinstance(self._sock, ssl.SSLSocket):
            return self._sock._sslobj
        return None


class _PinnedNetworkBackend(httpcore.NetworkBackend):
    """Connect directly to a previously validated literal IP address."""

    def __init__(self, address: str) -> None:
        self.address = address

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options: Optional[Iterable[tuple[int, int, int]]] = None,
    ) -> httpcore.NetworkStream:
        del host  # The URL hostname is retained by httpcore for Host and TLS SNI.
        parsed_address = ipaddress.ip_address(self.address)
        family = socket.AF_INET6 if parsed_address.version == 6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            if socket_options:
                for option in socket_options:
                    sock.setsockopt(*option)
            sock.settimeout(timeout)
            if local_address:
                local = (
                    (local_address, 0, 0, 0)
                    if family == socket.AF_INET6
                    else (local_address, 0)
                )
                sock.bind(local)
            destination = (
                (self.address, port, 0, 0)
                if family == socket.AF_INET6
                else (self.address, port)
            )
            sock.connect(destination)
        except socket.timeout as exc:
            sock.close()
            raise httpcore.ConnectTimeout(str(exc)) from exc
        except OSError as exc:
            sock.close()
            raise httpcore.ConnectError(str(exc)) from exc
        return _PinnedNetworkStream(sock)

    def connect_unix_socket(
        self,
        path: str,
        timeout: Optional[float] = None,
        socket_options: Optional[Iterable[tuple[int, int, int]]] = None,
    ) -> httpcore.NetworkStream:
        raise httpcore.ConnectError("Unix sockets are not supported.")

    def sleep(self, seconds: float) -> None:
        return None


class _PinnedHTTPTransport(httpx.HTTPTransport):
    """HTTP transport that pins TCP connections to one validated IP.

    The request URL remains hostname-based.  httpcore therefore continues to
    use that hostname for HTTP Host generation and TLS certificate/SNI
    handling, while this backend supplies the literal TCP destination.
    """

    def __init__(self, address: str) -> None:
        super().__init__(
            verify=True,
            trust_env=False,
            limits=httpx.Limits(
                max_connections=1,
                max_keepalive_connections=0,
                keepalive_expiry=0,
            ),
        )
        pool = self._pool
        self._pool = httpcore.ConnectionPool(
            ssl_context=pool._ssl_context,
            max_connections=1,
            max_keepalive_connections=0,
            keepalive_expiry=0,
            http1=True,
            http2=False,
            retries=0,
            network_backend=_PinnedNetworkBackend(address),
        )


class _ReadableTextParser(HTMLParser):
    """Extract title and visible text without executing page content."""

    def __init__(self, deadline: Optional[float] = None) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts = []
        self.text_parts = []
        self.in_title = False
        self.skip_depth = 0
        self.deadline = deadline
        self.processed_bytes = 0

    def _check_deadline(self, data: str = "") -> None:
        self.processed_bytes += len(data)
        if (
            self.deadline is not None
            and self.processed_bytes >= PROCESSING_CHECK_INTERVAL
        ):
            self.processed_bytes = 0
            if time.monotonic() >= self.deadline:
                raise TimeoutError("Response processing deadline exceeded.")

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        self._check_deadline(tag)
        tag = tag.lower()
        if self.in_title and tag != "title":
            self.in_title = False
        if tag == "title":
            self.in_title = True
        if tag in {"script", "style", "noscript", "template"}:
            self.skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        self._check_deadline(tag)
        tag = tag.lower()
        if tag == "title":
            self.in_title = False
        if tag in {"script", "style", "noscript", "template"} and self.skip_depth:
            self.skip_depth -= 1

    def handle_data(self, data: str) -> None:
        self._check_deadline(data)
        if self.in_title:
            self.title_parts.append(data)
            return
        if not self.skip_depth and data.strip():
            self.text_parts.append(data.strip())

    @property
    def title(self) -> Optional[str]:
        value = " ".join(self.title_parts).strip()
        return value or None

    @property
    def text(self) -> str:
        return " ".join(self.text_parts).strip()


def _default_resolver(host: str) -> Sequence[str]:
    addresses = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return list({entry[4][0] for entry in addresses})


def _is_public_address(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return parsed.is_global


def _resolve_validated_address(
    url: str,
    resolver: Resolver,
) -> tuple[Optional[str], Optional[str]]:
    try:
        parsed = urlparse(url)
    except ValueError as exc:
        return None, f"Malformed URL: {exc}"
    if parsed.scheme.lower() not in {"http", "https"}:
        return None, "Unsupported URL scheme. Only http and https are allowed."
    if not parsed.hostname:
        return None, "Malformed URL: URL does not contain a hostname."
    if parsed.username or parsed.password:
        return None, "URLs containing embedded credentials are not allowed."

    try:
        literal_address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        literal_address = None
    if literal_address is not None:
        if not literal_address.is_global:
            return None, "Destination resolves to a non-public IP address."
        return str(literal_address), None

    try:
        addresses = resolver(parsed.hostname)
    except (OSError, socket.gaierror):
        return None, "DNS resolution failed."
    if not addresses:
        return None, "DNS resolution returned no addresses."
    normalized_addresses = []
    for address in addresses:
        try:
            normalized = str(ipaddress.ip_address(address))
        except ValueError:
            return None, "DNS resolution returned an invalid address."
        normalized_addresses.append(normalized)
    if any(not _is_public_address(address) for address in normalized_addresses):
        return None, "Destination resolves to a non-public IP address."
    return normalized_addresses[0], None


def _validate_destination(url: str, resolver: Resolver) -> Optional[str]:
    """Preserve the existing validation helper's error-only contract."""
    _, error = _resolve_validated_address(url, resolver)
    return error


def _result(
    url: str,
    status: str,
    *,
    final_url: Optional[str] = None,
    status_code: Optional[int] = None,
    title: Optional[str] = None,
    text: str = "",
    error: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "url": url,
        "final_url": final_url,
        "status_code": status_code,
        "title": title,
        "text": text,
        "retrieval_status": status,
        "error": error,
    }


def _content_type(response: httpx.Response) -> str:
    return response.headers.get("content-type", "").split(";", 1)[0].strip().lower()


def _parse_html(
    text: str,
    deadline: Optional[float] = None,
) -> tuple[Optional[str], str]:
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError("Response processing deadline exceeded.")
    title_match = re.search(
        r"<title\b[^>]*>(.*?)(?:</title\s*>|(?=<(?:body|head|html)\b)|$)",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    title = html.unescape(title_match.group(1).strip()) if title_match else None
    content = (
        text[: title_match.start()] + text[title_match.end() :]
        if title_match
        else text
    )
    parser = _ReadableTextParser(deadline)
    parser.feed(content)
    parser.close()
    return title or parser.title, parser.text


class _ResponseTooLarge(ValueError):
    pass


class _ResponseDecodeError(ValueError):
    pass


class _BoundedDecoder:
    """Incrementally decode identity, gzip, and deflate with bounded output.

    Brotli, zstd, and multi-layer encodings are rejected because no supported
    dependency is available for bounded decoding.
    """

    _CHUNK_SIZE = 64 * 1024

    def __init__(self, content_encoding: str) -> None:
        encodings = [
            value.strip().lower()
            for value in content_encoding.split(",")
            if value.strip()
        ]
        if not encodings or encodings == ["identity"]:
            self.encoding = "identity"
        elif len(encodings) == 1 and encodings[0] in {"gzip", "deflate"}:
            self.encoding = encodings[0]
        else:
            raise _ResponseDecodeError(
                f"Unsupported content encoding: {content_encoding or 'unknown'}."
            )
        self._decoder = None
        self._deflate_first_chunk = self.encoding == "deflate"
        self._deflate_buffer = bytearray()
        if self.encoding == "gzip":
            self._decoder = zlib.decompressobj(zlib.MAX_WBITS | 16)
        elif self.encoding == "deflate":
            self._decoder = zlib.decompressobj()

    def _decode_compressed(
        self,
        chunk: bytes,
        remaining: int,
    ) -> list[bytes]:
        if remaining <= 0:
            limit = 1
        else:
            limit = min(self._CHUNK_SIZE, remaining + 1)
        try:
            decoded = self._decoder.decompress(chunk, limit)
        except zlib.error as exc:
            if self._deflate_first_chunk:
                self._decoder = zlib.decompressobj(-zlib.MAX_WBITS)
                self._deflate_first_chunk = False
                try:
                    decoded = self._decoder.decompress(chunk, limit)
                except zlib.error as raw_exc:
                    raise _ResponseDecodeError(str(raw_exc)) from raw_exc
            else:
                raise _ResponseDecodeError(str(exc)) from exc
        if len(decoded) > remaining:
            raise _ResponseTooLarge("Response body exceeds the configured byte limit.")
        return [decoded] if decoded else []

    def decode(
        self,
        raw_chunks: Iterable[bytes],
        max_bytes: int,
        deadline: Optional[float] = None,
    ) -> Iterable[bytes]:
        if self.encoding == "identity":
            for chunk in raw_chunks:
                if deadline is not None and time.monotonic() >= deadline:
                    raise TimeoutError("Response processing deadline exceeded.")
                if len(chunk) > max_bytes:
                    raise _ResponseTooLarge(
                        "Response body exceeds the configured byte limit."
                    )
                if chunk:
                    yield chunk
            return

        decoded_size = 0
        for raw_chunk in raw_chunks:
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError("Response processing deadline exceeded.")
            if not raw_chunk:
                continue
            offset = 0
            while offset < len(raw_chunk):
                if self.encoding == "gzip" and self._decoder.eof:
                    self._decoder = zlib.decompressobj(zlib.MAX_WBITS | 16)
                elif self.encoding == "deflate" and self._decoder.eof:
                    raise _ResponseDecodeError(
                        "Trailing data after deflate stream."
                    )
                compressed_chunk = raw_chunk[offset : offset + self._CHUNK_SIZE]
                offset += len(compressed_chunk)
                if self._deflate_first_chunk:
                    self._deflate_buffer.extend(compressed_chunk)
                    compressed_chunk = bytes(self._deflate_buffer)
                for decoded in self._decode_compressed(
                    compressed_chunk,
                    max_bytes - decoded_size,
                ):
                    decoded_size += len(decoded)
                    yield decoded
                self._deflate_first_chunk = False
                if self._deflate_buffer:
                    self._deflate_buffer.clear()
                while self._decoder.eof and self._decoder.unused_data:
                    if self.encoding != "gzip":
                        raise _ResponseDecodeError(
                            "Trailing data after deflate stream."
                        )
                    trailing = self._decoder.unused_data
                    self._decoder = zlib.decompressobj(zlib.MAX_WBITS | 16)
                    for decoded in self._decode_compressed(
                        trailing,
                        max_bytes - decoded_size,
                    ):
                        decoded_size += len(decoded)
                        yield decoded

        if not self._decoder.eof:
            raise _ResponseDecodeError("Compressed response ended before the stream.")
        while True:
            remaining = max_bytes - decoded_size
            flush_limit = min(self._CHUNK_SIZE, remaining + 1)
            try:
                flushed = self._decoder.flush(flush_limit)
            except zlib.error as exc:
                raise _ResponseDecodeError(str(exc)) from exc
            if len(flushed) > remaining:
                raise _ResponseTooLarge("Response body exceeds the configured byte limit.")
            if flushed:
                decoded_size += len(flushed)
                yield flushed
            if len(flushed) < flush_limit:
                break


def _read_limited(
    response: httpx.Response,
    max_bytes: int,
    deadline: Optional[float] = None,
) -> bytes:
    body = bytearray()
    decoder = _BoundedDecoder(response.headers.get("content-encoding", ""))
    raw_chunks = (
        (response._content,)
        if hasattr(response, "_content")
        else response.iter_raw()
    )
    for chunk in decoder.decode(raw_chunks, max_bytes, deadline):
        if len(body) + len(chunk) > max_bytes:
            raise _ResponseTooLarge(
                f"Response body exceeds the {max_bytes}-byte limit."
            )
        body.extend(chunk)
    return bytes(body)


def retrieve_source(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    client: Optional[httpx.Client] = None,
    resolver: Resolver = _default_resolver,
) -> Dict[str, Any]:
    """Retrieve one public HTTP(S) source without executing page content.

    Internally created clients use a fresh, non-pooled transport for each
    validated request.  The transport connects to the validated literal IP
    while the URL hostname remains available for HTTP Host and TLS identity.
    The optional ``client`` is an explicit offline/testing injection seam:
    externally supplied clients remain caller-controlled and do not receive
    DNS address pinning, proxy isolation, or pooling guarantees from this
    function. Callers handling untrusted URLs must leave ``client`` as ``None``
    and use the internally created pinned client.
    """
    original_url = url if isinstance(url, str) else ""
    if not isinstance(url, str) or not url.strip():
        return _result(original_url, "invalid_url", error="URL must be a non-empty string.")
    if timeout <= 0 or max_bytes <= 0 or max_redirects < 0:
        return _result(original_url, "invalid_url", error="Retrieval limits are invalid.")

    current_url = url.strip()
    own_client = client is None

    try:
        for redirect_count in range(max_redirects + 1):
            validated_address, destination_error = _resolve_validated_address(
                current_url,
                resolver,
            )
            if destination_error:
                status = (
                    "unsupported_url"
                    if "scheme" in destination_error.lower()
                    else "malformed_url"
                    if "malformed" in destination_error.lower()
                    else "network_error"
                    if destination_error.startswith("DNS resolution")
                    else "blocked_destination"
                )
                return _result(original_url, status, final_url=current_url, error=destination_error)

            request_client = client
            if own_client:
                request_client = httpx.Client(
                    transport=_PinnedHTTPTransport(validated_address),
                    follow_redirects=False,
                    timeout=timeout,
                    trust_env=False,
                )
            try:
                response_context = request_client.stream(
                    "GET",
                    current_url,
                    follow_redirects=False,
                    headers={"Accept": "text/html, text/plain"},
                )
                with response_context as response:
                    if 300 <= response.status_code < 400:
                        location = response.headers.get("location")
                        if not location:
                            return _result(
                                original_url,
                                "http_error",
                                final_url=str(response.url),
                                status_code=response.status_code,
                                error="Redirect response did not include a Location header.",
                            )
                        if redirect_count == max_redirects:
                            return _result(
                                original_url,
                                "redirect_limit_exceeded",
                                final_url=str(response.url),
                                status_code=response.status_code,
                                error=f"Redirect limit of {max_redirects} exceeded.",
                            )
                        current_url = urljoin(str(response.url), location)
                        continue

                    final_url = str(response.url)
                    if response.status_code >= 400:
                        return _result(
                            original_url,
                            "http_error",
                            final_url=final_url,
                            status_code=response.status_code,
                            error=f"HTTP error {response.status_code}.",
                        )

                    content_type = _content_type(response)
                    if content_type not in ALLOWED_CONTENT_TYPES:
                        return _result(
                            original_url,
                            "unsupported_content_type",
                            final_url=final_url,
                            status_code=response.status_code,
                            error=f"Unsupported content type: {content_type or 'missing'}.",
                        )

                    processing_deadline = time.monotonic() + timeout
                    try:
                        body = _read_limited(
                            response,
                            max_bytes,
                            processing_deadline,
                        )
                    except _ResponseTooLarge as exc:
                        return _result(
                            original_url,
                            "response_too_large",
                            final_url=final_url,
                            status_code=response.status_code,
                            error=str(exc),
                        )
                    except _ResponseDecodeError as exc:
                        if str(exc).startswith("Unsupported content encoding:"):
                            decode_error = str(exc)
                        else:
                            decode_error = "Response decompression failed."
                        return _result(
                            original_url,
                            "network_error",
                            final_url=final_url,
                            status_code=response.status_code,
                            error=decode_error,
                        )
                    except TimeoutError as exc:
                        return _result(
                            original_url,
                            "timeout",
                            final_url=final_url,
                            status_code=response.status_code,
                            error=str(exc),
                        )

                    if not body:
                        return _result(
                            original_url,
                            "empty_response",
                            final_url=final_url,
                            status_code=response.status_code,
                        )

                    decoded = body.decode(response.encoding or "utf-8", errors="replace")
                    if content_type == "text/plain":
                        return _result(
                            original_url,
                            "retrieved",
                            final_url=final_url,
                            status_code=response.status_code,
                            text=decoded.strip(),
                        )

                    try:
                        title, readable_text = _parse_html(decoded, processing_deadline)
                    except TimeoutError:
                        return _result(
                            original_url,
                            "timeout",
                            final_url=final_url,
                            status_code=response.status_code,
                            error="Response processing deadline exceeded.",
                        )
                    except Exception:
                        return _result(
                            original_url,
                            "parse_error",
                            final_url=final_url,
                            status_code=response.status_code,
                            error="Response parsing failed.",
                        )
                    return _result(
                        original_url,
                        "retrieved",
                        final_url=final_url,
                        status_code=response.status_code,
                        title=title,
                        text=readable_text,
                    )
            except httpx.TimeoutException:
                return _result(
                    original_url,
                    "timeout",
                    final_url=current_url,
                    error="Request timed out.",
                )
            except httpx.RequestError as exc:
                return _result(
                    original_url,
                    "network_error",
                    final_url=current_url,
                    error=_classify_request_exception(exc),
                )
            finally:
                if own_client:
                    request_client.close()
    except Exception:
        return _result(
            original_url,
            "pipeline_error",
            final_url=current_url,
            error="Source retrieval failed unexpectedly.",
        )

    return _result(original_url, "network_error", final_url=current_url, error="No response received.")
