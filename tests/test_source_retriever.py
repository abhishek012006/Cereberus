"""Offline tests for the bounded source retriever."""

import socket
import unittest
import os
import ssl
import subprocess
import tempfile
import threading
import gzip
import zlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx

import agents.source_retriever as source_retriever
from agents.source_retriever import retrieve_source


PUBLIC_IP = "93.184.216.34"


def resolver(_host):
    return [PUBLIC_IP]


def client_for(handler):
    return httpx.Client(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
    )


class TrackingStream(httpx.SyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.closed = False

    def __iter__(self):
        yield from self.chunks

    def close(self):
        self.closed = True


class LocalTLSServer:
    def __init__(self, certificate: Path, key: Path):
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self._listener.settimeout(0.5)
        self.port = self._listener.getsockname()[1]
        self.sni = None
        self.host = None
        self.handshake_failed = threading.Event()
        self._stopped = threading.Event()
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.load_cert_chain(certificate, key)
        self._context.set_servername_callback(self._capture_sni)
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _capture_sni(self, _ssl_socket, server_name, _context):
        self.sni = server_name

    def _serve(self):
        try:
            while not self._stopped.is_set():
                try:
                    connection, _address = self._listener.accept()
                except socket.timeout:
                    continue
                try:
                    with connection:
                        try:
                            with self._context.wrap_socket(connection, server_side=True) as tls:
                                request = tls.recv(4096)
                                headers = request.decode("ascii", errors="replace").split("\r\n")
                                self.host = next(
                                    line.split(":", 1)[1].strip()
                                    for line in headers
                                    if line.lower().startswith("host:")
                                )
                                tls.sendall(
                                    b"HTTP/1.1 200 OK\r\n"
                                    b"Content-Type: text/html\r\n"
                                    b"Content-Length: 58\r\n"
                                    b"Connection: close\r\n\r\n"
                                    b"<html><title>Local TLS</title><body>Verified</body></html>"
                                )
                        except (OSError, ssl.SSLError):
                            self.handshake_failed.set()
                finally:
                    self._stopped.set()
        finally:
            self._stopped.set()

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, _exc_type, _exc_value, _traceback):
        self._stopped.set()
        self._listener.close()
        self._thread.join(timeout=2)

    @property
    def thread_alive(self):
        return self._thread.is_alive()


def create_test_certificate(directory: Path, hostname: str, name: str):
    certificate = directory / f"{name}.pem"
    key = directory / f"{name}.key"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
            "-days",
            "1",
            "-subj",
            f"/CN={hostname}",
            "-addext",
            f"subjectAltName=DNS:{hostname}",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return certificate, key


class TestSourceRetriever(unittest.TestCase):
    def test_injected_client_boundary_is_explicitly_documented(self):
        documentation = retrieve_source.__doc__ or ""
        self.assertIn("offline/testing injection seam", documentation)
        self.assertIn("do not receive", documentation)
        self.assertIn("DNS address pinning", documentation)

    def test_html_title_and_readable_text(self):
        def handler(request):
            return httpx.Response(
                200,
                headers={"content-type": "text/html; charset=utf-8"},
                content=b"<html><head><title> Advisory </title></head><body><p>Hello</p><script>ignore()</script><p>World</p></body></html>",
                request=request,
            )

        with client_for(handler) as client:
            result = retrieve_source("https://example.com/a", client=client, resolver=resolver)

        self.assertEqual(result["retrieval_status"], "retrieved")
        self.assertEqual(result["title"], "Advisory")
        self.assertEqual(result["text"], "Hello World")

    def test_plain_text_response(self):
        def handler(request):
            return httpx.Response(200, headers={"content-type": "text/plain"}, text="CVE details", request=request)

        with client_for(handler) as client:
            result = retrieve_source("https://example.com/a", client=client, resolver=resolver)

        self.assertEqual(result["text"], "CVE details")
        self.assertIsNone(result["title"])

    def test_http_error_timeout_and_network_failure(self):
        def error_handler(request):
            return httpx.Response(404, request=request)

        with client_for(error_handler) as client:
            result = retrieve_source("https://example.com/a", client=client, resolver=resolver)
        self.assertEqual(result["retrieval_status"], "http_error")
        self.assertEqual(result["status_code"], 404)

        timeout_client = MagicMock()
        timeout_client.stream.side_effect = httpx.ReadTimeout("timed out")
        result = retrieve_source("https://example.com/a", client=timeout_client, resolver=resolver)
        self.assertEqual(result["retrieval_status"], "timeout")
        self.assertEqual(result["error"], "Request timed out.")

        network_client = MagicMock()
        network_client.stream.side_effect = httpx.ConnectError("offline")
        result = retrieve_source("https://example.com/a", client=network_client, resolver=resolver)
        self.assertEqual(result["retrieval_status"], "network_error")
        self.assertEqual(result["error"], "Connection failed.")

        read_client = MagicMock()
        read_client.stream.side_effect = httpx.ReadError("secret transport detail")
        result = retrieve_source("https://example.com/a", client=read_client, resolver=resolver)
        self.assertEqual(result["retrieval_status"], "network_error")
        self.assertEqual(result["error"], "Read/write transport failure.")

        write_client = MagicMock()
        write_client.stream.side_effect = httpx.WriteError("secret write detail")
        result = retrieve_source("https://example.com/a", client=write_client, resolver=resolver)
        self.assertEqual(result["retrieval_status"], "network_error")
        self.assertEqual(result["error"], "Read/write transport failure.")

    def test_unexpected_exception_is_sanitized_as_pipeline_error(self):
        client = MagicMock()
        client.stream.side_effect = ValueError("raw secret exception")

        result = retrieve_source("https://example.com/a", client=client, resolver=resolver)

        self.assertEqual(result["retrieval_status"], "pipeline_error")
        self.assertEqual(result["error"], "Source retrieval failed unexpectedly.")
        self.assertNotIn("raw secret exception", result["error"])
        self.assertNotIn("raw secret exception", repr(result))

    def test_parser_exception_remains_parse_error_and_is_sanitized(self):
        def handler(request):
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                text="<html>content</html>",
                request=request,
            )

        with client_for(handler) as client, patch.object(
            source_retriever,
            "_parse_html",
            side_effect=ValueError("raw parser detail"),
        ):
            result = retrieve_source("https://example.com/a", client=client, resolver=resolver)

        self.assertEqual(result["retrieval_status"], "parse_error")
        self.assertEqual(result["error"], "Response parsing failed.")
        self.assertNotIn("raw parser detail", repr(result))

    def test_unsupported_content_type_and_empty_response(self):
        def handler(request):
            return httpx.Response(200, headers={"content-type": "application/pdf"}, content=b"pdf", request=request)

        with client_for(handler) as client:
            result = retrieve_source("https://example.com/a", client=client, resolver=resolver)
        self.assertEqual(result["retrieval_status"], "unsupported_content_type")

        def empty_handler(request):
            return httpx.Response(200, headers={"content-type": "text/plain"}, content=b"", request=request)

        with client_for(empty_handler) as client:
            result = retrieve_source("https://example.com/a", client=client, resolver=resolver)
        self.assertEqual(result["retrieval_status"], "empty_response")

    def test_oversized_chunked_response(self):
        def handler(request):
            return httpx.Response(
                200,
                headers={"content-type": "text/plain"},
                content=b"0123456789",
                request=request,
            )

        with client_for(handler) as client:
            result = retrieve_source("https://example.com/a", max_bytes=5, client=client, resolver=resolver)
        self.assertEqual(result["retrieval_status"], "response_too_large")

    def test_bounded_decoding_supports_gzip_and_deflate(self):
        payload = b"decoded source content"
        encoded = (
            ("gzip", gzip.compress(payload)),
            ("deflate", zlib.compress(payload)),
        )
        for content_encoding, compressed in encoded:
            def handler(request, content_encoding=content_encoding, compressed=compressed):
                return httpx.Response(
                    200,
                    headers={
                        "content-type": "text/plain",
                        "content-encoding": content_encoding,
                    },
                    stream=TrackingStream([compressed]),
                    request=request,
                )

            with self.subTest(content_encoding=content_encoding), client_for(handler) as client:
                result = retrieve_source(
                    "https://example.com/a",
                    client=client,
                    resolver=resolver,
                )
            self.assertEqual(result["retrieval_status"], "retrieved")
            self.assertEqual(result["text"], payload.decode())

    def test_bounded_decoding_enforces_decoded_size(self):
        payload = b"A" * 1024
        compressed = gzip.compress(payload)

        def handler(request):
            return httpx.Response(
                200,
                headers={
                    "content-type": "text/plain",
                    "content-encoding": "gzip",
                },
                stream=TrackingStream([compressed]),
                request=request,
            )

        for max_bytes, expected_status in ((1024, "retrieved"), (1023, "response_too_large")):
            with self.subTest(max_bytes=max_bytes), client_for(handler) as client:
                result = retrieve_source(
                    "https://example.com/a",
                    max_bytes=max_bytes,
                    client=client,
                    resolver=resolver,
                )
            self.assertEqual(result["retrieval_status"], expected_status)

    def test_bounded_decoder_limits_one_decompression_operation(self):
        compressed = gzip.compress(b"A" * 1_000_000)
        decoder = source_retriever._BoundedDecoder("gzip")

        with self.assertRaises(source_retriever._ResponseTooLarge):
            list(decoder.decode([compressed], 1024))

    def test_processing_deadline_is_checked_during_decoding(self):
        stream = TrackingStream([b"plain content"])

        def handler(request):
            return httpx.Response(
                200,
                headers={"content-type": "text/plain"},
                stream=stream,
                request=request,
            )

        with patch.object(source_retriever.time, "monotonic", side_effect=(0, 1)):
            with client_for(handler) as client:
                result = retrieve_source(
                    "https://example.com/a",
                    timeout=1,
                    client=client,
                    resolver=resolver,
                )

        self.assertEqual(result["retrieval_status"], "timeout")
        self.assertIn("processing deadline", result["error"])
        self.assertTrue(stream.closed)

    def test_html_processing_checks_deadline_without_sleeping(self):
        with self.assertRaisesRegex(TimeoutError, "processing deadline"):
            source_retriever._parse_html("A" * 100, deadline=0)

    def test_bounded_decoding_rejects_malformed_truncated_and_empty_input(self):
        cases = (b"not gzip", gzip.compress(b"truncated")[:-3], b"")
        for compressed in cases:
            def handler(request, compressed=compressed):
                return httpx.Response(
                    200,
                    headers={
                        "content-type": "text/plain",
                        "content-encoding": "gzip",
                    },
                    stream=TrackingStream([compressed]),
                    request=request,
                )

            with self.subTest(compressed=compressed), client_for(handler) as client:
                result = retrieve_source(
                    "https://example.com/a",
                    client=client,
                    resolver=resolver,
                )
            self.assertEqual(result["retrieval_status"], "network_error")
            self.assertEqual(result["error"], "Response decompression failed.")

    def test_bounded_decoding_supports_concatenated_gzip_members(self):
        compressed = gzip.compress(b"first ") + gzip.compress(b"member")

        def handler(request):
            return httpx.Response(
                200,
                headers={
                    "content-type": "text/plain",
                    "content-encoding": "gzip",
                },
                stream=TrackingStream([compressed]),
                request=request,
            )

        with client_for(handler) as client:
            result = retrieve_source(
                "https://example.com/a",
                client=client,
                resolver=resolver,
            )
        self.assertEqual(result["retrieval_status"], "retrieved")
        self.assertEqual(result["text"], "first member")

    def test_unsupported_content_encoding_is_explicitly_rejected(self):
        for content_encoding in ("br", "zstd"):
            def handler(request, content_encoding=content_encoding):
                return httpx.Response(
                    200,
                    headers={
                        "content-type": "text/plain",
                        "content-encoding": content_encoding,
                    },
                    stream=TrackingStream([b"encoded"]),
                    request=request,
                )

            with self.subTest(content_encoding=content_encoding), client_for(handler) as client:
                result = retrieve_source(
                    "https://example.com/a",
                    client=client,
                    resolver=resolver,
                )
            self.assertEqual(result["retrieval_status"], "network_error")
            self.assertIn("Unsupported content encoding", result["error"])

    def test_decompression_failure_closes_stream(self):
        stream = TrackingStream([b"invalid gzip"])

        def handler(request):
            return httpx.Response(
                200,
                headers={
                    "content-type": "text/plain",
                    "content-encoding": "gzip",
                },
                stream=stream,
                request=request,
            )

        with client_for(handler) as client:
            result = retrieve_source(
                "https://example.com/a",
                client=client,
                resolver=resolver,
            )
        self.assertEqual(result["retrieval_status"], "network_error")
        self.assertTrue(stream.closed)

    def test_malformed_html_is_handled(self):
        def handler(request):
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                content=b"<html><title>Broken<body>Visible <b>text",
                request=request,
            )

        with client_for(handler) as client:
            result = retrieve_source("https://example.com/a", client=client, resolver=resolver)
        self.assertEqual(result["retrieval_status"], "retrieved")
        self.assertEqual(result["title"], "Broken")
        self.assertIn("Visible text", result["text"])

    def test_unsupported_and_malformed_urls(self):
        result = retrieve_source("ftp://example.com/file", resolver=resolver)
        self.assertEqual(result["retrieval_status"], "unsupported_url")

        result = retrieve_source("https://", resolver=resolver)
        self.assertEqual(result["retrieval_status"], "malformed_url")

        result = retrieve_source("https://user:pass@example.com/", resolver=resolver)
        self.assertEqual(result["retrieval_status"], "blocked_destination")

    def test_private_and_loopback_destinations_are_rejected(self):
        for url in ("http://127.0.0.1/", "http://localhost/"):
            result = retrieve_source(url, resolver=lambda _host: ["127.0.0.1"])
            self.assertEqual(result["retrieval_status"], "blocked_destination")

        result = retrieve_source("https://example.com/", resolver=lambda _host: ["10.0.0.5"])
        self.assertEqual(result["retrieval_status"], "blocked_destination")

    def test_redirect_is_manual_and_final_url_is_preserved(self):
        def handler(request):
            if request.url.path == "/start":
                return httpx.Response(302, headers={"location": "/final"}, request=request)
            return httpx.Response(200, headers={"content-type": "text/plain"}, text="done", request=request)

        with client_for(handler) as client:
            result = retrieve_source("https://example.com/start", client=client, resolver=resolver)
        self.assertEqual(result["retrieval_status"], "retrieved")
        self.assertEqual(result["final_url"], "https://example.com/final")

    def test_redirect_to_private_destination_is_rejected(self):
        def handler(request):
            return httpx.Response(302, headers={"location": "http://internal.test/"}, request=request)

        def redirect_resolver(host):
            return ["10.0.0.2"] if host == "internal.test" else [PUBLIC_IP]

        with client_for(handler) as client:
            result = retrieve_source("https://example.com/start", client=client, resolver=redirect_resolver)
        self.assertEqual(result["retrieval_status"], "blocked_destination")

    def test_redirect_limit_is_enforced(self):
        def handler(request):
            return httpx.Response(302, headers={"location": f"/{request.url.path.strip('/')}/next"}, request=request)

        with client_for(handler) as client:
            result = retrieve_source("https://example.com/start", max_redirects=2, client=client, resolver=resolver)
        self.assertEqual(result["retrieval_status"], "redirect_limit_exceeded")
        self.assertEqual(result["status_code"], 302)

    def test_dns_resolution_failure_is_explicit(self):
        result = retrieve_source(
            "https://example.com/",
            resolver=lambda _host: (_ for _ in ()).throw(socket.gaierror("no DNS")),
        )
        self.assertEqual(result["retrieval_status"], "network_error")
        self.assertIn("DNS resolution failed", result["error"])

    def test_pinned_backend_connects_to_validated_ipv4(self):
        fake_socket = MagicMock()
        with patch.object(source_retriever.socket, "socket", return_value=fake_socket):
            stream = source_retriever._PinnedNetworkBackend(
                "93.184.216.34"
            ).connect_tcp("rebinding.example", 443, timeout=2.5)

        fake_socket.settimeout.assert_called_once_with(2.5)
        fake_socket.connect.assert_called_once_with(("93.184.216.34", 443))
        self.assertIsInstance(stream, source_retriever._PinnedNetworkStream)

    def test_pinned_backend_ipv6_destination_is_exact(self):
        fake_socket = MagicMock()
        with patch.object(
            source_retriever.socket,
            "socket",
            return_value=fake_socket,
        ) as socket_factory:
            source_retriever._PinnedNetworkBackend(
                "2001:4860:4860::8888"
            ).connect_tcp("rebinding.example", 443)

        socket_factory.assert_called_once_with(socket.AF_INET6, socket.SOCK_STREAM)
        fake_socket.connect.assert_called_once_with(
            ("2001:4860:4860::8888", 443, 0, 0)
        )

    def test_resolver_change_cannot_change_pinned_transport_destination(self):
        resolver_calls = []
        transport_addresses = []

        class FakeTransport:
            def __init__(self, address):
                transport_addresses.append(address)

            def handle_request(self, request):
                return httpx.Response(
                    200,
                    headers={"content-type": "text/plain"},
                    text="safe",
                    request=request,
                )

            def close(self):
                return None

        def changing_resolver(host):
            resolver_calls.append(host)
            return ["93.184.216.34"] if len(resolver_calls) == 1 else ["127.0.0.1"]

        with patch.object(source_retriever, "_PinnedHTTPTransport", FakeTransport):
            result = retrieve_source(
                "https://rebinding.example/report",
                resolver=changing_resolver,
            )

        self.assertEqual(result["retrieval_status"], "retrieved")
        self.assertEqual(resolver_calls, ["rebinding.example"])
        self.assertEqual(transport_addresses, ["93.184.216.34"])

    def test_redirect_public_destination_gets_independent_pin(self):
        transport_addresses = []

        class FakeTransport:
            def __init__(self, address):
                transport_addresses.append(address)

            def handle_request(self, request):
                if request.url.path == "/start":
                    return httpx.Response(
                        302,
                        headers={"location": "https://second.example/final"},
                        request=request,
                    )
                return httpx.Response(
                    200,
                    headers={"content-type": "text/plain"},
                    text="safe",
                    request=request,
                )

            def close(self):
                return None

        def resolver(host):
            return {
                "first.example": ["93.184.216.34"],
                "second.example": ["142.250.72.14"],
            }[host]

        with patch.object(source_retriever, "_PinnedHTTPTransport", FakeTransport):
            result = retrieve_source(
                "https://first.example/start",
                resolver=resolver,
            )

        self.assertEqual(result["retrieval_status"], "retrieved")
        self.assertEqual(result["final_url"], "https://second.example/final")
        self.assertEqual(transport_addresses, ["93.184.216.34", "142.250.72.14"])

    def test_pinned_transport_keeps_tls_verification_enabled(self):
        transport = source_retriever._PinnedHTTPTransport("93.184.216.34")
        try:
            ssl_context = transport._pool._ssl_context
            self.assertEqual(ssl_context.verify_mode, source_retriever.ssl.CERT_REQUIRED)
            self.assertTrue(ssl_context.check_hostname)
            self.assertIsInstance(
                transport._pool._network_backend,
                source_retriever._PinnedNetworkBackend,
            )
            self.assertEqual(transport._pool._max_keepalive_connections, 0)
            self.assertIsNone(transport._pool._proxy)
        finally:
            transport.close()

    def test_tls_sni_uses_original_hostname(self):
        fake_socket = MagicMock()
        fake_context = MagicMock()
        fake_context.wrap_socket.return_value = fake_socket
        stream = source_retriever._PinnedNetworkStream(fake_socket)

        stream.start_tls(fake_context, server_hostname="rebinding.example", timeout=3)

        fake_context.wrap_socket.assert_called_once_with(
            fake_socket,
            server_hostname="rebinding.example",
        )

    def test_pinned_path_preserves_hostname_and_ignores_proxy_environment(self):
        captured = []
        requests = []

        class FakeTransport:
            def __init__(self, address):
                captured.append(address)

            def handle_request(self, request):
                requests.append(request)
                self.request = request
                return httpx.Response(
                    200,
                    headers={"content-type": "text/plain"},
                    text="safe",
                    request=request,
                )

            def close(self):
                return None

        with patch.dict(
            os.environ,
            {"HTTP_PROXY": "http://127.0.0.1:9", "HTTPS_PROXY": "http://127.0.0.1:9"},
            clear=False,
        ), patch.object(source_retriever, "_PinnedHTTPTransport", FakeTransport):
            result = retrieve_source(
                "https://original.example/report",
                resolver=lambda host: ["93.184.216.34"],
            )

        self.assertEqual(result["retrieval_status"], "retrieved")
        self.assertEqual(captured, ["93.184.216.34"])
        self.assertEqual(str(requests[0].url), "https://original.example/report")
        self.assertEqual(requests[0].url.host, "original.example")
        self.assertEqual(requests[0].headers["host"], "original.example")

    def test_mixed_and_restricted_addresses_fail_closed(self):
        for addresses in (
            ["93.184.216.34", "10.0.0.1"],
            ["127.0.0.1"],
            ["169.254.169.254"],
            ["0.0.0.0"],
            ["::1"],
            ["fe80::1"],
        ):
            result = retrieve_source(
                "https://restricted.example/",
                resolver=lambda _host, values=addresses: values,
            )
            self.assertEqual(result["retrieval_status"], "blocked_destination")

    def test_real_pinned_transport_successfully_retrieves_https(self):
        hostname = "tls.example.test"
        with tempfile.TemporaryDirectory() as temporary_directory:
            certificate, key = create_test_certificate(
                Path(temporary_directory), hostname, "matching"
            )
            with LocalTLSServer(certificate, key) as server:
                original_transport = source_retriever._PinnedHTTPTransport

                def trusted_transport(address):
                    transport = original_transport(address)
                    transport._pool._ssl_context.load_verify_locations(
                        cafile=str(certificate)
                    )
                    return transport

                with patch.object(
                    source_retriever, "_PinnedHTTPTransport", trusted_transport
                ), patch.object(
                    source_retriever, "_is_public_address", return_value=True
                ):
                    result = retrieve_source(
                        f"https://{hostname}:{server.port}/report",
                        resolver=lambda _host: ["127.0.0.1"],
                    )

            self.assertEqual(result["retrieval_status"], "retrieved")
            self.assertEqual(result["title"], "Local TLS")
            self.assertEqual(result["text"], "Verified")
            self.assertEqual(server.sni, hostname)
            self.assertTrue(server.host.startswith(hostname))
            self.assertFalse(server.thread_alive)

    def test_real_pinned_transport_rejects_hostname_mismatch(self):
        requested_hostname = "requested.example.test"
        certificate_hostname = "different.example.test"
        with tempfile.TemporaryDirectory() as temporary_directory:
            certificate, key = create_test_certificate(
                Path(temporary_directory), certificate_hostname, "mismatch"
            )
            with LocalTLSServer(certificate, key) as server:
                original_transport = source_retriever._PinnedHTTPTransport

                def trusted_transport(address):
                    transport = original_transport(address)
                    transport._pool._ssl_context.load_verify_locations(
                        cafile=str(certificate)
                    )
                    return transport

                with patch.object(
                    source_retriever, "_PinnedHTTPTransport", trusted_transport
                ), patch.object(
                    source_retriever, "_is_public_address", return_value=True
                ):
                    result = retrieve_source(
                        f"https://{requested_hostname}:{server.port}/",
                        resolver=lambda _host: ["127.0.0.1"],
                    )

            self.assertEqual(result["retrieval_status"], "network_error")
            self.assertEqual(result["error"], "TLS or certificate verification failed.")
            self.assertFalse(server.thread_alive)

    def test_real_pinned_transport_rejects_untrusted_certificate_and_cleans_up(self):
        hostname = "untrusted.example.test"
        with tempfile.TemporaryDirectory() as temporary_directory:
            certificate, key = create_test_certificate(
                Path(temporary_directory), hostname, "untrusted"
            )
            with LocalTLSServer(certificate, key) as server:
                with patch.object(
                    source_retriever, "_is_public_address", return_value=True
                ):
                    result = retrieve_source(
                        f"https://{hostname}:{server.port}/",
                        resolver=lambda _host: ["127.0.0.1"],
                    )

            self.assertEqual(result["retrieval_status"], "network_error")
            self.assertEqual(result["error"], "TLS or certificate verification failed.")
            self.assertTrue(server.handshake_failed.wait(timeout=1))
            self.assertFalse(server.thread_alive)


if __name__ == "__main__":
    unittest.main()
