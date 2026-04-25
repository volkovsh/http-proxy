#!/usr/bin/env python3

import argparse
import socket
import threading
import time
"""
Лаба 4: простой HTTP-прокси (без HTTPS).

Ключевая особенность: браузер при работе через прокси отправляет request-line в absolute-form:
    GET http://host:port/path HTTP/1.1
А сервер назначения чаще ожидает origin-form:
    GET /path HTTP/1.1
Поэтому прокси переписывает request-line перед пересылкой upstream.
"""

from dataclasses import dataclass
from typing import Dict, Optional, Tuple
from urllib.parse import urlsplit


CRLF = b"\r\n"
HEADER_END = b"\r\n\r\n"


@dataclass
class ParsedRequest:
    method: str
    # Что пришло в request-line от клиента: absolute-form (URL целиком) или origin-form (путь).
    raw_target: str
    version: str
    # Заголовки в двух видах:
    # - headers: для быстрых lookup'ов (ключи в lower-case)
    # - header_items: чтобы сохранить исходный порядок/регистры при пересылке
    headers: Dict[str, str]
    header_items: Tuple[Tuple[str, str], ...]
    host: str
    port: int
    # Путь в origin-form (включая query), который уйдёт upstream.
    path: str
    # Нормализованный absolute URL для логирования.
    absolute_url: str
    # Сырые байты заголовков (для диагностики/отладки при необходимости).
    header_bytes: bytes


def _recv_until(sock: socket.socket, marker: bytes, limit: int = 256 * 1024) -> bytes:
    """Читает из сокета до маркера (например, CRLFCRLF для конца заголовков)."""
    buf = bytearray()
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > limit:
            raise ValueError("Header too large")
    return bytes(buf)


def _parse_headers(header_block: bytes) -> Tuple[str, str, str, Tuple[Tuple[str, str], ...], Dict[str, str]]:
    """Парсит request-line и заголовки из блока, заканчивающегося CRLFCRLF."""
    head, _sep, _rest = header_block.partition(HEADER_END)
    lines = head.split(CRLF)
    if not lines or not lines[0]:
        raise ValueError("Empty request")
    try:
        request_line = lines[0].decode("iso-8859-1")
    except UnicodeDecodeError as exc:
        raise ValueError(f"Bad request line encoding: {exc}") from exc

    parts = request_line.split()
    if len(parts) != 3:
        raise ValueError(f"Bad request line: {request_line!r}")
    method, target, version = parts

    items = []
    headers_lc: Dict[str, str] = {}
    for raw in lines[1:]:
        if not raw:
            continue
        try:
            line = raw.decode("iso-8859-1")
        except UnicodeDecodeError:
            continue
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.strip()
        value = value.lstrip(" \t")
        items.append((name, value))
        headers_lc[name.lower()] = value
    return method, target, version, tuple(items), headers_lc


def _determine_upstream(method: str, target: str, headers_lc: Dict[str, str]) -> Tuple[str, int, str, str]:
    """
    Returns (host, port, path, absolute_url).
    Supports absolute-form and origin-form.
    """
    # absolute-form: "http://host:port/path?query"
    if target.startswith("http://") or target.startswith("https://"):
        u = urlsplit(target)
        if not u.hostname:
            raise ValueError("No hostname in absolute URL")
        host = u.hostname
        port = u.port or (443 if u.scheme == "https" else 80)
        path = u.path or "/"
        if u.query:
            path = f"{path}?{u.query}"
        absolute_url = f"{u.scheme}://{host}:{port}{path}"
        return host, port, path, absolute_url

    # origin-form: "/path?query". В этом случае host/port берём из заголовка Host.
    host_hdr = headers_lc.get("host")
    if not host_hdr:
        raise ValueError("Missing Host header")
    host_port = host_hdr.strip()
    if ":" in host_port:
        host, port_s = host_port.rsplit(":", 1)
        try:
            port = int(port_s)
        except ValueError as exc:
            raise ValueError("Bad Host header port") from exc
    else:
        host = host_port
        port = 80

    path = target if target else "/"
    if not path.startswith("/"):
        # could be authority-form or something unexpected; still forward as-is
        path = "/" + path
    absolute_url = f"http://{host}:{port}{path}"
    return host, port, path, absolute_url


def parse_client_request(client_sock: socket.socket) -> Tuple[ParsedRequest, bytes]:
    """
    Считывает только заголовки запроса (до CRLFCRLF) и возвращает:
    - ParsedRequest
    - остаток байт, которые могли прийти вместе с заголовками (начало body)
    """
    raw = _recv_until(client_sock, HEADER_END)
    if not raw:
        raise ValueError("Client closed")
    header_block, _sep, remainder = raw.partition(HEADER_END)
    header_bytes = header_block + HEADER_END

    method, target, version, header_items, headers_lc = _parse_headers(header_bytes)
    host, port, path, absolute_url = _determine_upstream(method, target, headers_lc)

    return (
        ParsedRequest(
            method=method,
            raw_target=target,
            version=version,
            headers=headers_lc,
            header_items=header_items,
            host=host,
            port=port,
            path=path,
            absolute_url=absolute_url,
            header_bytes=header_bytes,
        ),
        remainder,
    )


def build_upstream_request(req: ParsedRequest) -> bytes:
    # Переписываем request-line в origin-form для upstream серверов.
    request_line = f"{req.method} {req.path} {req.version}\r\n"

    # Удаляем proxy-specific заголовки и управляем Connection сами.
    #
    # Важно: мы принудительно добавляем "Connection: close" (ниже), чтобы упрощённо
    # определять конец ответа: прокси будет читать до закрытия upstream-сокета.
    # Это особенно удобно для потоковых ответов (радио) и ответов без Content-Length.
    out_lines = [request_line]
    seen_host = False
    for name, value in req.header_items:
        nlc = name.lower()
        if nlc in {"proxy-connection", "proxy-authorization"}:
            continue
        if nlc == "connection":
            continue
        if nlc == "host":
            seen_host = True
        out_lines.append(f"{name}: {value}\r\n")

    if not seen_host:
        out_lines.append(f"Host: {req.host}:{req.port}\r\n")

    # Force close so we can reliably detect end-of-response for unknown-length bodies.
    out_lines.append("Connection: close\r\n")
    out_lines.append("\r\n")
    return "".join(out_lines).encode("iso-8859-1")


def _read_response_headers(upstream: socket.socket) -> Tuple[bytes, int, bytes]:
    """Считывает заголовки ответа (до CRLFCRLF) и извлекает status code для логирования."""
    raw = _recv_until(upstream, HEADER_END)
    if not raw:
        raise ValueError("Upstream closed before response")
    header_block, _sep, remainder = raw.partition(HEADER_END)
    header_bytes = header_block + HEADER_END

    # Parse status code from status-line: HTTP/1.1 200 OK
    first = header_block.split(CRLF, 1)[0].decode("iso-8859-1", errors="replace")
    parts = first.split()
    status = 0
    if len(parts) >= 2:
        try:
            status = int(parts[1])
        except ValueError:
            status = 0
    return header_bytes, status, remainder


def _relay_stream(src: socket.socket, dst: socket.socket, initial: bytes = b"") -> None:
    """Прокачка байт без буферизации: читает чанки и сразу пишет дальше."""
    if initial:
        dst.sendall(initial)
    while True:
        chunk = src.recv(64 * 1024)
        if not chunk:
            return
        dst.sendall(chunk)


def handle_client(
    client_sock: socket.socket,
    client_addr: Tuple[str, int],
    connect_timeout_s: float,
) -> None:
    try:
        try:
            req, body_remainder = parse_client_request(client_sock)
        except ValueError:
            return

        # HTTPS через CONNECT по условию не требуется.
        if req.method.upper() == "CONNECT":
            client_sock.sendall(
                b"HTTP/1.1 501 Not Implemented\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            )
            return

        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream.settimeout(connect_timeout_s)
        upstream.connect((req.host, req.port))
        upstream.settimeout(None)

        # Отправляем переписанные заголовки + уже прочитанный кусок body (если он пришёл вместе с заголовками).
        upstream.sendall(build_upstream_request(req))

        # If the client already sent some body bytes together with headers, forward them immediately.
        if body_remainder:
            upstream.sendall(body_remainder)

        # Дальше можем дочитать ещё немного body со стороны клиента (на случай POST),
        # но не блокируемся надолго, чтобы не задерживать получение ответа от upstream.
        client_sock.settimeout(0.2)
        try:
            while True:
                chunk = client_sock.recv(64 * 1024)
                if not chunk:
                    break
                upstream.sendall(chunk)
                # Эвристика: если сейчас данных меньше чанка — вероятно, body закончился (или пауза).
                if len(chunk) < 64 * 1024:
                    break
        except socket.timeout:
            pass
        finally:
            client_sock.settimeout(None)

        # Сначала читаем заголовки ответа, чтобы получить status code для лога,
        # затем потоково прокачиваем оставшееся тело без лишней буферизации.
        resp_header_bytes, status_code, resp_remainder = _read_response_headers(upstream)
        client_sock.sendall(resp_header_bytes)

        # Log: URL + status code
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}] {client_addr[0]}:{client_addr[1]} -> {req.absolute_url} => {status_code}")

        _relay_stream(upstream, client_sock, initial=resp_remainder)
    except OSError:
        return
    finally:
        try:
            client_sock.close()
        except OSError:
            pass
        try:
            upstream.close()  # type: ignore[name-defined]
        except Exception:
            pass


def serve(listen_host: str, listen_port: int, connect_timeout_s: float) -> None:
    """Запускает слушающий сокет и обрабатывает клиентов в отдельных потоках."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((listen_host, listen_port))
    server.listen(128)

    print(f"HTTP proxy listening on {listen_host}:{listen_port} (HTTP only; HTTPS CONNECT not supported)")

    try:
        while True:
            client_sock, client_addr = server.accept()
            t = threading.Thread(
                target=handle_client,
                args=(client_sock, client_addr, connect_timeout_s),
                daemon=True,
            )
            t.start()
    finally:
        server.close()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Simple HTTP proxy with logging (lab 4)")
    p.add_argument("--listen-host", default="127.0.0.1", help="Host/IP to listen on")
    p.add_argument("--listen-port", type=int, default=8080, help="TCP port to listen on")
    p.add_argument("--connect-timeout", type=float, default=5.0, help="Upstream connect timeout (seconds)")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    serve(args.listen_host, args.listen_port, args.connect_timeout)


if __name__ == "__main__":
    main()

