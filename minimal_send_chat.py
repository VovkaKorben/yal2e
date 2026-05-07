#!/usr/bin/env python3
"""Standalone minimal L2 Interlude chat sender.
Dependency: pip install pycryptodome
"""

from __future__ import annotations

import socket
import struct
import time
from Crypto.Cipher import Blowfish

# Hardcoded config
AUTH_HOST = "51.83.130.113"
AUTH_PORT = 2106
SERVER_ID = 58
USERNAME = "ZCEred3"
PASSWORD = "Pass13"
CHAR_INDEX = 0
MESSAGE = "hello"
PROTOCOL_VERSION = 746
TIMEOUT = 10.0

LS_INIT = 0x00
LS_LOGIN_FAIL = 0x01
LS_SERVER_LIST = 0x04
LS_PLAY_FAIL = 0x06
LS_PLAY_OK = 0x07
LS_GG_AUTH = 0x0B
GS_KEY_INIT = 0x00
GS_CHAR_SELECT_INFO = 0x13
GS_CHAR_SELECTED = 0x15
GS_LOGIN_FAIL = 0x14
GS_NET_PING = 0xD3
GS_USER_INFO = 0x04
GS_CHAR_INFO = 0x31
GS_LOGOUT_OK = 0x7E

STATIC_BLOWFISH_KEY = bytes.fromhex("6b 60 cb 5b 82 ce 90 b1 cc 2b 6c 55 6c 6c 6c 6c")
LEGACY_STATIC_BLOWFISH_KEY = bytes.fromhex("6b 60 cb 5b 82 ce 90 b1")
INTERLUDE_PROTOCOL_BLOB = bytes.fromhex(
    "19 07 54 56 03 09 0B 01 07 02 54 54 56 07 00 02 55 56 00 51 00 53 57 04 07 55 08 54 01 07 01 53 00 56 55 "
    "56 11 06 05 04 51 03 08 51 08 51 56 04 54 06 55 08 02 09 51 56 01 53 06 55 04 53 00 56 56 53 01 09 02 09 "
    "01 51 54 51 09 55 56 09 03 54 07 05 55 04 06 55 04 06 19 04 51 01 18 08 06 05 52 06 04 01 07 54 03 06 52 "
    "55 06 55 25 51 01 02 04 54 03 55 54 01 57 51 55 05 52 05 54 07 51 51 55 07 02 53 53 00 52 05 52 07 01 54 "
    "00 03 05 05 08 06 05 05 06 03 00 0D 08 01 07 09 03 51 03 07 53 09 71 06 07 54 0A 50 56 02 52 04 05 55 51 "
    "02 53 00 08 54 04 52 56 06 02 09 00 08 03 53 56 01 15 00 55 06 08 56 04 0D 06 07 52 06 07 04 0A 06 01 04 "
    "54 04 00 05 02 04 54 00 09 42 53 05 04 01 04 05 05 01 52 51 52 0D 06 51 08 09 54 53 00 0D 01 02 03 54 53 "
    "01 05 03 08 56 54 07 02 54 0B 06"
)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        c = sock.recv(n - len(out))
        if not c:
            raise RuntimeError("socket closed")
        out.extend(c)
    return bytes(out)


def recv_packet(sock: socket.socket) -> bytes:
    size = struct.unpack("<H", recv_exact(sock, 2))[0]
    return recv_exact(sock, size - 2)


def send_packet(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack("<H", len(payload) + 2) + payload)


def _wordswap8(block: bytes) -> bytes:
    return block[:4][::-1] + block[4:][::-1]


def bf_crypt(key: bytes, payload: bytes, decrypt: bool) -> bytes:
    if len(payload) % 8:
        raise ValueError("blowfish payload must be multiple of 8")
    c = Blowfish.new(key, Blowfish.MODE_ECB)
    fn = c.decrypt if decrypt else c.encrypt
    return b"".join(_wordswap8(fn(_wordswap8(payload[i : i + 8]))) for i in range(0, len(payload), 8))


def dec_xor_pass(raw: bytearray, size: int) -> None:
    key = struct.unpack_from("<I", raw, size - 8)[0]
    pos = size - 12
    while pos >= 4:
        enc = struct.unpack_from("<I", raw, pos)[0]
        plain = enc ^ key
        struct.pack_into("<I", raw, pos, plain)
        key = (key - plain) & 0xFFFFFFFF
        pos -= 4


def decrypt_login_init(payload: bytes) -> bytes:
    for k in (STATIC_BLOWFISH_KEY, LEGACY_STATIC_BLOWFISH_KEY):
        d = bf_crypt(k, payload, True)
        x = bytearray(d)
        if len(x) >= 12:
            dec_xor_pass(x, len(x))
            if x and x[0] == 0x00:
                return bytes(x)
        if d and d[0] == 0x00:
            return d
    raise RuntimeError("cannot decrypt login init")


def login_checksum(payload: bytes) -> int:
    p = payload + b"\x00" * ((4 - len(payload) % 4) % 4)
    s = 0
    for i in range(0, len(p), 4):
        s ^= struct.unpack_from("<I", p, i)[0]
    return s & 0xFFFFFFFF


def encrypt_login_packet(key: bytes, payload: bytes) -> bytes:
    d = bytearray(payload)
    d.extend(b"\x00" * ((8 - len(d) % 8) % 8))
    d.extend(struct.pack("<I", login_checksum(d)))
    d.extend(b"\x00" * 12)
    enc = bf_crypt(key, bytes(d), False)
    return struct.pack("<H", len(enc) + 2) + enc


def xor_crypt(data: bytes, key: bytearray, decrypt: bool) -> bytes:
    out = bytearray(len(data))
    carry = 0
    for i, v in enumerate(data):
        if decrypt:
            out[i] = v ^ key[i & 15] ^ carry
            carry = v
        else:
            e = v ^ key[i & 15] ^ carry
            out[i] = e
            carry = e
    m = (struct.unpack_from("<I", key, 8)[0] + len(data)) & 0xFFFFFFFF
    struct.pack_into("<I", key, 8, m)
    return bytes(out)


def cstr(s: str) -> bytes:
    return s.encode("utf-16le") + b"\x00\x00"


def parse_server_list(pkt: bytes) -> tuple[str, int]:
    n, off = pkt[1], 3
    for _ in range(n):
        sid = pkt[off]
        off += 1
        host = ".".join(str(b) for b in pkt[off : off + 4])
        off += 4
        port = struct.unpack_from("<I", pkt, off)[0]
        off += 4 + 1 + 1 + 2 + 2 + 1 + 4 + 1
        if sid == SERVER_ID:
            return host, port
    raise RuntimeError(f"server id {SERVER_ID} not found")


def unscramble_modulus(m: bytes) -> bytes:
    x = bytearray(m)
    for i in range(0x40):
        x[0x40 + i] ^= x[i]
    for i in range(4):
        x[0x0D + i] ^= x[0x34 + i]
    for i in range(0x40):
        x[i] ^= x[0x40 + i]
    for i in range(4):
        x[i], x[0x4D + i] = x[0x4D + i], x[i]
    return bytes(x)


def rsa_block(username: str, password: str, mod_scrambled: bytes) -> bytes:
    blk = bytearray(128)
    ub = username.encode("ascii", "ignore")[:14]
    pb = password.encode("ascii", "ignore")[:16]
    blk[91:94] = b"\x24\x00\x00"
    blk[94 : 94 + len(ub)] = ub
    blk[108 : 108 + len(pb)] = pb
    mod = int.from_bytes(unscramble_modulus(mod_scrambled), "big")
    enc = pow(int.from_bytes(blk, "big"), 65537, mod)
    return enc.to_bytes(128, "big")


# ---- Login server flow: init -> gg -> auth -> server list -> play ok
ls = socket.create_connection((AUTH_HOST, AUTH_PORT), timeout=TIMEOUT)
ls.settimeout(TIMEOUT)
init = decrypt_login_init(recv_packet(ls))
if init[0] != LS_INIT:
    raise RuntimeError("unexpected LS init opcode")
session_id = struct.unpack_from("<I", init, 1)[0]
modulus, bf_key = init[9:137], init[153:169]

ls.sendall(encrypt_login_packet(bf_key, b"\x07" + struct.pack("<I", session_id) + b"\x00" * 19))
gg = bf_crypt(bf_key, recv_packet(ls), True)
if gg[0] != LS_GG_AUTH:
    raise RuntimeError("expected GGAuth")
gg_token = struct.unpack_from("<I", gg, 1)[0]

auth = b"\x00" + rsa_block(USERNAME, PASSWORD, modulus) + struct.pack("<I", gg_token) + b"\x00" * 16 + struct.pack("<I", 8) + b"\x00" * 5
ls.sendall(encrypt_login_packet(bf_key, auth))
r = bf_crypt(bf_key, recv_packet(ls), True)
if r[0] == LS_LOGIN_FAIL:
    raise RuntimeError(f"login fail reason=0x{r[1]:02x}")
if r[0] == 0x03:
    lk1, lk2 = struct.unpack_from("<II", r, 1)
    ls.sendall(encrypt_login_packet(bf_key, b"\x05" + struct.pack("<II", lk1, lk2) + struct.pack("<I", 4)))
    sl = bf_crypt(bf_key, recv_packet(ls), True)
elif r[0] == LS_SERVER_LIST:
    lk1 = lk2 = 0
    sl = r
else:
    raise RuntimeError(f"unexpected login reply 0x{r[0]:02x}")

if sl[0] != LS_SERVER_LIST:
    raise RuntimeError("expected server list")
game_host, game_port = parse_server_list(sl)
ls.sendall(encrypt_login_packet(bf_key, b"\x02" + struct.pack("<II", lk1, lk2) + bytes([SERVER_ID])))
po = bf_crypt(bf_key, recv_packet(ls), True)
if po[0] == LS_PLAY_FAIL:
    raise RuntimeError("play fail")
if po[0] != LS_PLAY_OK:
    raise RuntimeError("expected play ok")
pk1, pk2 = struct.unpack_from("<II", po, 1)
ls.close()

# ---- Game server flow: protocol -> key -> game auth -> char select -> enter world -> chat
gs = socket.create_connection((game_host, game_port), timeout=TIMEOUT)
gs.settimeout(TIMEOUT)
send_packet(gs, b"\x00" + struct.pack("<I", PROTOCOL_VERSION) + INTERLUDE_PROTOCOL_BLOB)
first = recv_packet(gs)
if first[0] not in (GS_KEY_INIT, 0x2E):
    raise RuntimeError("expected first key")
seed = first[2:18]
recv_key = bytearray(seed)
send_key = bytearray(seed)

gauth = b"\x08" + cstr(USERNAME) + struct.pack("<I", pk2) + struct.pack("<I", pk1) + b"\x00" * 8 + struct.pack("<I", 6)
send_packet(gs, xor_crypt(gauth, send_key, False))

# Read one decrypted game packet and auto-reply to ping.
def recv_game() -> bytes:
    while True:
        p = xor_crypt(recv_packet(gs), recv_key, True)
        if p and p[0] == GS_NET_PING and len(p) >= 5:
            ping_id = struct.unpack_from("<I", p, 1)[0]
            send_packet(gs, xor_crypt(b"\xa8" + struct.pack("<II", ping_id, 0x800), send_key, False))
            continue
        return p

# Wait for char list.
while True:
    p = recv_game()
    if p[0] == GS_LOGIN_FAIL:
        raise RuntimeError("game auth failed")
    if p[0] == GS_CHAR_SELECT_INFO:
        break

# Select char, then enter world (minimal sequence from pyl2bot).
time.sleep(2.0)
send_packet(gs, xor_crypt(b"\x0d" + struct.pack("<I", CHAR_INDEX) + b"\x00" * 13 + b"\xdd", send_key, False))
while True:
    p = recv_game()
    if p and p[0] == GS_CHAR_SELECTED:
        break

time.sleep(1.0)
send_packet(gs, xor_crypt(b"\xd0\x08\x00", send_key, False))
time.sleep(0.1)
send_packet(gs, xor_crypt(b"\x03" + b"\x00" * 16, send_key, False))

# Wait until world is ready before chat (same idea as pyl2bot Engine._wait_until_ready).
deadline = time.monotonic() + TIMEOUT
while time.monotonic() < deadline:
    p = recv_game()
    if p and p[0] in (GS_USER_INFO, GS_CHAR_INFO):
        break
else:
    raise RuntimeError("timed out waiting for world-ready packet")

# Send chat (channel 0 = all chat).
send_packet(gs, xor_crypt(b"\x38" + cstr(MESSAGE) + struct.pack("<I", 0) + cstr(""), send_key, False))
print(f"Message sent to {game_host}:{game_port} as {USERNAME!r}")

# Proper exit: request logout and wait for LogoutOk when possible.
time.sleep(1.0)
send_packet(gs, xor_crypt(b"\x09", send_key, False))
deadline = time.monotonic() + min(TIMEOUT, 5.0)
while time.monotonic() < deadline:
    try:
        p = recv_game()
    except socket.timeout:
        break
    if p and p[0] == GS_LOGOUT_OK:
        break

gs.close()
