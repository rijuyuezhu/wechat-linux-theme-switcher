from __future__ import annotations

import argparse
import binascii
import os
import shutil
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

try:
    from cryptography.hazmat.decrepit.ciphers import modes
except ImportError:  # cryptography < 48
    from cryptography.hazmat.primitives.ciphers import modes


MMKV_CRYPT_KEY = b"xwechat_crypt_key"[:16]
APPEARANCE_KEY = "gAppearanceKey"
THEME_VALUES = {"light": 1, "dark": 2}
DEFAULT_CONFIG = Path.home() / "Documents/xwechat_files/all_users/config/global_config"


class SwitchError(RuntimeError):
    pass


@dataclass(frozen=True)
class Record:
    offset: int
    key: bytes
    value: bytes
    end: int


@dataclass(frozen=True)
class MMKVFile:
    path: Path
    crc_path: Path
    raw: bytes
    crc_raw: bytes
    actual_size: int
    iv: bytes
    plain: bytes


def read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    shift = 0
    value = 0
    start = pos
    while pos < len(buf):
        b = buf[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        if not (b & 0x80):
            return value, pos
        shift += 7
        if shift > 63:
            break
    raise SwitchError(f"invalid varint at plaintext offset 0x{start:x}")


def write_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def aes_cfb(data: bytes, iv: bytes, *, decrypt: bool) -> bytes:
    cipher = Cipher(algorithms.AES(MMKV_CRYPT_KEY), modes.CFB(iv))
    ctx = cipher.decryptor() if decrypt else cipher.encryptor()
    return ctx.update(data) + ctx.finalize()


def crc_path_for(config_path: Path) -> Path:
    return config_path.with_name(config_path.name + ".crc")


def load_mmkv(config_path: Path) -> MMKVFile:
    crc_path = crc_path_for(config_path)
    if not config_path.exists():
        raise SwitchError(f"config file not found: {config_path}")
    if not crc_path.exists():
        raise SwitchError(f"crc file not found: {crc_path}")

    raw = config_path.read_bytes()
    crc_raw = crc_path.read_bytes()
    if len(raw) < 4:
        raise SwitchError(f"config file too small: {config_path}")
    if len(crc_raw) < 0x20:
        raise SwitchError(f"crc metadata too small: {crc_path}")

    actual_size = struct.unpack_from("<I", raw, 0)[0]
    if actual_size > len(raw) - 4:
        raise SwitchError(
            f"actual_size {actual_size} exceeds encrypted payload capacity {len(raw) - 4}"
        )

    iv = crc_raw[0x0C:0x1C]
    plain = aes_cfb(raw[4 : 4 + actual_size], iv, decrypt=True)
    return MMKVFile(config_path, crc_path, raw, crc_raw, actual_size, iv, plain)


def parse_records(plain: bytes) -> list[Record]:
    # Encrypted MMKV stores a 4-byte random size holder before MiniPB records.
    pos = 4
    records: list[Record] = []
    while pos < len(plain):
        start = pos
        key_len, pos = read_varint(plain, pos)
        key = plain[pos : pos + key_len]
        pos += key_len
        if pos > len(plain):
            raise SwitchError(f"key at plaintext offset 0x{start:x} extends past end")

        value_len, pos = read_varint(plain, pos)
        value = plain[pos : pos + value_len]
        pos += value_len
        if pos > len(plain):
            key_text = key.decode(errors="replace")
            raise SwitchError(f"value for {key_text!r} extends past end")
        records.append(Record(start, key, value, pos))
    return records


def decode_int(value: bytes) -> int | None:
    try:
        decoded, pos = read_varint(value, 0)
    except SwitchError:
        return None
    return decoded if pos == len(value) else None


def current_appearance(records: list[Record]) -> int | None:
    target = APPEARANCE_KEY.encode()
    result: int | None = None
    for record in records:
        if record.key == target:
            result = decode_int(record.value)
    return result


def int_record(key: str, value: int) -> bytes:
    key_bytes = key.encode()
    value_bytes = write_varint(value)
    return (
        write_varint(len(key_bytes))
        + key_bytes
        + write_varint(len(value_bytes))
        + value_bytes
    )


def build_raw_config(mmkv: MMKVFile, new_plain: bytes) -> bytes:
    encrypted = aes_cfb(new_plain, mmkv.iv, decrypt=False)
    needed = 4 + len(encrypted)
    if needed <= len(mmkv.raw):
        out = bytearray(mmkv.raw)
    else:
        new_size = max(len(mmkv.raw), 4096)
        while new_size < needed:
            new_size *= 2
        out = bytearray(new_size)

    struct.pack_into("<I", out, 0, len(encrypted))
    out[4 : 4 + len(encrypted)] = encrypted
    out[4 + len(encrypted) :] = b"\x00" * (len(out) - 4 - len(encrypted))
    return bytes(out)


def build_crc_meta(mmkv: MMKVFile, new_raw: bytes) -> bytes:
    actual_size = struct.unpack_from("<I", new_raw, 0)[0]
    encrypted = new_raw[4 : 4 + actual_size]
    out = bytearray(mmkv.crc_raw)
    struct.pack_into("<I", out, 0, binascii.crc32(encrypted) & 0xFFFFFFFF)
    struct.pack_into("<I", out, 0x1C, actual_size)
    return bytes(out)


def atomic_write(path: Path, data: bytes) -> None:
    temp_path = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        temp_path.write_bytes(data)
        os.replace(temp_path, path)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def make_backups(mmkv: MMKVFile) -> tuple[Path, Path]:
    config_backup = mmkv.path.with_name(f"{mmkv.path.name}.bak")
    crc_backup = mmkv.crc_path.with_name(f"{mmkv.crc_path.name}.bak")
    shutil.copy2(mmkv.path, config_backup)
    shutil.copy2(mmkv.crc_path, crc_backup)
    return config_backup, crc_backup


def find_wechat_processes() -> list[tuple[int, str]]:
    proc = Path("/proc")
    matches: list[tuple[int, str]] = []
    if not proc.exists():
        return matches

    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            comm = (entry / "comm").read_text(errors="ignore").strip()
            cmdline = (entry / "cmdline").read_bytes().replace(b"\x00", b" ").decode(
                errors="ignore"
            )
        except OSError:
            continue
        if comm == "wechat" or "/opt/wechat/wechat" in cmdline:
            matches.append((pid, cmdline or comm))
    return matches


def switch_theme(args: argparse.Namespace) -> int:
    config_path = args.config.expanduser().resolve()
    target_value = THEME_VALUES[args.theme]
    target_name = args.theme

    mmkv = load_mmkv(config_path)
    records = parse_records(mmkv.plain)
    current_value = current_appearance(records)

    if current_value == target_value:
        print(f"Already set to {target_name}.")
        return 0

    running = find_wechat_processes()
    if running and not args.force and not args.dry_run:
        pid_text = ", ".join(str(pid) for pid, _cmd in running[:5])
        raise SwitchError(
            "WeChat appears to be running "
            f"(pid: {pid_text}). Quit WeChat first or pass --force."
        )

    new_plain = mmkv.plain + int_record(APPEARANCE_KEY, target_value)
    new_raw = build_raw_config(mmkv, new_plain)
    new_crc = build_crc_meta(mmkv, new_raw)

    old_name = "unset" if current_value is None else {1: "light", 2: "dark", 0: "automatic"}.get(
        current_value, str(current_value)
    )
    print(f"Current appearance: {old_name}")
    print(f"Target appearance: {target_name}")
    print(f"Config: {config_path}")

    if args.dry_run:
        print("Dry run: no files written.")
        return 0

    backups: tuple[Path, Path] | None = None
    if not args.no_backup:
        backups = make_backups(mmkv)

    atomic_write(mmkv.path, new_raw)
    atomic_write(mmkv.crc_path, new_crc)

    if backups:
        print(f"Backup: {backups[0]}")
        print(f"Backup: {backups[1]}")
    print(f"Switched WeChat appearance to {target_name}.")
    print("Restart WeChat if it was already running.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Switch WeChat Linux dark/light appearance in global_config."
    )
    parser.add_argument("theme", choices=sorted(THEME_VALUES), help="target appearance")
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG,
        help=f"path to global_config (default: {DEFAULT_CONFIG})",
    )
    parser.add_argument("--dry-run", action="store_true", help="parse and preview without writing")
    parser.add_argument("--force", action="store_true", help="write even if WeChat appears to run")
    parser.add_argument("--no-backup", action="store_true", help="do not create .bak files")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return switch_theme(args)
    except SwitchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
