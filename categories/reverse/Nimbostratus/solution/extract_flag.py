from __future__ import annotations

import sys
from hashlib import sha256
from pathlib import Path

import pefile

DOTA_ORDER = (7331, 2843, 9157, 5629)

def extract_rcdata(executable: Path) -> dict[int, bytes]:
    pe = pefile.PE(str(executable), fast_load=False)
    resources: dict[int, bytes] = {}
    for type_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if type_entry.struct.Id != 10:
            continue
        for name_entry in type_entry.directory.entries:
            rid = int(name_entry.struct.Id)
            lang = name_entry.directory.entries[0]
            rva = int(lang.data.struct.OffsetToData)
            size = int(lang.data.struct.Size)
            resources[rid] = pe.get_data(rva, size)
    return resources

def decrypt_container(archive: bytes, password: bytes, out_dir: Path) -> None:
    key = sha256(password).digest()
    bias = key[0] ^ key[31]

    if archive[:4] != b"DOTA":
        raise RuntimeError("bad container magic")

    count = int.from_bytes(archive[5:9], "little")
    offset = 9
    ok = 0

    for _ in range(count):
        name_len = int.from_bytes(archive[offset:offset + 4], "little")
        data_len = int.from_bytes(archive[offset + 4:offset + 12], "little")
        expected = archive[offset + 12:offset + 44]
        offset += 44

        name = archive[offset:offset + name_len].decode("utf-8")
        offset += name_len

        cipher = archive[offset:offset + data_len]
        offset += data_len

        plain = bytes(
            (((byte - bias) & 0xFF) ^ key[i & 31])
            for i, byte in enumerate(cipher)
        )

        if sha256(plain).digest() != expected:
            raise RuntimeError(f"SHA-256 mismatch: {name}")
        ok += 1

        target = out_dir / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(plain)

    print(f"decrypted entries: {ok}/{count}")

def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(
            f"usage: {Path(sys.argv[0]).name} task.exe <32-hex-password>"
        )

    executable = Path(sys.argv[1])
    password = sys.argv[2].strip().encode("ascii")

    resources = extract_rcdata(executable)
    archive = b"".join(resources[rid] for rid in DOTA_ORDER)

    out_dir = Path("Flags_extracted")
    out_dir.mkdir(exist_ok=True)
    decrypt_container(archive, password, out_dir)

    print(f"payload written to: {out_dir}/")
    print("real flag lives inside "
          "Flag_countries_1950/Flags/Student_CTF_Flag.png")

if __name__ == "__main__":
    main()
