"""
Regenerate the small synthetic disk images used by the Pillage tests.

All file content is synthetic. No third-party samples are used.

This is a developer tool, it's not run by the tests. Run it from anywhere:

    sudo python3 tests/api/data_files/pillage/make_fixtures.py

Requirements (Debian/Ubuntu package names in parentheses):

- mkfs.fat and mtools (``dosfstools``, ``mtools``)
- mke2fs (``e2fsprogs``)
- mkntfs and ntfs-3g (``ntfs-3g``). ntfs-3g mounts the NTFS image with FUSE,
  which needs root or FUSE permissions.
- ewfacquire (``ewf-tools``)
- qemu-img (``qemu-utils``)
- xz (``xz-utils``)

Images that tests build themselves with :mod:`struct` (GPT, extended MBR,
split raw, VMDK descriptors) are not generated here.

Only regenerate the NTFS image, or the multi-segment EWF image (made from
the existing fat12_mbr.img.xz):

    sudo python3 tests/api/data_files/pillage/make_fixtures.py ntfs
    python3 tests/api/data_files/pillage/make_fixtures.py ewf-segments
"""

import lzma
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent

# Offset of the FAT12 partition in fat12_mbr.img, in 512-byte sectors
FAT_LBA = 64
FAT_SIZE = 512 * 1024


def run(*args: str, cwd: Path | None = None) -> None:
    print("+", " ".join(args))  # noqa: T201
    subprocess.run(args, check=True, cwd=cwd, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})


def write_files(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        pth = root / rel
        pth.parent.mkdir(parents=True, exist_ok=True)
        pth.write_text(text, encoding="utf-8")


def mbr(partitions: list[tuple[int, int, int]]) -> bytes:
    """MBR with up to 4 (type, start_lba, num_sectors) entries."""
    data = bytearray(512)
    for i, (ptype, start, count) in enumerate(partitions):
        data[446 + i * 16 : 446 + (i + 1) * 16] = struct.pack(
            "<B3sB3sII", 0, b"\xff\xff\xff", ptype, b"\xff\xff\xff", start, count
        )
    data[510:512] = b"\x55\xaa"
    return bytes(data)


def reparse_data(tag: int, data: bytes) -> bytes:
    """An NTFS reparse point (REPARSE_DATA_BUFFER), as set by ntfs-3g's xattr."""
    return struct.pack("<IHH", tag, len(data), 0) + data


def mount_point_data(target: str) -> bytes:
    """The data of a junction (IO_REPARSE_TAG_MOUNT_POINT) to a Windows path."""
    subst = f"\\??\\{target}".encode("utf-16-le")
    printed = target.encode("utf-16-le")
    names = subst + b"\x00\x00" + printed + b"\x00\x00"
    return struct.pack("<HHHH", 0, len(subst), len(subst) + 2, len(printed)) + names


def make_fat(work: Path) -> Path:
    part = work / "part.fat"
    with part.open("wb") as fp:
        fp.truncate(FAT_SIZE)
    run("mkfs.fat", "-F", "12", "-n", "PEATTEST", "-i", "1234ABCD", str(part))
    src = work / "fat_src"
    write_files(
        src,
        {
            "SET_ALL.TXT": "synthetic SEL settings\r\n",
            "relay.rdb": "synthetic SEL RDB\r\n",
            "project.L5X": "<RSLogix5000Content/>\r\n",
            "skip.rdb": "must not be copied (excluded directory)\r\n",
            "readme.txt": "not a device file\r\n",
            "set_all_2.txt": "second synthetic SEL settings\r\n",
        },
    )
    mtools = ["-i", str(part)]
    run("mmd", *mtools, "::/SEL", "::/SEL/sub", "::/WINDOWS", "::/Other")
    run("mcopy", *mtools, str(src / "SET_ALL.TXT"), "::/SEL/SET_ALL.TXT")
    run("mcopy", *mtools, str(src / "relay.rdb"), "::/SEL/sub/relay.rdb")
    run("mcopy", *mtools, str(src / "project.L5X"), "::/project.L5X")
    run("mcopy", *mtools, str(src / "skip.rdb"), "::/WINDOWS/skip.rdb")
    run("mcopy", *mtools, str(src / "readme.txt"), "::/readme.txt")
    # Same name as /SEL/SET_ALL.TXT, to exercise the name collision handling
    run("mcopy", *mtools, str(src / "set_all_2.txt"), "::/Other/set_all.txt")
    return part


def make_fat_mbr(work: Path, part: Path) -> Path:
    disk = work / "fat12_mbr.img"
    with disk.open("wb") as fp:
        fp.write(mbr([(0x01, FAT_LBA, FAT_SIZE // 512)]))
        fp.write(b"\x00" * (FAT_LBA * 512 - 512))
        fp.write(part.read_bytes())
    return disk


def make_ext4(work: Path) -> Path:
    src = work / "ext_src"
    write_files(
        src,
        {
            "etc/cfg.txt": "synthetic SEL cfg\n",
            "home/user/Projects/plant.L5X": "<RSLogix5000Content/>\n",
        },
    )
    # Symbolic link that must never be followed
    (src / "etc" / "evil.rdb").symlink_to("/etc/shadow")
    img = work / "ext4.img"
    run(
        "mke2fs",
        "-q",
        "-F",
        "-t",
        "ext4",
        "-O",
        "^has_journal",
        "-b",
        "1024",
        "-N",
        "32",
        "-L",
        "PEATEXT",
        "-U",
        "0b4d5e7f-2a3c-4d6e-8f90-a1b2c3d4e5f6",
        "-E",
        "root_owner=0:0",
        "-d",
        str(src),
        str(img),
        "1M",
    )
    return img


def make_ntfs(work: Path) -> Path:
    img = work / "ntfs.img"
    with img.open("wb") as fp:
        fp.truncate(2 * 1024 * 1024)
    run("mkntfs", "-q", "-F", "-Q", "-L", "PEATNTFS", str(img))
    mnt = work / "ntfs_mnt"
    mnt.mkdir()
    run("ntfs-3g", str(img), str(mnt))
    try:
        write_files(
            mnt,
            {
                "set_all.txt": "synthetic SEL settings\r\n",
                "Project.RDB": "synthetic SEL RDB\r\n",
                "SEL/sub/cser.txt": "synthetic SEL CSER\r\n",
                "Users/eng/OneDrive/Projects/plant.L5X": "synthetic L5X in OneDrive\r\n",
            },
        )
        # A hard link to Project.RDB (the same MFT entry)
        os.link(mnt / "Project.RDB", mnt / "SEL" / "hardlink.rdb")
        # A OneDrive (Files On-Demand) folder: the directory has a cloud files
        # reparse point (IO_REPARSE_TAG_CLOUD_6), but its files are on the disk
        os.setxattr(
            mnt / "Users/eng/OneDrive",
            "system.ntfs_reparse_data",
            reparse_data(0x9000601A, bytes(8)),
        )
        # A junction to C:\Windows (IO_REPARSE_TAG_MOUNT_POINT), its index is empty
        (mnt / "Junction").mkdir()
        os.setxattr(
            mnt / "Junction",
            "system.ntfs_reparse_data",
            reparse_data(0xA0000003, mount_point_data("C:\\Windows")),
        )
    finally:
        run("umount", str(mnt))
    return img


def make_ewf_segments(work: Path, disk: Path) -> list[Path]:
    """
    An uncompressed EWF image of the FAT12 MBR disk, padded to 2.5 MiB, in
    three 1 MiB segments (the smallest segment size ewfacquire supports).
    The segments are mostly zeros, so they compress to a few KB with xz.
    """
    padded = work / "padded.img"
    data = disk.read_bytes()
    padded.write_bytes(data + bytes(5 * 512 * 1024 - len(data)))
    target = work / "fat12_mbr_segments"
    run(
        "ewfacquire",
        "-u",
        "-q",
        "-c",
        "none",
        "-f",
        "encase6",
        "-S",
        "1048576",
        "-C",
        "PEAT-CASE-2",
        "-t",
        str(target),
        str(padded),
    )
    return sorted(work.glob("fat12_mbr_segments.E*"))


def compress(images: list[Path]) -> None:
    for img in images:
        dst = OUT_DIR / f"{img.name}.xz"
        dst.unlink(missing_ok=True)
        run("xz", "-9", "-e", "-k", "-z", str(img))
        shutil.move(str(img) + ".xz", dst)


def main() -> None:
    if sys.argv[1:] == ["ntfs"]:
        with tempfile.TemporaryDirectory() as tmp:
            compress([make_ntfs(Path(tmp))])
        return
    if sys.argv[1:] == ["ewf-segments"]:
        with tempfile.TemporaryDirectory() as tmp:
            disk = Path(tmp) / "fat12_mbr.img"
            disk.write_bytes(lzma.decompress((OUT_DIR / "fat12_mbr.img.xz").read_bytes()))
            compress(make_ewf_segments(Path(tmp), disk))
        return

    for tool in ("mkfs.fat", "mmd", "mcopy", "mke2fs", "mkntfs", "ntfs-3g", "ewfacquire"):
        if not shutil.which(tool, path="/usr/sbin:/usr/bin:/sbin:/bin"):
            raise SystemExit(f"Missing required tool: {tool}")

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        part = make_fat(work)
        disk = make_fat_mbr(work, part)
        images = [disk, make_ext4(work), make_ntfs(work), *make_ewf_segments(work, disk)]

        # EnCase 6 (E01) image of the FAT12 MBR disk
        run(
            "ewfacquire",
            "-u",
            "-q",
            "-c",
            "best",
            "-f",
            "encase6",
            "-C",
            "PEAT-CASE-1",
            "-D",
            "synthetic PEAT test image",
            "-e",
            "PEAT",
            "-E",
            "EV-1",
            "-N",
            "synthetic",
            "-t",
            str(OUT_DIR / "fat12_mbr"),
            str(disk),
        )

        # Virtual machine disk formats of the same disk
        for fmt, ext, opts in (
            ("vmdk", "vmdk", []),
            ("vpc", "vhd", ["-o", "force_size=on"]),
            ("vhdx", "vhdx", []),
            ("qcow2", "qcow2", []),
        ):
            out = work / f"fat12_mbr.{ext}"
            run("qemu-img", "convert", "-q", "-f", "raw", "-O", fmt, *opts, str(disk), str(out))
            images.append(out)

        compress(images)


if __name__ == "__main__":
    main()
