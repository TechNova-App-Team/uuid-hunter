"""
Gegencheck + Benchmark: validiert die C++-UUIDs mit Pythons stdlib-uuid
und misst, wie schnell Python selbst UUIDs erzeugt.

    python uuid_check.py

ACHTUNG: Eine Datei namens uuid.py im selben Ordner ueberschattet das
stdlib-Modul "uuid". Dieses Skript entfernt sein eigenes Verzeichnis
deshalb aus sys.path, bevor es importiert.
"""

import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))

# --- stdlib-uuid trotz lokaler uuid.py laden -------------------------------
_shadow = os.path.join(HERE, "uuid.py")
_shadowed = os.path.exists(_shadow)
for p in ("", ".", HERE):
    while p in sys.path:
        sys.path.remove(p)
sys.modules.pop("uuid", None)
import uuid  # noqa: E402

EXE = os.path.join(HERE, "uuid_collision.exe")
if not os.path.exists(EXE):
    EXE = os.path.join(HERE, "uuid_collision")


def check_format(n=2000):
    """Laesst das C++-Programm UUIDs erzeugen und validiert sie mit stdlib."""
    out = subprocess.run([EXE, "--samples"], capture_output=True, text=True,
                         encoding="utf-8", errors="replace").stdout
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    ok = 0
    for line in lines:
        u = uuid.UUID(line)          # wirft bei ungueltigem Format
        assert str(u) == line, f"Roundtrip fehlgeschlagen: {line}"
        assert u.version == 4, f"Version != 4: {line}"
        assert (u.int >> 62) & 0b11 == 0b10, f"Variante falsch: {line}"
        ok += 1
    return ok, lines


def bench_python(seconds=2.0):
    u4 = uuid.uuid4
    n = 0
    t0 = time.perf_counter()
    while True:
        for _ in range(10000):
            u4()
        n += 10000
        dt = time.perf_counter() - t0
        if dt >= seconds:
            return n / dt


def main():
    print()
    if _shadowed:
        print("  \033[93m[!] uuid.py liegt in diesem Ordner.\033[0m")
        print("      Ein `import uuid` aus diesem Verzeichnis importiert die Datei")
        print("      selbst, nicht die Standardbibliothek. uuid.uuid4() schlaegt dann")
        print("      mit AttributeError fehl. Datei umbenennen (z.B. mein_uuid.py).")
        print()

    ok, lines = check_format()
    print(f"  \033[92m[+] {ok} C++-UUIDs von Pythons uuid-Modul akzeptiert\033[0m")
    print(f"      Version 4, Variante RFC-4122, Roundtrip identisch")
    print(f"      Beispiel: {lines[0]}")
    print()

    print("  Benchmark Python uuid.uuid4() ...", end="", flush=True)
    rate = bench_python()
    print("\r" + " " * 40 + "\r", end="")
    print(f"  \033[96mPython uuid4():\033[0m  {rate/1e6:.3f} M/s  (1 Kern, CPython)")

    # Reine C++-Erzeugungsrate: 122-Bit-Modus zaehlt nur, ohne Hashtabelle.
    # (Ein Lauf mit Tabelle waere speicherlimitiert und wuerde C++ untertreiben.)
    print("  \033[96mC++ (alle Kerne):\033[0m messe ...", end="", flush=True)
    proc = subprocess.Popen([EXE, "--bits", "122", "--no-color"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            encoding="utf-8", errors="replace")
    try:
        out, _ = proc.communicate(timeout=4)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()

    cpp = None
    for line in out.splitlines():
        s = line.replace("\x1b[K", "").strip()
        if s.startswith("Rate"):
            cpp = s.split()[1:3]          # letzte Messung gewinnt
    print("\r" + " " * 40 + "\r", end="")

    if cpp:
        print(f"  \033[96mC++ (alle Kerne):\033[0m {' '.join(cpp)}  (reine Erzeugung)")
        try:
            unit = {"G/s": 1e9, "M/s": 1e6, "K/s": 1e3}.get(cpp[1], 1.0)
            val = float(cpp[0]) * unit
            print(f"  \033[1mFaktor:\033[0m {val/rate:,.0f}x schneller als Python")
            years = 1.1774100225 * (2 ** 61) / val / (365.25 * 86400)
            print()
            print(f"  Bei dieser Rate bis zur ersten echten UUIDv4-Kollision (50 %):")
            print(f"    C++ auf diesem PC : \033[93m{years:,.0f} Jahre\033[0m")
            print(f"    Python, 1 Kern    : \033[91m{years*val/rate:,.0f} Jahre\033[0m")
        except (ValueError, IndexError, KeyError):
            pass
    print()


if __name__ == "__main__":
    main()
