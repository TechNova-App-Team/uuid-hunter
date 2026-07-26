# UUID Collision Hunter

Sucht per Geburtstagsparadoxon nach zwei identischen UUIDv4 — und zeigt live,
warum das bei den echten 122 Bit nicht klappt.

Gemessen auf: AMD Ryzen 9 7950X3D (32 Threads), 47 GB RAM, MSVC 14.50, `/O2 /GL /arch:AVX2`.

---

## Bauen und starten

`build.bat` per Doppelklick oder im Terminal. Das Fenster bleibt am Ende offen;
für den Einsatz in Skripten `build.bat nopause` aufrufen.

```powershell
.\build.bat
.\uuid_collision.exe --ladder
```

> **`.\` nicht vergessen.** PowerShell führt Programme aus dem aktuellen Ordner
> nicht ohne Pfadangabe aus — `uuid_collision.exe --ladder` scheitert dort mit
> `CommandNotFoundException`. In `cmd.exe` ist es egal; `.\` funktioniert in
> beiden.

Das Build-Skript wechselt selbst in seinen eigenen Ordner und arbeitet mit
absoluten Pfaden — es ist also egal, aus welchem Verzeichnis es gestartet wird.

| Befehl | Was passiert |
|---|---|
| `.\uuid_collision.exe --bits 44` | Live-Dashboard, Kollision nach ~40 ms |
| `.\uuid_collision.exe --ladder` | Skalierungsleiter — **das Wichtigste** |
| `.\uuid_collision.exe --bits 30 --trials 500` | Statistiktest gegen die Theorie |
| `.\uuid_collision.exe --bits 122` | Echte UUIDv4. Läuft bis Strg+C. |
| `.\uuid_collision.exe --rng chacha8` | Kryptographischer PRNG statt xoshiro |
| `python uuid_check.py` | Format-Gegencheck + Python-Vergleich |

---

## Die zentrale Idee

Eine echte 122-Bit-Kollision ist unerreichbar — also verkleinert man den
Suchraum auf `N` Bits (`--bits N`) und findet *tatsächlich* Kollisionen. Aus
dem gemessenen Verlauf wird auf 122 Bit hochgerechnet.

Als Schlüssel dienen die untersten `N` Bits des Zufallsanteils. Die festen
Version- (`4`) und Varianten-Bits sind bewusst **ausgeschlossen** — sonst
würde man sich die Kollision schönrechnen.

```
128 Bit  =  48 Zufall | 4 Version | 12 Zufall | 2 Variante | 62 Zufall
                                                             ^^^^^^^^^
                                                    hieraus die N Bits
```

## Gemessene Ergebnisse

Jede Zeile über mehrere Läufe gemittelt (`Rep`), weil Einzelläufe stark streuen:

```
  Bits   Rep  Theorie E[n]       Gemessen n        Zeit        Rate
  ----------------------------------------------------------------------
  32      21      82137.20           92'001      2.8 ms   32.54 M/s
  36      21     328548.78          319'606     11.3 ms   28.26 M/s
  40      21    1314195.12        1'348'615     10.8 ms  124.62 M/s
  44      21    5256780.50        4'782'635     41.5 ms  115.30 M/s
  48       9      2.10e+07       20'432'207    187.5 ms  109.00 M/s
  52       2      8.41e+07       88'539'811    814.8 ms  108.66 M/s
  56       1      3.36e+08      293'394'981      3.10 s   94.57 M/s
  60       0      1.35e+09                -      8.09 s   [RAM voll]
```

Messung und Theorie stimmen auf ±13 % überein. Bei **60 Bit ist Schluss** —
nicht weil es zu lange dauert, sondern weil 47 GB RAM nicht mehr reichen.

## Ist das nur ein schwacher Zufallsgenerator?

Nein. Drei völlig verschiedene Quellen, je 12 Läufe bei 40 Bit:

| Generator | Gemessen / Theorie |
|---|---|
| xoshiro256++ (schnell) | 0.977 |
| ChaCha8 (kryptographisch) | 1.036 |
| RDRAND (CPU-Hardware) | 0.976 |

Alle innerhalb von 4 %. Die Kollisionen folgen der Geburtstagsformel, nicht
einer Schwäche des Generators.

Zusätzlich, 500 Läufe bei 30 Bit:

```
Mittelwert     39'667        Theorie E[n]   41'069     → 0.966
Median         37'209        Theorie n50    38'581     → 0.964
Var.koeff.      0.539        Theorie         0.523
```

Der Standardfehler bei 500 Läufen liegt bei 2.3 %, das Ergebnis also 1.5 Sigma
von der Theorie entfernt — unauffällig.

---

## Hochrechnung auf echte UUIDv4

Reine Erzeugungsrate ohne Hashtabelle: **4.35 Mrd. UUIDs/s** auf 32 Threads.

| | |
|---|---|
| Suchraum | 5.32 × 10³⁶ |
| Nötig für 50 % | 2.72 × 10¹⁸ UUIDs |
| Rechenzeit | **~20 Jahre** |
| Speicher | **37.7 EB** (≈ 2.2 Mio. Festplatten à 20 TB) |
| P nach 1 Billion IDs | 9.4 × 10⁻¹² % |
| P nach 1 Trillion IDs | 8.98 % |

**Rechenleistung ist nicht die Hürde — Speicher ist es.** 20 Jahre Rechnen
klingt machbar, aber man muss *jede* erzeugte ID behalten, um sie vergleichen
zu können. Genau daran scheitert es, und genau das zeigt die Leiter oben: bei
60 Bit war der RAM voll, lange bevor die Zeit ein Problem wurde.

Zum Vergleich: `uuid.uuid4()` in CPython schafft ~1.0 M/s auf einem Kern. Das
sind ~87'000 Jahre für dasselbe Ziel.

---

## Technisches

* **Hashtabelle**: offene Adressierung, lineares Sondieren, lock-free.
  16 Byte/Slot, zwei getrennte Arrays. Reservierung per CAS auf ein
  Sentinel (`1`), Freigabe per Release-Store — ein gültiges `hi` ist wegen
  des Versions-Nibbles nie `0` oder `1`, deshalb funktioniert das ohne
  `cmpxchg16b`.
* **Speicher**: `VirtualAlloc` / `mmap`, wird vom OS lazy genullt.
  Abbruch bei 85 % Füllgrad, bevor lineares Sondieren entartet.
* **Zählung**: thread-lokal, Flush-Intervall so gewählt, dass der Zählfehler
  unter 0.1 % bleibt. Bei kleinen Suchräumen läuft nur ein Thread, weil sonst
  der Thread-Start die Messung dominiert.
* **Über 62 Bit** wird ausschließlich gezählt, ohne Tabelle. Sonst würde das
  Programm heimlich eine 62-Bit-Kollision finden und sie als 122-Bit-Treffer
  ausgeben.

## Warum nicht Pollard-Rho?

Der übliche speicherlose Kollisionsangriff (Rho / Distinguished Points, Speicher
O(1) statt O(√M)) braucht eine deterministische Funktion `f`, die man iterieren
kann. Echte UUIDs kommen aus einem Entropiestrom — es gibt kein `f`. Der Angriff
ist auf zufällig gezogene Werte nicht anwendbar, deshalb bleibt der Speicher die
harte Grenze.

---
