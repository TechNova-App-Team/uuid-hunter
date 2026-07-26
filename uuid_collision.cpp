// ============================================================================
//  UUID COLLISION HUNTER
//  ---------------------------------------------------------------------------
//  Erzeugt RFC-4122 Version-4 UUIDs (identisch zu Python uuid.uuid4()) mit
//  maximaler Geschwindigkeit und sucht per Geburtstagsparadoxon nach zwei
//  identischen IDs.
//
//  Da eine echte 122-Bit-Kollision physikalisch unerreichbar ist, laesst sich
//  der Suchraum auf N Bits verkleinern (--bits). Man findet dann tatsaechlich
//  Kollisionen und sieht, wie die benoetigte Zeit sich pro 2 Bit verdoppelt.
//  Aus der gemessenen Rate wird auf die echten 122 Bit hochgerechnet.
//
//  Build (Windows / MSVC):   build.bat
//  Build (Linux / g++):      ./build.sh
// ============================================================================

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <immintrin.h>
#define UCH_X86 1
#endif

// ----------------------------------------------------------------------------
// Kleine Helfer
// ----------------------------------------------------------------------------

static inline uint64_t rotl64(uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

static inline void cpuRelax() {
#if defined(UCH_X86)
    _mm_pause();
#else
    std::this_thread::yield();
#endif
}

// splitmix64 - Seeding und Hash-Mixing
static inline uint64_t splitmix64(uint64_t& x) {
    uint64_t z = (x += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static inline uint64_t mix64(uint64_t z) {
    z ^= z >> 33;
    z *= 0xFF51AFD7ED558CCDULL;
    z ^= z >> 33;
    z *= 0xC4CEB9FE1A85EC53ULL;
    z ^= z >> 33;
    return z;
}

// ----------------------------------------------------------------------------
// Zufallsgeneratoren
// ----------------------------------------------------------------------------

// xoshiro256++ : 1.5 - 3 GB/s pro Kern, Periode 2^256-1, besteht BigCrush.
struct Xoshiro256pp {
    uint64_t s[4];

    void seed(uint64_t a, uint64_t b) {
        uint64_t x = a ^ (b * 0x9E3779B97F4A7C15ULL);
        for (int i = 0; i < 4; ++i) s[i] = splitmix64(x);
        for (int i = 0; i < 32; ++i) next();  // warmup
    }

    inline uint64_t next() {
        const uint64_t result = rotl64(s[0] + s[3], 23) + s[0];
        const uint64_t t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = rotl64(s[3], 45);
        return result;
    }
};

// ChaCha8 - kryptographischer Stromchiffre-PRNG. Das ist im Kern das, was
// os.urandom() / getrandom() liefert. Deutlich langsamer, aber "echt".
struct ChaCha8 {
    uint32_t state[16];
    uint32_t block[16];
    int used = 16;

    void seed(uint64_t a, uint64_t b) {
        static const char sigma[] = "expand 32-byte k";
        std::memcpy(state, sigma, 16);
        uint64_t x = a ^ 0xA5A5A5A5DEADBEEFULL;
        for (int i = 4; i < 12; ++i) state[i] = (uint32_t)splitmix64(x);
        state[12] = 0;
        state[13] = 0;
        state[14] = (uint32_t)b;
        state[15] = (uint32_t)(b >> 32);
        used = 16;
    }

    static inline void qr(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
        a += b; d ^= a; d = (d << 16) | (d >> 16);
        c += d; b ^= c; b = (b << 12) | (b >> 20);
        a += b; d ^= a; d = (d << 8) | (d >> 24);
        c += d; b ^= c; b = (b << 7) | (b >> 25);
    }

    void generate() {
        std::memcpy(block, state, sizeof(block));
        for (int i = 0; i < 4; ++i) {  // 8 Runden = 4 Doppelrunden
            qr(block[0], block[4], block[8], block[12]);
            qr(block[1], block[5], block[9], block[13]);
            qr(block[2], block[6], block[10], block[14]);
            qr(block[3], block[7], block[11], block[15]);
            qr(block[0], block[5], block[10], block[15]);
            qr(block[1], block[6], block[11], block[12]);
            qr(block[2], block[7], block[8], block[13]);
            qr(block[3], block[4], block[9], block[14]);
        }
        for (int i = 0; i < 16; ++i) block[i] += state[i];
        if (++state[12] == 0) ++state[13];
        used = 0;
    }

    inline uint64_t next() {
        if (used >= 16) generate();
        uint64_t lo = block[used++];
        uint64_t hi = block[used++];
        return lo | (hi << 32);
    }
};

// RDRAND - Hardware-Entropiequelle der CPU (on-chip DRBG).
struct RdRand {
    void seed(uint64_t, uint64_t) {}
    inline uint64_t next() {
#if defined(UCH_X86)
        unsigned long long v = 0;
        for (int i = 0; i < 16; ++i)
            if (_rdrand64_step(&v)) return (uint64_t)v;
        return 0;
#else
        return 0;
#endif
    }
};

enum class RngKind { Xoshiro, ChaCha8Rng, RdRandHw };

// Vereinheitlichter Generator - Branch nur einmal pro Thread, nicht pro UUID.
struct AnyRng {
    RngKind kind;
    Xoshiro256pp x;
    ChaCha8 c;
    RdRand r;

    void seed(RngKind k, uint64_t a, uint64_t b) {
        kind = k;
        x.seed(a, b);
        c.seed(a, b);
        r.seed(a, b);
    }
    inline uint64_t next() {
        switch (kind) {
            case RngKind::Xoshiro:  return x.next();
            case RngKind::ChaCha8Rng: return c.next();
            default: return r.next();
        }
    }
};

// ----------------------------------------------------------------------------
// UUID v4
// ----------------------------------------------------------------------------
//
//  128 Bit gesamt:
//    hi[63..16]  48 Bit Zufall   (time_low + time_mid)
//    hi[15..12]   4 Bit Version  -> fest 0b0100
//    hi[11.. 0]  12 Bit Zufall   (time_hi)
//    lo[63..62]   2 Bit Variante -> fest 0b10
//    lo[61.. 0]  62 Bit Zufall
//  => 48 + 12 + 62 = 122 echte Zufallsbits
//
//  Als Kollisionsschluessel nehmen wir die untersten N Bits von lo. Das sind
//  garantiert echte Zufallsbits - die festen Version-/Variantenbits sind
//  ausgeschlossen, sonst wuerde man sich die Kollision schoenrechnen.

static inline void makeUuidV4(uint64_t rndA, uint64_t rndB, uint64_t& hi, uint64_t& lo) {
    hi = (rndA & 0xFFFFFFFFFFFF0FFFULL) | 0x0000000000004000ULL;  // Version 4
    lo = (rndB & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;  // Variante 10xx
}

static std::string uuidToString(uint64_t hi, uint64_t lo) {
    static const char* H = "0123456789abcdef";
    char buf[37];
    int p = 0;
    for (int i = 0; i < 16; ++i) {
        uint8_t byte = (i < 8) ? (uint8_t)(hi >> (56 - i * 8))
                               : (uint8_t)(lo >> (56 - (i - 8) * 8));
        buf[p++] = H[byte >> 4];
        buf[p++] = H[byte & 0xF];
        if (i == 3 || i == 5 || i == 7 || i == 9) buf[p++] = '-';
    }
    buf[p] = 0;
    return std::string(buf);
}

// ----------------------------------------------------------------------------
// Speicher (lazy zero-filled)
// ----------------------------------------------------------------------------

static void* allocZeroed(size_t bytes) {
#if defined(_WIN32)
    return VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
#else
    void* p = mmap(nullptr, bytes, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return (p == MAP_FAILED) ? nullptr : p;
#endif
}

static void freeZeroed(void* p, size_t bytes) {
    if (!p) return;
#if defined(_WIN32)
    (void)bytes;
    VirtualFree(p, 0, MEM_RELEASE);
#else
    munmap(p, bytes);
#endif
}

static uint64_t systemMemoryBytes() {
#if defined(_WIN32)
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms)) return ms.ullTotalPhys;
    return 8ULL << 30;
#else
    long pages = sysconf(_SC_PHYS_PAGES);
    long ps = sysconf(_SC_PAGE_SIZE);
    if (pages > 0 && ps > 0) return (uint64_t)pages * (uint64_t)ps;
    return 8ULL << 30;
#endif
}

// ----------------------------------------------------------------------------
// Terminal / ANSI
// ----------------------------------------------------------------------------

static bool g_color = true;

static void enableVT() {
#if defined(_WIN32)
    SetConsoleOutputCP(CP_UTF8);
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode))
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#endif
}

#define C_RESET (g_color ? "\x1b[0m"  : "")
#define C_DIM   (g_color ? "\x1b[2m"  : "")
#define C_BOLD  (g_color ? "\x1b[1m"  : "")
#define C_CYAN  (g_color ? "\x1b[96m" : "")
#define C_GREEN (g_color ? "\x1b[92m" : "")
#define C_YEL   (g_color ? "\x1b[93m" : "")
#define C_RED   (g_color ? "\x1b[91m" : "")
#define C_MAG   (g_color ? "\x1b[95m" : "")
#define C_BLUE  (g_color ? "\x1b[94m" : "")
#define C_GRAY  (g_color ? "\x1b[90m" : "")

// ----------------------------------------------------------------------------
// Formatierung
// ----------------------------------------------------------------------------

static std::string groupNum(uint64_t v) {
    std::string s = std::to_string(v);
    std::string out;
    int c = 0;
    for (int i = (int)s.size() - 1; i >= 0; --i) {
        out.push_back(s[i]);
        if (++c % 3 == 0 && i > 0) out.push_back('\'');
    }
    std::reverse(out.begin(), out.end());
    return out;
}

static std::string sci(double v, int prec = 3) {
    char b[64];
    if (v != 0.0 && (v < 1e-4 || v >= 1e7))
        std::snprintf(b, sizeof(b), "%.*e", prec, v);
    else
        std::snprintf(b, sizeof(b), "%.*f", prec, v);
    return std::string(b);
}

static std::string fmtBytes(double b) {
    static const char* u[] = {"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"};
    int i = 0;
    while (b >= 1024.0 && i < 8) { b /= 1024.0; ++i; }
    char s[64];
    std::snprintf(s, sizeof(s), "%.2f %s", b, u[i]);
    return std::string(s);
}

static std::string fmtRate(double r) {
    char s[64];
    if (r >= 1e9)      std::snprintf(s, sizeof(s), "%.2f G/s", r / 1e9);
    else if (r >= 1e6) std::snprintf(s, sizeof(s), "%.2f M/s", r / 1e6);
    else if (r >= 1e3) std::snprintf(s, sizeof(s), "%.2f K/s", r / 1e3);
    else               std::snprintf(s, sizeof(s), "%.0f /s", r);
    return std::string(s);
}

static std::string fmtDuration(double sec) {
    char s[128];
    if (sec < 1e-3)  { std::snprintf(s, sizeof(s), "%.0f us", sec * 1e6);  return s; }
    if (sec < 1.0)   { std::snprintf(s, sizeof(s), "%.1f ms", sec * 1e3);  return s; }
    if (sec < 60.0)  { std::snprintf(s, sizeof(s), "%.2f s", sec);          return s; }
    if (sec < 3600.0){ std::snprintf(s, sizeof(s), "%dm %02ds", (int)(sec/60), (int)std::fmod(sec,60)); return s; }
    if (sec < 86400.0){std::snprintf(s, sizeof(s), "%dh %02dm", (int)(sec/3600), (int)std::fmod(sec/60,60)); return s; }

    double days = sec / 86400.0;
    if (days < 365.25) { std::snprintf(s, sizeof(s), "%.1f Tage", days); return s; }

    double years = days / 365.25;
    if (years < 100)  { std::snprintf(s, sizeof(s), "%.1f Jahre", years); return s; }
    if (years < 1e6)  { std::snprintf(s, sizeof(s), "%s Jahre", groupNum((uint64_t)years).c_str()); return s; }
    if (years < 1e9)  { std::snprintf(s, sizeof(s), "%.2f Mio. Jahre", years / 1e6); return s; }
    if (years < 1e12) { std::snprintf(s, sizeof(s), "%.2f Mrd. Jahre", years / 1e9); return s; }
    std::snprintf(s, sizeof(s), "%.3e Jahre", years);
    return std::string(s);
}

static std::string fmtClock(double sec) {
    int h = (int)(sec / 3600);
    int m = (int)std::fmod(sec / 60, 60);
    double s = std::fmod(sec, 60);
    char b[64];
    std::snprintf(b, sizeof(b), "%02d:%02d:%04.1f", h, m, s);
    return std::string(b);
}

// UTF-8 aware: zaehlt sichtbare Zeichen (fuer Rahmen-Ausrichtung)
static size_t visLen(const std::string& s) {
    size_t n = 0;
    for (size_t i = 0; i < s.size();) {
        unsigned char c = (unsigned char)s[i];
        if (c == 0x1b) { while (i < s.size() && s[i] != 'm') ++i; ++i; continue; }
        i += (c < 0x80) ? 1 : (c < 0xE0) ? 2 : (c < 0xF0) ? 3 : 4;
        ++n;
    }
    return n;
}

// ----------------------------------------------------------------------------
// Mathematik des Geburtstagsparadoxons
// ----------------------------------------------------------------------------
//
//  Suchraum M = 2^bits
//  Median (50 % Chance):    n50  = sqrt(2 * ln2 * M) = 1.17741 * sqrt(M)
//  Erwartungswert:          E[n] = sqrt(pi/2 * M)    = 1.25331 * sqrt(M)
//  P(Kollision nach n):     1 - exp(-n^2 / (2M))

static double spaceSize(int bits) { return std::pow(2.0, (double)bits); }
static double median50(int bits)  { return 1.1774100225 * std::pow(2.0, bits / 2.0); }
static double expectedN(int bits) { return 1.2533141373 * std::pow(2.0, bits / 2.0); }

static double collisionProb(double n, int bits) {
    double M = spaceSize(bits);
    double e = -(n * n) / (2.0 * M);
    if (e < -700) return 1.0;
    return 1.0 - std::exp(e);
}

// ----------------------------------------------------------------------------
// Hashtabelle: offene Adressierung, lock-free, 16 Byte pro Slot
// ----------------------------------------------------------------------------
//
//  hiArr[i]: 0 = leer, 1 = reserviert, sonst = echtes hi einer UUID
//            (echtes hi hat immer Bit 14 gesetzt -> nie 0 oder 1)
//  loArr[i]: wird zwischen Reservierung und Freigabe geschrieben
//
//  Publish per release-store auf hiArr, Lesen per acquire-load. Damit ist
//  loArr[i] garantiert sichtbar, sobald hiArr[i] > 1 gelesen wurde.

struct Table {
    uint64_t* hiArr = nullptr;
    uint64_t* loArr = nullptr;
    uint64_t  capacity = 0;
    uint64_t  capMask = 0;
    size_t    bytes = 0;

    bool alloc(uint64_t cap) {
        capacity = cap;
        capMask = cap - 1;
        bytes = (size_t)cap * 8;
        hiArr = (uint64_t*)allocZeroed(bytes);
        loArr = (uint64_t*)allocZeroed(bytes);
        if (!hiArr || !loArr) { release(); return false; }
        return true;
    }
    void release() {
        freeZeroed(hiArr, bytes); hiArr = nullptr;
        freeZeroed(loArr, bytes); loArr = nullptr;
        capacity = 0; capMask = 0; bytes = 0;
    }
    double totalBytes() const { return (double)bytes * 2.0; }
};

// ----------------------------------------------------------------------------
// Suchlauf
// ----------------------------------------------------------------------------

static std::atomic<bool> g_abort{false};

static void onSigint(int) { g_abort.store(true, std::memory_order_relaxed); }

struct HuntResult {
    bool     found = false;
    bool     memExhausted = false;
    bool     aborted = false;
    uint64_t generated = 0;
    double   seconds = 0;
    double   rate = 0;
    uint64_t key = 0;
    uint64_t aHi = 0, aLo = 0;   // frueher gespeicherte UUID
    uint64_t bHi = 0, bLo = 0;   // neu erzeugte UUID
    uint64_t capacity = 0;
    double   tableBytes = 0;
};

struct SharedState {
    std::atomic<uint64_t> generated{0};
    std::atomic<bool>     stop{false};
    std::atomic<uint64_t> hitKey{0};
    std::atomic<uint64_t> hitAHi{0}, hitALo{0}, hitBHi{0}, hitBLo{0};
    std::atomic<bool>     hit{false};
    std::atomic<uint64_t> lastHi{0}, lastLo{0};
    std::atomic<bool>     memFull{false};
};

static void worker(int tid, const Table* tab, uint64_t mask, RngKind rk,
                   SharedState* st, uint64_t flushEvery, uint64_t maxEntries,
                   bool countOnly) {
    AnyRng rng;
    std::random_device rd;
    uint64_t s1 = ((uint64_t)rd() << 32) ^ rd() ^ (uint64_t)tid * 0x9E3779B97F4A7C15ULL;
    uint64_t s2 = ((uint64_t)rd() << 32) ^ rd() ^
                  (uint64_t)std::chrono::high_resolution_clock::now().time_since_epoch().count();
    rng.seed(rk, s1, s2);

    std::atomic<uint64_t>* hiA = reinterpret_cast<std::atomic<uint64_t>*>(tab->hiArr);
    uint64_t* loA = tab->loArr;
    const uint64_t capMask = tab->capMask;

    uint64_t local = 0;
    uint64_t hi = 0, lo = 0;

    while (!st->stop.load(std::memory_order_relaxed)) {
        for (uint64_t iter = 0; iter < flushEvery; ++iter) {
            makeUuidV4(rng.next(), rng.next(), hi, lo);
            ++local;

            // Ueber 62 Bit passt kein Schluessel mehr in einen 64-Bit-Slot und
            // der Speicher reicht ohnehin nie. Dann wird ehrlich nur gezaehlt,
            // statt heimlich eine kuerzere Kollision zu suchen und sie als
            // 122-Bit-Treffer auszugeben.
            if (countOnly) continue;

            const uint64_t key = lo & mask;
            uint64_t idx = mix64(key) & capMask;

            for (;;) {
                uint64_t h = hiA[idx].load(std::memory_order_acquire);

                if (h == 0) {
                    uint64_t expect = 0;
                    if (hiA[idx].compare_exchange_strong(expect, 1ULL,
                            std::memory_order_acq_rel, std::memory_order_acquire)) {
                        loA[idx] = lo;
                        hiA[idx].store(hi, std::memory_order_release);
                        break;                       // eingefuegt, keine Kollision
                    }
                    h = expect;                      // jemand anders war schneller
                }

                if (h == 1) { cpuRelax(); continue; }  // Slot wird gerade befuellt

                if ((loA[idx] & mask) == key) {        // >>> KOLLISION <<<
                    bool expected = false;
                    if (st->hit.compare_exchange_strong(expected, true)) {
                        st->hitKey.store(key);
                        st->hitAHi.store(hiA[idx].load(std::memory_order_relaxed));
                        st->hitALo.store(loA[idx]);
                        st->hitBHi.store(hi);
                        st->hitBLo.store(lo);
                        st->generated.fetch_add(local, std::memory_order_relaxed);
                        local = 0;
                        st->stop.store(true, std::memory_order_release);
                    }
                    goto done;
                }
                idx = (idx + 1) & capMask;             // lineares Sondieren
            }
        }

        uint64_t total = st->generated.fetch_add(local, std::memory_order_relaxed) + local;
        local = 0;
        if (total >= maxEntries) {
            st->memFull.store(true, std::memory_order_release);
            st->stop.store(true, std::memory_order_release);
        }
        if (g_abort.load(std::memory_order_relaxed)) st->stop.store(true, std::memory_order_release);

        st->lastHi.store(hi, std::memory_order_relaxed);   // fuer die Live-Anzeige
        st->lastLo.store(lo, std::memory_order_relaxed);
    }

done:
    if (local) st->generated.fetch_add(local, std::memory_order_relaxed);
}

// ----------------------------------------------------------------------------
// Live-Dashboard
// ----------------------------------------------------------------------------

static const char* SPARK[8] = {"\xe2\x96\x81","\xe2\x96\x82","\xe2\x96\x83","\xe2\x96\x84",
                               "\xe2\x96\x85","\xe2\x96\x86","\xe2\x96\x87","\xe2\x96\x88"};

static std::string sparkline(const std::vector<double>& v) {
    if (v.empty()) return "";
    double mx = 0;
    for (double d : v) mx = std::max(mx, d);
    if (mx <= 0) mx = 1;
    std::string s;
    for (double d : v) {
        int i = (int)(d / mx * 7.999);
        s += SPARK[std::max(0, std::min(7, i))];
    }
    return s;
}

static std::string progressBar(double frac, int width) {
    frac = std::max(0.0, std::min(1.0, frac));
    int full = (int)(frac * width);
    std::string s;
    for (int i = 0; i < width; ++i) s += (i < full) ? "\xe2\x96\x88" : "\xe2\x96\x91";
    return s;
}

static void row(const char* label, const std::string& value, const char* color = "") {
    std::printf("  %s%-14s%s %s%s%s%s\n", C_GRAY, label, C_RESET, color, value.c_str(),
                C_RESET, g_color ? "\x1b[K" : "");
}

// ----------------------------------------------------------------------------
// Der eigentliche Lauf
// ----------------------------------------------------------------------------

struct Config {
    int    bits = 48;
    int    threads = 0;
    double memGB = 0;
    int    trials = 1;
    bool   ladder = false;
    int    ladderFrom = 24, ladderTo = 52, ladderStep = 4;
    RngKind rng = RngKind::Xoshiro;
    bool   live = true;
    bool   samples = false;
};

static const char* rngName(RngKind k) {
    switch (k) {
        case RngKind::Xoshiro: return "xoshiro256++";
        case RngKind::ChaCha8Rng: return "ChaCha8 (CSPRNG)";
        default: return "RDRAND (Hardware)";
    }
}

static HuntResult hunt(const Config& cfg, int bits, bool live, uint64_t memBudget) {
    HuntResult res;
    const bool countOnly = (bits > 62);
    const uint64_t mask = countOnly ? 0 : ((1ULL << bits) - 1ULL);

    // Kapazitaet: ~2.5x der erwarteten Eintraege, aufgerundet auf Zweierpotenz
    double want = expectedN(bits) * 2.5;
    uint64_t cap = 1024;
    while ((double)cap < want && cap < (1ULL << 40)) cap <<= 1;

    // Speicherlimit einhalten (2 Arrays * 8 Byte)
    uint64_t maxCap = memBudget / 16;
    uint64_t capLimit = 1024;
    while (capLimit * 2 <= maxCap) capLimit <<= 1;
    if (cap > capLimit) cap = capLimit;
    if (countOnly) cap = 1024;   // Dummy - wird nie benutzt

    Table tab;
    if (!tab.alloc(cap)) {
        std::fprintf(stderr, "%sSpeicher konnte nicht reserviert werden (%s).%s\n",
                     C_RED, fmtBytes((double)cap * 16).c_str(), C_RESET);
        res.memExhausted = true;
        return res;
    }
    res.capacity = countOnly ? 0 : cap;
    res.tableBytes = countOnly ? 0 : tab.totalBytes();

    // Bei 85 % Fuellgrad abbrechen - danach wird lineares Sondieren pathologisch
    const uint64_t maxEntries = countOnly ? ~0ULL : (uint64_t)(cap * 0.85);

    int nThreads = cfg.threads > 0 ? cfg.threads : (int)std::thread::hardware_concurrency();
    if (nThreads < 1) nThreads = 1;
    if (cfg.rng == RngKind::RdRandHw) nThreads = std::min(nThreads, 16);

    // Bei kleinen Suchraeumen kostet das Starten von 32 Threads mehr als die
    // eigentliche Arbeit - die Ratenmessung waere dann reines Rauschen.
    double expWork = expectedN(bits);
    if (expWork < 5.0e5) nThreads = 1;
    else if (expWork < 5.0e6) nThreads = std::min(nThreads, 8);

    // Flush-Intervall so waehlen, dass der Zaehlfehler < 0.1 % bleibt
    uint64_t flushEvery = (uint64_t)std::max(1.0, std::min(65536.0, expWork / (1000.0 * nThreads)));

    SharedState st;
    auto t0 = std::chrono::steady_clock::now();

    std::vector<std::thread> pool;
    pool.reserve(nThreads);
    for (int i = 0; i < nThreads; ++i)
        pool.emplace_back(worker, i, &tab, mask, cfg.rng, &st, flushEvery, maxEntries, countOnly);

    // ---- Live-Anzeige ----
    const int LINES = 17;
    std::vector<double> hist;
    uint64_t lastCount = 0;
    auto lastT = t0;
    bool drawn = false;

    if (live) {
        std::printf("\n");
        while (!st.stop.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));

            auto now = std::chrono::steady_clock::now();
            double elapsed = std::chrono::duration<double>(now - t0).count();
            double dt = std::chrono::duration<double>(now - lastT).count();
            uint64_t cnt = st.generated.load(std::memory_order_relaxed);

            if (dt >= 0.1) {
                hist.push_back((double)(cnt - lastCount) / dt);
                if (hist.size() > 32) hist.erase(hist.begin());
                lastCount = cnt;
                lastT = now;
            }

            double rate = elapsed > 0 ? cnt / elapsed : 0;
            double n50 = median50(bits);
            double prob = collisionProb((double)cnt, bits) * 100.0;
            double load = (double)cnt / (double)cap * 100.0;

            if (drawn) std::printf("\x1b[%dA", LINES);
            drawn = true;

            std::printf("  %s%s UUID COLLISION HUNTER %s%s%s\x1b[K\n",
                        C_BOLD, C_CYAN, C_DIM, "\xe2\x80\x94 live", C_RESET);
            std::printf("  %s%s%s\x1b[K\n", C_GRAY,
                        "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"
                        "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"
                        "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"
                        "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"
                        "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"
                        "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"
                        "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"
                        "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"
                        "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80",
                        C_RESET);

            char b[256];
            std::snprintf(b, sizeof(b), "%d von 122 Bits   %s(%s Werte)%s",
                          bits, C_DIM, sci(spaceSize(bits), 2).c_str(), C_RESET);
            row("Suchraum", b, C_BOLD);

            std::snprintf(b, sizeof(b), "%s  %s%d Threads%s", rngName(cfg.rng), C_DIM, nThreads, C_RESET);
            row("Generator", b);

            if (countOnly) {
                std::snprintf(b, sizeof(b), "%skeine - nur zaehlen (%s waeren noetig)%s",
                              C_DIM, fmtBytes(median50(bits) * 16.0).c_str(), C_RESET);
                row("Tabelle", b);
            } else {
                std::snprintf(b, sizeof(b), "2^%d Slots  %s%s  Last %.1f%%%s",
                              (int)std::log2((double)cap), C_DIM,
                              fmtBytes(tab.totalBytes()).c_str(), load, C_RESET);
                row("Tabelle", b);
            }

            std::printf("\x1b[K\n");

            row("Erzeugt", groupNum(cnt), C_BOLD);
            std::snprintf(b, sizeof(b), "%-10s %s%s%s", fmtRate(rate).c_str(),
                          C_CYAN, sparkline(hist).c_str(), C_RESET);
            row("Rate", b, C_GREEN);
            row("Laufzeit", fmtClock(elapsed));

            std::printf("\x1b[K\n");

            std::snprintf(b, sizeof(b), "  %sFortschritt bis 50%%-Punkt (%s UUIDs)%s\x1b[K\n",
                          C_GRAY, sci(n50, 2).c_str(), C_RESET);
            std::printf("%s", b);
            std::printf("  %s%s%s  %s%6.2f %%%s\x1b[K\n",
                        prob > 50 ? C_YEL : C_BLUE,
                        progressBar((double)cnt / n50, 44).c_str(), C_RESET,
                        C_BOLD, (double)cnt / n50 * 100.0, C_RESET);

            std::printf("\x1b[K\n");
            std::snprintf(b, sizeof(b), "%.4f %%", prob);
            row("P(Kollision)", b, prob > 50 ? C_YEL : C_RESET);
            row("aktuelle ID", uuidToString(st.lastHi.load(), st.lastLo.load()), C_MAG);
            std::printf("\x1b[K\n");
            std::fflush(stdout);
        }
    }

    for (auto& t : pool) t.join();

    auto t1 = std::chrono::steady_clock::now();
    res.seconds = std::chrono::duration<double>(t1 - t0).count();
    res.generated = st.generated.load();
    res.rate = res.seconds > 0 ? res.generated / res.seconds : 0;
    res.found = st.hit.load();
    res.memExhausted = st.memFull.load();
    res.aborted = g_abort.load();

    if (res.found) {
        res.key = st.hitKey.load();
        res.aHi = st.hitAHi.load(); res.aLo = st.hitALo.load();
        res.bHi = st.hitBHi.load(); res.bLo = st.hitBLo.load();
    }

    tab.release();
    return res;
}

// ----------------------------------------------------------------------------
// Ausgabe des Ergebnisses
// ----------------------------------------------------------------------------

static void printCollision(const HuntResult& r, int bits) {
    std::string a = uuidToString(r.aHi, r.aLo);
    std::string b = uuidToString(r.bHi, r.bLo);

    std::printf("\n  %s%s KOLLISION GEFUNDEN%s\n\n", C_BOLD, C_RED, C_RESET);
    std::printf("    %s#1%s  %s%s%s\n", C_GRAY, C_RESET, C_BOLD, a.c_str(), C_RESET);
    std::printf("    %s#2%s  %s%s%s\n", C_GRAY, C_RESET, C_BOLD, b.c_str(), C_RESET);

    // Marker unter die uebereinstimmenden Hex-Ziffern (untere N Bits von lo)
    int hexDigits = (bits + 3) / 4;
    std::string marker(38, ' ');
    for (int i = 0; i < hexDigits && i < 16; ++i) {
        int pos = 35 - i;                 // letzte Stelle des 36-Zeichen-Strings
        if (pos >= 0 && pos < 36) marker[6 + pos] = '^';
    }
    std::printf("  %s%s%s\n", C_YEL, marker.c_str(), C_RESET);
    std::printf("      %s%d gemeinsame Zufallsbits  (Schluessel 0x%llx)%s\n\n",
                C_GRAY, bits, (unsigned long long)r.key, C_RESET);

    double exp = expectedN(bits);
    double factor = exp > 0 ? (double)r.generated / exp : 0;

    row("Nach", groupNum(r.generated) + " UUIDs", C_BOLD);
    row("Zeit", fmtDuration(r.seconds), C_BOLD);
    row("Rate", fmtRate(r.rate), C_GREEN);
    char b2[128];
    std::snprintf(b2, sizeof(b2), "%s UUIDs  %s(Faktor %.2fx)%s",
                  sci(exp, 3).c_str(), C_DIM, factor, C_RESET);
    row("Theorie E[n]", b2);
}

static void printExtrapolation(double rate, int measuredBits, double measuredSeconds) {
    std::printf("\n  %s%sHOCHRECHNUNG AUF ECHTE UUIDv4 (122 Bit)%s\n", C_BOLD, C_CYAN, C_RESET);
    std::printf("  %s────────────────────────────────────────────────────────────────%s\n\n", C_GRAY, C_RESET);

    double n50 = median50(122);
    double secs = rate > 0 ? n50 / rate : 0;
    double bytes = n50 * 16.0;

    row("Suchraum", sci(spaceSize(122), 3) + " moegliche UUIDs");
    row("Noetig (50%)", sci(n50, 3) + " UUIDs", C_BOLD);
    std::printf("\n");

    char b[256];
    std::snprintf(b, sizeof(b), "%s   %s(bei %s)%s", fmtDuration(secs).c_str(),
                  C_DIM, fmtRate(rate).c_str(), C_RESET);
    row("Rechenzeit", b, C_RED);

    std::snprintf(b, sizeof(b), "%s   %s(nur zum Speichern der IDs)%s",
                  fmtBytes(bytes).c_str(), C_DIM, C_RESET);
    row("Speicher", b, C_RED);

    // Selbst wenn die ganze Welt mitrechnet, bleibt der Speicher das Problem.
    double earthRate = rate * 8.0e9;   // 8 Mrd. Maschinen dieser Klasse
    std::snprintf(b, sizeof(b), "%s Rechenzeit  %s(8 Mrd. solcher PCs)%s",
                  fmtDuration(n50 / earthRate).c_str(), C_DIM, C_RESET);
    row("Weltweit", b, C_YEL);

    std::printf("\n  %sRechenleistung ist NICHT die Huerde - Speicher ist es. Man muss\n"
                "  jede erzeugte ID behalten, um sie vergleichen zu koennen. %s\n"
                "  entspricht rund %s Festplatten a 20 TB.%s\n\n",
                C_GRAY, fmtBytes(bytes).c_str(),
                groupNum((uint64_t)(bytes / (20e12))).c_str(), C_RESET);

    double p1e12 = collisionProb(1e12, 122);
    std::snprintf(b, sizeof(b), "%s %%  %s(= 1 Billion IDs)%s", sci(p1e12 * 100, 3).c_str(), C_DIM, C_RESET);
    row("P nach 1e12", b);

    double p1e18 = collisionProb(1e18, 122);
    std::snprintf(b, sizeof(b), "%s %%  %s(= 1 Trillion IDs)%s", sci(p1e18 * 100, 3).c_str(), C_DIM, C_RESET);
    row("P nach 1e18", b, C_YEL);

    if (measuredBits > 0 && measuredSeconds > 0) {
        std::printf("\n  %sGemessen bei %d Bit: %s. Jedes zusaetzliche Bit verdoppelt%s\n",
                    C_GRAY, measuredBits, fmtDuration(measuredSeconds).c_str(), C_RESET);
        std::printf("  %sden Aufwand nicht - es sind sqrt(2) ~ 1.41x. Von %d auf 122 Bit%s\n",
                    C_GRAY, measuredBits, C_RESET);
        std::printf("  %ssind das Faktor %s.%s\n", C_GRAY,
                    sci(std::pow(2.0, (122 - measuredBits) / 2.0), 2).c_str(), C_RESET);
    }
    std::printf("\n");
}

// ----------------------------------------------------------------------------
// Ladder-Modus: Bit fuer Bit die Wand hochlaufen
// ----------------------------------------------------------------------------

struct LadderRow {
    int bits;
    uint64_t n;        // Mittelwert ueber reps Laeufe
    double seconds;    // Mittelwert
    double rate;
    int reps;
    bool found;
};

// Einzelne Laeufe streuen stark (Variationskoeffizient 0.52). Damit die Leiter
// den exponentiellen Trend zeigt statt Rauschen, wird gemittelt - so oft, wie
// es das Zeitbudget erlaubt.
static int repsFor(int bits) {
    double n = expectedN(bits);
    int r = (int)(2.0e8 / n);
    return std::max(1, std::min(21, r));
}

static void runLadder(const Config& cfg, uint64_t memBudget) {
    std::printf("\n  %s%sSKALIERUNGSLEITER%s  %s— wie die Wand exponentiell waechst%s\n",
                C_BOLD, C_CYAN, C_RESET, C_DIM, C_RESET);
    std::printf("  %s────────────────────────────────────────────────────────────────%s\n\n", C_GRAY, C_RESET);
    std::printf("  %s%-5s %4s %13s %16s %11s %11s%s\n", C_GRAY,
                "Bits", "Rep", "Theorie E[n]", "Gemessen n", "Zeit", "Rate", C_RESET);
    std::printf("  %s%s%s\n", C_GRAY,
                "----------------------------------------------------------------------", C_RESET);

    std::vector<LadderRow> rows;
    double lastRate = 0;
    int lastBits = 0;
    double lastSec = 0;

    for (int b = cfg.ladderFrom; b <= cfg.ladderTo; b += cfg.ladderStep) {
        if (g_abort.load()) break;

        int reps = repsFor(b);
        double sumN = 0, sumSec = 0, rawN = 0, rawSec = 0;
        int got = 0;
        bool memOut = false;

        for (int k = 0; k < reps && !g_abort.load(); ++k) {
            HuntResult r = hunt(cfg, b, false, memBudget);
            sumSec += r.seconds;
            rawN += (double)r.generated;      // auch abgebrochene Laeufe zaehlen
            rawSec += r.seconds;              // fuer die Durchsatzmessung
            if (r.found) { sumN += (double)r.generated; ++got; }
            if (r.memExhausted) { memOut = true; break; }
        }

        uint64_t avgN = got ? (uint64_t)(sumN / got) : 0;
        double avgSec = got ? sumSec / got : sumSec;
        double rate = rawSec > 0 ? rawN / rawSec : 0;
        rows.push_back({b, avgN, avgSec, rate, got, got > 0});

        std::printf("  %s%-5d%s %4d %13s %16s %11s %11s%s%s\n",
                    C_BOLD, b, C_RESET, got,
                    sci(expectedN(b), 2).c_str(),
                    got ? groupNum(avgN).c_str() : "-",
                    fmtDuration(avgSec).c_str(),
                    fmtRate(rate).c_str(),
                    got ? "" : (memOut ? "  [RAM voll]" : "  [Abbruch]"),
                    C_RESET);
        std::fflush(stdout);

        if (got) { lastRate = rate; lastBits = b; lastSec = avgSec; }
        if (memOut) break;
    }

    // Balkendiagramm der benoetigten UUID-Anzahl, log2-skaliert auf den
    // tatsaechlichen Wertebereich. n statt Zeit, weil n von Thread-Anzahl und
    // Cache-Verhalten unabhaengig ist - das ist die reine Mathematik.
    std::printf("\n  %sBenoetigte UUIDs pro Bitbreite (log2-Skala)%s\n\n", C_GRAY, C_RESET);
    double lmin = 1e300, lmax = -1e300;
    for (auto& r : rows)
        if (r.found && r.n > 0) {
            double l = std::log2((double)r.n);
            lmin = std::min(lmin, l);
            lmax = std::max(lmax, l);
        }
    double span = std::max(1.0, lmax - lmin);
    for (auto& r : rows) {
        if (!r.found || r.n == 0) continue;
        double frac = 0.04 + 0.96 * (std::log2((double)r.n) - lmin) / span;
        std::printf("  %s%3d%s %s%s%s %s%-14s %s%s\n", C_BOLD, r.bits, C_RESET,
                    C_BLUE, progressBar(frac, 40).c_str(), C_RESET,
                    C_DIM, groupNum(r.n).c_str(), fmtDuration(r.seconds).c_str(), C_RESET);
    }

    // Extrapolierte Zeilen bis 122
    if (lastRate > 0) {
        std::printf("\n  %sExtrapoliert bei %s:%s\n\n", C_GRAY, fmtRate(lastRate).c_str(), C_RESET);
        for (int b = lastBits + cfg.ladderStep; b <= 122; b += cfg.ladderStep) {
            double n = median50(b);
            std::printf("  %s%-6d%s %14s %16s %12s%s\n",
                        b >= 122 ? C_RED : C_YEL, b, C_RESET,
                        sci(expectedN(b), 2).c_str(), "-",
                        fmtDuration(n / lastRate).c_str(), C_RESET);
        }
        double n = median50(122);
        if ((122 - lastBits) % cfg.ladderStep != 0)
            std::printf("  %s%-6d%s %14s %16s %12s%s\n", C_RED, 122, C_RESET,
                        sci(expectedN(122), 2).c_str(), "-",
                        fmtDuration(n / lastRate).c_str(), C_RESET);

        printExtrapolation(lastRate, lastBits, lastSec);
    }
}

// ----------------------------------------------------------------------------
// Statistik-Modus: mehrere Laeufe gegen die Theorie pruefen
// ----------------------------------------------------------------------------

static void runTrials(const Config& cfg, uint64_t memBudget) {
    std::printf("\n  %s%sSTATISTIK-TEST%s  %s— %d Laeufe bei %d Bit gegen die Theorie%s\n",
                C_BOLD, C_CYAN, C_RESET, C_DIM, cfg.trials, cfg.bits, C_RESET);
    std::printf("  %s────────────────────────────────────────────────────────────────%s\n\n", C_GRAY, C_RESET);

    std::vector<double> vals;
    double sum = 0, sumRate = 0;

    for (int i = 0; i < cfg.trials && !g_abort.load(); ++i) {
        HuntResult r = hunt(cfg, cfg.bits, false, memBudget);
        if (!r.found) { std::printf("  Lauf %d: keine Kollision (RAM/Abbruch)\n", i + 1); continue; }
        vals.push_back((double)r.generated);
        sum += (double)r.generated;
        sumRate += r.rate;
        std::printf("  %sLauf %2d%s  n = %-16s  %s%s%s   %s\n", C_GRAY, i + 1, C_RESET,
                    groupNum(r.generated).c_str(), C_DIM, fmtDuration(r.seconds).c_str(), C_RESET,
                    uuidToString(r.aHi, r.aLo).c_str());
        std::fflush(stdout);
    }
    if (vals.empty()) return;

    double mean = sum / vals.size();
    double var = 0;
    for (double v : vals) var += (v - mean) * (v - mean);
    var /= vals.size();
    double sd = std::sqrt(var);
    std::sort(vals.begin(), vals.end());
    double med = vals[vals.size() / 2];

    std::printf("\n");
    row("Laeufe", std::to_string(vals.size()));
    row("Mittelwert", groupNum((uint64_t)mean), C_BOLD);
    row("Theorie E[n]", sci(expectedN(cfg.bits), 4), C_GREEN);
    char b[128];
    std::snprintf(b, sizeof(b), "%.4f  %s(1.0 = perfekt)%s", mean / expectedN(cfg.bits), C_DIM, C_RESET);
    row("Verhaeltnis", b, C_YEL);
    std::printf("\n");
    row("Median", groupNum((uint64_t)med));
    row("Theorie n50", sci(median50(cfg.bits), 4), C_GREEN);
    row("Std.Abw.", groupNum((uint64_t)sd));
    std::snprintf(b, sizeof(b), "%s  %s(theor. 0.5227)%s",
                  sci(sd / mean, 4).c_str(), C_DIM, C_RESET);
    row("Var.koeff.", b);

    printExtrapolation(sumRate / vals.size(), cfg.bits, sum / vals.size() / (sumRate / vals.size()));
}

// ----------------------------------------------------------------------------
// main
// ----------------------------------------------------------------------------

static void usage() {
    std::printf(
        "\n  UUID Collision Hunter\n\n"
        "  Optionen:\n"
        "    --bits N        Suchraum auf N Zufallsbits verkleinern (8..62, Standard 48)\n"
        "                    122 = echte UUIDv4 (findet nie etwas, reine Demo)\n"
        "    --threads N     Anzahl Threads (Standard: alle Kerne)\n"
        "    --mem GB        Speicherbudget fuer die Hashtabelle (Standard: 60%% RAM)\n"
        "    --rng NAME      xoshiro | chacha8 | rdrand   (Standard xoshiro)\n"
        "    --ladder        Skalierungsleiter: 24,28,...,52 Bit nacheinander\n"
        "    --from N --to N --step N   Bereich der Leiter\n"
        "    --trials N      N Laeufe, Statistik gegen die Theorie\n"
        "    --no-live       Kein Live-Dashboard\n"
        "    --no-color      Keine ANSI-Farben\n"
        "    --samples       10 Beispiel-UUIDs ausgeben (Cross-Check mit Python)\n"
        "    --help\n\n"
        "  Beispiele:\n"
        "    uuid_collision --bits 40            schnelle Demo (Sekundenbruchteile)\n"
        "    uuid_collision --bits 52            spuerbar laenger\n"
        "    uuid_collision --ladder             die exponentielle Wand sehen\n"
        "    uuid_collision --bits 36 --trials 30  Theorie verifizieren\n"
        "    uuid_collision --bits 122           echte UUIDv4 (laeuft ewig)\n\n");
}

int main(int argc, char** argv) {
    enableVT();
    std::signal(SIGINT, onSigint);

    Config cfg;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto val = [&](int def) -> int { return (i + 1 < argc) ? std::atoi(argv[++i]) : def; };
        if      (a == "--bits")     cfg.bits = val(48);
        else if (a == "--threads")  cfg.threads = val(0);
        else if (a == "--mem")      cfg.memGB = (i + 1 < argc) ? std::atof(argv[++i]) : 0;
        else if (a == "--trials")   { cfg.trials = val(1); cfg.live = false; }
        else if (a == "--ladder")   { cfg.ladder = true; cfg.live = false; }
        else if (a == "--from")     cfg.ladderFrom = val(24);
        else if (a == "--to")       cfg.ladderTo = val(52);
        else if (a == "--step")     cfg.ladderStep = val(4);
        else if (a == "--no-live")  cfg.live = false;
        else if (a == "--no-color") g_color = false;
        else if (a == "--samples")  cfg.samples = true;
        else if (a == "--rng") {
            std::string r = (i + 1 < argc) ? argv[++i] : "xoshiro";
            if (r == "chacha8") cfg.rng = RngKind::ChaCha8Rng;
            else if (r == "rdrand") cfg.rng = RngKind::RdRandHw;
            else cfg.rng = RngKind::Xoshiro;
        }
        else if (a == "--help" || a == "-h") { usage(); return 0; }
        else { std::printf("Unbekannte Option: %s\n", a.c_str()); usage(); return 1; }
    }

    if (cfg.samples) {
        AnyRng rng;
        std::random_device rd;
        rng.seed(cfg.rng, ((uint64_t)rd() << 32) ^ rd(), ((uint64_t)rd() << 32) ^ rd());
        for (int i = 0; i < 10; ++i) {
            uint64_t hi, lo;
            makeUuidV4(rng.next(), rng.next(), hi, lo);
            std::printf("%s\n", uuidToString(hi, lo).c_str());
        }
        return 0;
    }

    if (cfg.bits < 8 || (cfg.bits > 62 && cfg.bits != 122)) {
        std::printf("%s--bits muss zwischen 8 und 62 liegen (oder 122 fuer die Demo).%s\n"
                    "%sGrund: ab 63 Bit passt kein Eintrag mehr in 64-Bit-Slots und der\n"
                    "Speicherbedarf (2^31 * 16 B = 34 GB) ist ohnehin die harte Grenze.%s\n",
                    C_RED, C_RESET, C_GRAY, C_RESET);
        return 1;
    }

    uint64_t sysMem = systemMemoryBytes();
    uint64_t budget = cfg.memGB > 0 ? (uint64_t)(cfg.memGB * 1024.0 * 1024.0 * 1024.0)
                                    : (uint64_t)(sysMem * 0.60);

    std::printf("\n  %s%s╔══════════════════════════════════════════════════════════════╗%s\n", C_BOLD, C_CYAN, C_RESET);
    std::printf("  %s%s║   U U I D   C O L L I S I O N   H U N T E R                  ║%s\n", C_BOLD, C_CYAN, C_RESET);
    std::printf("  %s%s╚══════════════════════════════════════════════════════════════╝%s\n", C_BOLD, C_CYAN, C_RESET);
    std::printf("  %sRAM %s · Budget %s · %u Kerne · %s%s\n\n", C_GRAY,
                fmtBytes((double)sysMem).c_str(), fmtBytes((double)budget).c_str(),
                std::thread::hardware_concurrency(), rngName(cfg.rng), C_RESET);

    if (cfg.ladder) { runLadder(cfg, budget); return 0; }
    if (cfg.trials > 1) { runTrials(cfg, budget); return 0; }

    if (cfg.bits == 122) {
        std::printf("  %s%sModus: echte UUIDv4 mit 122 Zufallsbits.%s\n", C_BOLD, C_YEL, C_RESET);
        std::printf("  %sSpeichern ist unmoeglich (43 EB noetig) - es wird nur gezaehlt,\n"
                    "  damit du siehst, wie weit man in realer Zeit kommt. Strg+C beendet.%s\n\n",
                    C_GRAY, C_RESET);
    }

    HuntResult r = hunt(cfg, cfg.bits, cfg.live, budget);

    if (r.found) {
        printCollision(r, cfg.bits);
    } else if (r.aborted) {
        std::printf("\n  %sAbgebrochen nach %s UUIDs in %s (%s).%s\n", C_YEL,
                    groupNum(r.generated).c_str(), fmtDuration(r.seconds).c_str(),
                    fmtRate(r.rate).c_str(), C_RESET);
        std::printf("  %sKollisionswahrscheinlichkeit bisher: %s %%%s\n", C_GRAY,
                    sci(collisionProb((double)r.generated, cfg.bits) * 100, 4).c_str(), C_RESET);
    } else if (r.memExhausted) {
        std::printf("\n  %sKeine Kollision - Hashtabelle voll nach %s UUIDs (%s).%s\n", C_YEL,
                    groupNum(r.generated).c_str(), fmtBytes(r.tableBytes).c_str(), C_RESET);
        std::printf("  %sGenau das ist die Wand: bei %d Bit reicht der RAM nicht mehr.\n"
                    "  Mehr Speicher mit --mem GB, oder --bits kleiner waehlen.%s\n",
                    C_GRAY, cfg.bits, C_RESET);
    }

    printExtrapolation(r.rate, r.found ? cfg.bits : 0, r.found ? r.seconds : 0);
    return 0;
}
