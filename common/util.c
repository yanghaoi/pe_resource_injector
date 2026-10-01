#include "peres.h"

void *mcopy(void *dst, const void *src, u32 n)
{
    u8 *d = (u8 *)dst;
    const u8 *s = (const u8 *)src;
    u32 i;
    for (i = 0; i < n; i++) d[i] = s[i];
    return dst;
}

void *mfill(void *dst, int c, u32 n)
{
    u8 *d = (u8 *)dst;
    u32 i;
    for (i = 0; i < n; i++) d[i] = (u8)c;
    return dst;
}

/* ---------------------------------------------------------------------------
 * GCC 在 -O2 下即便加了 -fno-builtin，仍可能为「大结构体赋值 / 数组整体拷贝」
 * 合成对 memcpy、memset 的调用（GCC 16 实测会）。无 CRT 时就链接报错，
 * 所以这里自己提供同名实现，直接转发到上面的 mcopy / mfill。
 * 注意：不能加 static，否则不会作为全局符号参与链接。
 * ------------------------------------------------------------------------- */
void *memcpy(void *dst, const void *src, unsigned long long n)
{
    return mcopy(dst, src, (u32)n);
}

void *memset(void *dst, int c, unsigned long long n)
{
    return mfill(dst, c, (u32)n);
}

u32 wlen(const WCHAR *s)
{
    u32 n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

WCHAR *wcopy(WCHAR *d, const WCHAR *s)
{
    while (*s) *d++ = *s++;
    *d = 0;
    return d;
}

WCHAR *wcat(WCHAR *d, const WCHAR *s)
{
    while (*d) d++;
    while (*s) *d++ = *s++;
    *d = 0;
    return d;
}

int wcmpi(const WCHAR *a, const WCHAR *b)
{
    while (*a && *b) {
        WCHAR ca = *a, cb = *b;
        if (ca >= L'a' && ca <= L'z') ca = (WCHAR)(ca - 32);
        if (cb >= L'a' && cb <= L'z') cb = (WCHAR)(cb - 32);
        if (ca != cb) return (ca < cb) ? -1 : 1;
        a++; b++;
    }
    if (*a == *b) return 0;
    return (*a < *b) ? -1 : 1;
}

/* 注意：wcat_u32 / wcat_hex 必须像 wcat 一样先走到字符串末尾再追加。
   否则「fmt_filetime 里连着调用三次」这种写法会每次从开头覆写，
   最终只剩最后一次的结果。调用方若已经传入末尾指针（ser + wlen(ser)），
   这里的 while(*d) d++ 是空操作，依然兼容。 */
WCHAR *wcat_u32(WCHAR *d, u32 v)
{
    WCHAR t[16];
    int i = 0;
    while (*d) d++;
    if (v == 0) t[i++] = L'0';
    while (v) { t[i++] = (WCHAR)(L'0' + (v % 10)); v /= 10; }
    while (i) *d++ = t[--i];
    *d = 0;
    return d;
}

WCHAR *wcat_hex(WCHAR *d, u32 v, int digits)
{
    const WCHAR *HD = L"0123456789ABCDEF";
    WCHAR t[16];
    int i;
    while (*d) d++;
    for (i = 0; i < digits && i < 16; i++) { t[i] = HD[v & 0xF]; v >>= 4; }
    while (i) *d++ = t[--i];
    *d = 0;
    return d;
}

u32 alignto(u32 v, u32 a)
{
    if (a == 0) return v;
    return (v + a - 1) / a * a;
}

void put16(u8 *p, u32 off, u16 v)
{
    p[off] = (u8)(v & 0xFF); p[off + 1] = (u8)((v >> 8) & 0xFF);
}

void put32(u8 *p, u32 off, u32 v)
{
    p[off] = (u8)(v & 0xFF);             p[off + 1] = (u8)((v >> 8) & 0xFF);
    p[off + 2] = (u8)((v >> 16) & 0xFF); p[off + 3] = (u8)((v >> 24) & 0xFF);
}

u32 rd16(const u8 *p, u32 o) { return (u32)p[o] | ((u32)p[o + 1] << 8); }

u32 rd32(const u8 *p, u32 o)
{
    return (u32)p[o] | ((u32)p[o + 1] << 8) |
           ((u32)p[o + 2] << 16) | ((u32)p[o + 3] << 24);
}

void *halloc(u32 bytes)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)bytes);
}

void hfree(void *p)
{
    if (p) HeapFree(GetProcessHeap(), 0, p);
}

/* --- 伪随机数：xorshift64 --- */
u64 g_rndState;

void rnd_seed(void)
{
    LARGE_INTEGER pc;
    u64 v = 0x9E3779B97F4A7C15ULL;
    if (QueryPerformanceCounter(&pc)) v ^= (u64)pc.QuadPart;
    v ^= ((u64)GetTickCount64() << 17);
    v ^= ((u64)GetCurrentProcessId() << 33);
    v ^= ((u64)GetCurrentThreadId() << 7);
    if (v == 0) v = 0x2545F4914F6CDD1DULL;
    g_rndState = v;
}

u32 rnd32(void)
{
    u64 x = g_rndState;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    g_rndState = x;
    return (u32)(x >> 32);
}

u32 rnd_range(u32 lo, u32 hi)
{
    u32 span, lim, x;
    if (hi <= lo) return lo;
    span = hi - lo + 1;
    if (span == 0) return lo + (rnd32() >> 1);   /* hi=0xFFFFFFFF,lo=0 时 span 溢出为 0 */
    lim = 0xFFFFFFFFu - (0xFFFFFFFFu % span);    /* 拒绝采样，消除取模偏差 */
    do { x = rnd32(); } while (x > lim);
    return lo + (x % span);
}

void rnd_bytes(u8 *p, u32 n)
{
    u32 i;
    for (i = 0; i < n; i++) p[i] = (u8)(rnd32() & 0xFF);
}

void rnd_hexstr(WCHAR *out, u32 n)
{
    u32 i;
    for (i = 0; i < n; i++) out[i] = L"0123456789ABCDEF"[rnd32() & 0xF];
    out[n] = 0;
}
