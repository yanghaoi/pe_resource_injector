#include "peres.h"

int buf_init(BUF *b, u32 cap)
{
    b->d = (u8 *)halloc(cap ? cap : 1024);
    if (!b->d) return 0;
    b->cap = cap ? cap : 1024;
    b->len = 0;
    return 1;
}

int buf_need(BUF *b, u32 extra)
{
    u32 need = b->len + extra;
    if (need <= b->cap) return 1;
    {
        u32 nc = b->cap;
        u8 *nd;
        while (nc < need) nc = nc + nc / 2 + 64;
        nd = (u8 *)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, b->d, (SIZE_T)nc);
        if (!nd) return 0;
        b->d = nd; b->cap = nc;
    }
    return 1;
}

void buf_u16(BUF *b, u16 v)
{
    if (!buf_need(b, 2)) return;
    b->d[b->len++] = (u8)(v & 0xFF);
    b->d[b->len++] = (u8)((v >> 8) & 0xFF);
}

void buf_raw(BUF *b, const void *p, u32 n)
{
    if (!buf_need(b, n)) return;
    mcopy(b->d + b->len, p, n);
    b->len += n;
}

void buf_zero(BUF *b, u32 n)
{
    if (!buf_need(b, n)) return;
    mfill(b->d + b->len, 0, n);
    b->len += n;
}

void buf_wstr(BUF *b, const WCHAR *s)
{
    buf_raw(b, s, (wlen(s) + 1) * sizeof(WCHAR));
}

void buf_align4(BUF *b)
{
    u32 pad = (4 - (b->len & 3)) & 3;
    if (pad) buf_zero(b, pad);
}

void buf_patch16(BUF *b, u32 off, u16 v)
{
    if (off + 2 <= b->len) {
        b->d[off]     = (u8)(v & 0xFF);
        b->d[off + 1] = (u8)((v >> 8) & 0xFF);
    }
}
