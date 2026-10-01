#include "peres.h"

BOOL pe_parse(const u8 *buf, u32 size, PEHDR *h)
{
    u32 lf, opt, dd;

    if (size < 0x40 || buf[0] != 'M' || buf[1] != 'Z') return FALSE;
    lf = rd32(buf, 0x3C);
    if (lf + 24 + 68 > size) return FALSE;
    if (buf[lf] != 'P' || buf[lf + 1] != 'E' || buf[lf + 2] || buf[lf + 3]) return FALSE;

    opt = lf + 24;
    {
        u32 ddOff = (rd16(buf, opt) == 0x20B) ? 112u : 96u;
        if (opt + ddOff + 40 > size) return FALSE;   /* dd+36 是本函数最大读取偏移 */
        dd = opt + ddOff;
    }

    h->e_lfanew      = lf;
    h->machine       = (u16)rd16(buf, lf + 4);
    h->nSections     = (u16)rd16(buf, lf + 6);
    h->timeStamp     = rd32(buf, lf + 8);
    h->sizeOfOptHdr  = (u16)rd16(buf, lf + 20);
    h->optMagic      = (u16)rd16(buf, opt);
    h->linkerMaj     = buf[opt + 2];
    h->linkerMin     = buf[opt + 3];
    h->sectAlign     = rd32(buf, opt + 32);
    h->fileAlign     = rd32(buf, opt + 36);
    h->sizeOfImage   = rd32(buf, opt + 56);
    h->sizeOfHeaders = rd32(buf, opt + 60);
    h->checkSum      = rd32(buf, opt + 64);
    h->subsystem     = (u16)rd16(buf, opt + 68);
    h->rsrcRVA       = rd32(buf, dd + 16);
    h->rsrcSize      = rd32(buf, dd + 20);
    h->secDirOff     = rd32(buf, dd + 32);
    h->secDirSize    = rd32(buf, dd + 36);
    h->ddOff         = dd;
    h->fileSize      = size;
    return TRUE;
}

BOOL pe_read_header(const WCHAR *path, PEHDR *h)
{
    HANDLE f;
    DWORD lo, rd = 0;
    u8 *buf;
    BOOL ok;

    f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return FALSE;

    lo = GetFileSize(f, NULL);
    if (lo == INVALID_FILE_SIZE || lo < 0x200 || lo > 512u * 1024 * 1024) {
        CloseHandle(f);
        return FALSE;
    }
    buf = (u8 *)halloc(4096);
    if (!buf) { CloseHandle(f); return FALSE; }
    ok = ReadFile(f, buf, 4096, &rd, NULL) && rd >= 0x200 && pe_parse(buf, rd, h);
    if (ok) h->fileSize = lo;
    hfree(buf);
    CloseHandle(f);
    return ok;
}

BOOL pe_patch_u32(const WCHAR *path, u32 fileOffset, u32 value)
{
    HANDLE f;
    DWORD wr = 0;
    BOOL ok;

    f = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return FALSE;
    if (SetFilePointer(f, (LONG)fileOffset, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        if (GetLastError() != NO_ERROR) { CloseHandle(f); return FALSE; }
    }
    ok = WriteFile(f, &value, 4, &wr, NULL) && (wr == 4);
    FlushFileBuffers(f);
    CloseHandle(f);
    return ok;
}

BOOL pe_patch_u16(const WCHAR *path, u32 fileOffset, u16 value)
{
    HANDLE f;
    DWORD wr = 0;
    BOOL ok;

    f = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return FALSE;
    if (SetFilePointer(f, (LONG)fileOffset, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        if (GetLastError() != NO_ERROR) { CloseHandle(f); return FALSE; }
    }
    ok = WriteFile(f, &value, 2, &wr, NULL) && (wr == 2);
    FlushFileBuffers(f);
    CloseHandle(f);
    return ok;
}

u32 time_now_stamp(void)
{
    SYSTEMTIME st;
    FILETIME ft;
    u64 t;
    GetSystemTime(&st);
    if (!SystemTimeToFileTime(&st, &ft)) return (u32)GetTickCount64();
    t = ((u64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    t -= 116444736000000000ULL;
    return (u32)(t / 10000000ULL);
}

BOOL pe_append_resource_section(const WCHAR *path, u8 *res, u32 resSize, u32 *outRVA)
{
    HANDLE f;
    DWORD lo, rd = 0, wr = 0;
    u8   *img = NULL, *final = NULL;
    u32   lf, opt, secTab, dd;
    u32   newVA, newPtr, newRaw, newVirt, maxEnd = 0, maxRawEnd = 0;
    u32   i, finalSize;
    PEHDR h;
    BOOL  ok = FALSE;

    f = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return FALSE;

    lo = GetFileSize(f, NULL);
    if (lo == INVALID_FILE_SIZE || lo < 0x200 || lo > 512u * 1024 * 1024) goto done;

    img = (u8 *)halloc(lo);
    if (!img) goto done;
    if (!ReadFile(f, img, lo, &rd, NULL) || rd != lo) goto done;
    if (!pe_parse(img, lo, &h)) goto done;

    lf     = h.e_lfanew;
    opt    = lf + 24;
    secTab = opt + h.sizeOfOptHdr;
    dd     = h.ddOff;

    if (h.sectAlign == 0) h.sectAlign = 0x1000;
    if (h.fileAlign == 0) h.fileAlign = 0x200;
    if (secTab + (h.nSections + 1) * 40 > h.sizeOfHeaders) goto done;

    for (i = 0; i < h.nSections; i++) {
        u32 sh = secTab + i * 40;
        u32 va = rd32(img, sh + 12);
        u32 vs = rd32(img, sh + 8);
        u32 rs = rd32(img, sh + 16);
        u32 pr = rd32(img, sh + 20);
        u32 vEnd = va + (vs ? vs : rs);
        u32 rEnd = pr + rs;
        if (vEnd > maxEnd) maxEnd = vEnd;
        if (rEnd > maxRawEnd) maxRawEnd = rEnd;
    }

    newVA   = alignto(maxEnd, h.sectAlign);
    newPtr  = alignto((maxRawEnd > lo ? maxRawEnd : lo), h.fileAlign);
    newRaw  = alignto(resSize, h.fileAlign);
    newVirt = resSize;

    /* 叶子数据项 OffsetToData：节内偏移 -> 真正 RVA */
    {
        u32 nt = rd16(res, 12) + rd16(res, 14);
        u32 t;
        for (t = 0; t < nt; t++) {
            u32 sub = rd32(res, 16 + t * 8 + 4);
            u32 d2, nn, n;
            if (!(sub & 0x80000000u)) continue;
            d2 = sub & 0x7FFFFFFFu;
            nn = rd16(res, d2 + 12) + rd16(res, d2 + 14);
            for (n = 0; n < nn; n++) {
                u32 sub2 = rd32(res, d2 + 16 + n * 8 + 4);
                u32 d3, nl, l;
                if (!(sub2 & 0x80000000u)) continue;
                d3 = sub2 & 0x7FFFFFFFu;
                nl = rd16(res, d3 + 12) + rd16(res, d3 + 14);
                for (l = 0; l < nl; l++) {
                    u32 de = rd32(res, d3 + 16 + l * 8 + 4);
                    if (de >= resSize) continue;
                    put32(res, de, rd32(res, de) + newVA);
                }
            }
        }
    }

    finalSize = newPtr + newRaw;
    final = (u8 *)halloc(finalSize);
    if (!final) goto done;
    mcopy(final, img, lo);
    mcopy(final + newPtr, res, resSize);

    {
        u32 sh = secTab + h.nSections * 40;
        mcopy(final + sh, ".rsrc\0\0", 8);
        put32(final, sh + 8,  newVirt);
        put32(final, sh + 12, newVA);
        put32(final, sh + 16, newRaw);
        put32(final, sh + 20, newPtr);
        put32(final, sh + 24, 0);
        put32(final, sh + 28, 0);
        put16(final, sh + 32, 0);
        put16(final, sh + 34, 0);
        put32(final, sh + 36, 0x40000040u);
    }

    put16(final, lf + 6, (u16)(h.nSections + 1));
    {
        u32 nsz = alignto(newVA + newVirt, h.sectAlign);
        if (nsz > h.sizeOfImage) put32(final, opt + 56, nsz);
    }
    put32(final, dd + 16, newVA);
    put32(final, dd + 20, resSize);
    put32(final, opt + 64, 0);

    if (SetFilePointer(f, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        if (GetLastError() != NO_ERROR) goto done;
    }
    if (!WriteFile(f, final, finalSize, &wr, NULL) || wr != finalSize) goto done;
    SetEndOfFile(f);
    FlushFileBuffers(f);
    if (outRVA) *outRVA = newVA;
    ok = TRUE;

done:
    hfree(img);
    hfree(final);
    CloseHandle(f);
    return ok;
}

/* ---- Security Directory / WIN_CERTIFICATE ---- */

u8 *pe_read_cert_table(const WCHAR *path, u32 *outSize)
{
    PEHDR h;
    HANDLE f;
    u8 *buf = NULL;
    DWORD rd = 0;

    if (!pe_read_header(path, &h)) return NULL;
    if (h.secDirOff == 0 || h.secDirSize == 0) return NULL;
    if (h.secDirSize > 64u * 1024 * 1024) return NULL;
    if (h.secDirOff + h.secDirSize > h.fileSize) return NULL;

    f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return NULL;

    buf = (u8 *)halloc(h.secDirSize);
    if (!buf) { CloseHandle(f); return NULL; }
    if (SetFilePointer(f, (LONG)h.secDirOff, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        if (GetLastError() != NO_ERROR) { hfree(buf); CloseHandle(f); return NULL; }
    }
    if (!ReadFile(f, buf, h.secDirSize, &rd, NULL) || rd != h.secDirSize) {
        hfree(buf); buf = NULL;
    }
    CloseHandle(f);
    if (buf) *outSize = h.secDirSize;
    return buf;
}

BOOL pe_write_cert_table(const WCHAR *path, const u8 *cert, u32 certSize)
{
    PEHDR h;
    HANDLE f;
    DWORD lo, wr = 0;
    u32 at;
    BOOL ok = FALSE;

    if (!pe_read_header(path, &h)) return FALSE;

    f = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return FALSE;

    lo = GetFileSize(f, NULL);
    if (lo == INVALID_FILE_SIZE) goto done;
    at = alignto(lo, 8);

    if (SetFilePointer(f, (LONG)at, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        if (GetLastError() != NO_ERROR) goto done;
    }
    if (!WriteFile(f, cert, certSize, &wr, NULL) || wr != certSize) goto done;
    SetEndOfFile(f);

    /* Security Directory 的 "VirtualAddress" 字段实际存的是文件偏移 */
    if (SetFilePointer(f, (LONG)(h.ddOff + 32), NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        if (GetLastError() != NO_ERROR) goto done;
    }
    if (!WriteFile(f, &at, 4, &wr, NULL) || wr != 4) goto done;
    if (!WriteFile(f, &certSize, 4, &wr, NULL) || wr != 4) goto done;
    FlushFileBuffers(f);
    ok = TRUE;

done:
    CloseHandle(f);
    return ok;
}

/* ===========================================================================
 * 5. 随机资源生成
 * =========================================================================== */

u8 *make_random_blob(u32 size)
{
    u8 *p = (u8 *)halloc(size ? size : 1);
    if (!p) return NULL;
    rnd_bytes(p, size);
    return p;
}

u8 *make_random_bitmap(int w, int h, u32 *outSize)
{
    BITMAPINFOHEADER bi;
    u32 row, px, total;
    u8 *p, *pix;
    u32 y, x;

    row   = (u32)((w * 4 + 3) & ~3);
    px    = row * (u32)h;
    total = (u32)sizeof(bi) + px;
    p     = (u8 *)halloc(total);
    if (!p) return NULL;

    bi.biSize          = sizeof(bi);
    bi.biWidth         = w;
    bi.biHeight        = h;
    bi.biPlanes        = 1;
    bi.biBitCount      = 32;
    bi.biCompression   = BI_RGB;
    bi.biSizeImage     = px;
    bi.biXPelsPerMeter = 0;
    bi.biYPelsPerMeter = 0;
    bi.biClrUsed       = 0;
    bi.biClrImportant  = 0;
    mcopy(p, &bi, sizeof(bi));

    pix = p + sizeof(bi);
    for (y = 0; y < (u32)h; y++) {
        for (x = 0; x < (u32)w; x++) {
            u8 *q = pix + y * row + x * 4;
            q[0] = (u8)(rnd32() & 0xFF);
            q[1] = (u8)(rnd32() & 0xFF);
            q[2] = (u8)(rnd32() & 0xFF);
            q[3] = 0xFF;
        }
    }
    *outSize = total;
    return p;
}

