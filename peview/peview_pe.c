#include "peview.h"

static const WCHAR *const DD_NAMES[16] = {
    L"EXPORT", L"IMPORT", L"RESOURCE", L"EXCEPTION", L"SECURITY", L"BASERELOC",
    L"DEBUG", L"ARCH", L"GLOBALPTR", L"TLS", L"LOADCONFIG", L"BOUNDIMPORT",
    L"IAT", L"DELAYIMP", L"COMDESC", L"RESERVED"
};

static const WCHAR *const RT_NAMES[] = {
    L"0", L"CURSOR", L"BITMAP", L"ICON", L"MENU", L"DIALOG", L"STRING",
    L"FONTDIR", L"FONT", L"ACCEL", L"RCDATA", L"MESSAGETABLE",
    L"GROUP_CURSOR", L"13", L"GROUP_ICON", L"15", L"VERSION",
    L"17", L"18", L"19", L"20", L"21", L"22", L"23", L"MANIFEST"
};

static const WCHAR *rt_name(u32 id)
{
    if (id < COUNTOF(RT_NAMES)) return RT_NAMES[id];
    return L"?";
}

static u8 *read_file(const WCHAR *path, u32 *outSize)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, 0, NULL);
    DWORD sz, rd = 0;
    u8 *buf;
    if (h == INVALID_HANDLE_VALUE) return NULL;
    sz = GetFileSize(h, NULL);
    if (sz == 0 || sz == INVALID_FILE_SIZE) { CloseHandle(h); return NULL; }
    buf = (u8 *)halloc(sz);
    if (!buf) { CloseHandle(h); return NULL; }
    if (!ReadFile(h, buf, sz, &rd, NULL) || rd != sz) {
        hfree(buf); CloseHandle(h); return NULL;
    }
    CloseHandle(h);
    *outSize = sz;
    return buf;
}

void vw_buf_cat(BUF *b, const WCHAR *s)
{
    buf_raw(b, s, wlen(s) * sizeof(WCHAR));
}

void vw_buf_cat_line(BUF *b, const WCHAR *s)
{
    vw_buf_cat(b, s);
    vw_buf_cat(b, L"\r\n");
}

static void cat_indent(BUF *b, int n)
{
    int i;
    for (i = 0; i < n; i++) vw_buf_cat(b, L"  ");
}

static u32 rva_to_off(const u8 *d, u32 nsec, u32 sect, u32 rva)
{
    u32 i;
    for (i = 0; i < nsec; i++) {
        u32 b = sect + i * 40;
        u32 vs = rd32(d, b + 8);
        u32 va = rd32(d, b + 12);
        u32 rs = rd32(d, b + 16);
        u32 ptr = rd32(d, b + 20);
        if (va <= rva && rva < va + (vs > rs ? vs : rs))
            return ptr + (rva - va);
    }
    return 0xFFFFFFFF;
}

/* ---- PE header dump ---- */
void peview_dump_header(const WCHAR *path, BUF *out)
{
    u32 sz, lf, opt, dd, nsec, optsize, magic, machine, i;
    u8 *d = read_file(path, &sz);
    WCHAR line[256];
    if (!d) { vw_buf_cat_line(out, L"[error] cannot read file"); return; }
    if (sz < 0x40 || d[0] != 'M' || d[1] != 'Z') {
        vw_buf_cat_line(out, L"[error] not a valid PE file");
        hfree(d); return;
    }
    lf = rd32(d, 0x3C);
    vw_buf_cat_line(out, L"【PE 头信息】解析 PE 文件头：DOS→PE→可选头→数据目录→节表");
    wsprintfW(line, L"File: %s  Size: %u bytes", path, sz);
    vw_buf_cat_line(out, line);
    wsprintfW(line, L"e_lfanew = 0x%X", lf);
    vw_buf_cat_line(out, line);
    if (d[lf] != 'P' || d[lf+1] != 'E') {
        vw_buf_cat_line(out, L"[error] PE signature mismatch");
        hfree(d); return;
    }
    machine = rd16(d, lf + 4);
    nsec    = rd16(d, lf + 6);
    optsize = rd16(d, lf + 20);
    opt     = lf + 24;
    magic   = rd16(d, opt);
    dd      = opt + (magic == 0x20B ? 112 : 96);
    wsprintfW(line, L"Machine=0x%04X  Sections=%u  OptHdrSize=%u  Magic=0x%04X",
              machine, nsec, optsize, magic);
    vw_buf_cat_line(out, line);
    wsprintfW(line, L"OptHdrOff=0x%X  DataDirOff=0x%X", opt, dd);
    vw_buf_cat_line(out, line);
    vw_buf_cat_line(out, L"");
    vw_buf_cat_line(out, L"Data Directories:");
    for (i = 0; i < 16; i++) {
        u32 va = rd32(d, dd + i * 8);
        u32 ds = rd32(d, dd + i * 8 + 4);
        wsprintfW(line, L"  [%2d] %-12s VA=0x%08X  Size=%u", i, DD_NAMES[i], va, ds);
        vw_buf_cat_line(out, line);
    }
    vw_buf_cat_line(out, L"");
    vw_buf_cat_line(out, L"Section Table:");
    {
        u32 sect = lf + 24 + optsize;
        for (i = 0; i < nsec; i++) {
            u32 b = sect + i * 40;
            WCHAR nm[9] = {0};
            u32 vs, va, rs, ptr;
            int j;
            for (j = 0; j < 8 && d[b+j]; j++) nm[j] = d[b+j];
            vs = rd32(d, b + 8); va = rd32(d, b + 12);
            rs = rd32(d, b + 16); ptr = rd32(d, b + 20);
            wsprintfW(line, L"  %-8s VA=0x%08X VSZ=%-8u RAW=0x%08X RSZ=%u",
                      nm, va, vs, ptr, rs);
            vw_buf_cat_line(out, line);
        }
    }
    hfree(d);
}

/* ---- resource list (self-parsed) ---- */
static void walk_res(const u8 *d, u32 base, u32 rsz, u32 dirOff,
                     int level, u32 tname, int tIsStr, u32 nname, int nIsStr,
                     BUF *out)
{
    u32 named, idn, i;
    WCHAR line[256];
    if (dirOff >= rsz) return;
    named = rd16(d, base + dirOff + 12);
    idn   = rd16(d, base + dirOff + 14);
    for (i = 0; i < named + idn; i++) {
        u32 e = base + dirOff + 16 + i * 8;
        u32 idv = rd32(d, e);
        u32 off = rd32(d, e + 4);
        int isstr = (idv & 0x80000000) != 0;

        u32 sub = off & 0x7FFFFFFF;
        if (level == 0) {
            walk_res(d, base, rsz, sub, 1, idv, isstr, 0, 0, out);
        } else if (level == 1) {
            walk_res(d, base, rsz, sub, 2, tname, tIsStr, idv, isstr, out);
        } else {
            u32 dataOff = base + sub;
            u32 size = rd32(d, dataOff + 4);
            cat_indent(out, 2);
            if (tIsStr) wsprintfW(line, L"(str)  ");
            else wsprintfW(line, L"%-14s ", rt_name(tname));
            vw_buf_cat(out, line);
            if (nIsStr) wsprintfW(line, L"(str)       ");
            else wsprintfW(line, L"id=%-8u ", nname);
            vw_buf_cat(out, line);
            wsprintfW(line, L"lang=0x%04X  size=%u", idv, size);
            vw_buf_cat_line(out, line);
        }
    }
}

void peview_list_resources(const WCHAR *path, BUF *out)
{
    u32 sz, lf, opt, dd, nsec, optsize, magic, rsrcRVA, rsrcSize, base, sect;
    u8 *d = read_file(path, &sz);
    WCHAR line[256];
    if (!d) { vw_buf_cat_line(out, L"[error] cannot read file"); return; }
    if (sz < 0x40 || d[0] != 'M') { vw_buf_cat_line(out, L"[error] not PE"); hfree(d); return; }
    lf = rd32(d, 0x3C);
    nsec = rd16(d, lf + 6);
    optsize = rd16(d, lf + 20);
    opt = lf + 24;
    magic = rd16(d, opt);
    dd = opt + (magic == 0x20B ? 112 : 96);
    sect = lf + 24 + optsize;
    rsrcRVA = rd32(d, dd + 16);
    rsrcSize = rd32(d, dd + 20);
    vw_buf_cat_line(out, L"【资源列表·自解析】直接读 .rsrc 节字节遍历三级目录，反映文件原始布局");
    wsprintfW(line, L"File: %s", path);
    vw_buf_cat_line(out, line);
    if (!rsrcRVA || !rsrcSize) {
        vw_buf_cat_line(out, L"No resource directory (.rsrc)");
        hfree(d); return;
    }
    base = rva_to_off(d, nsec, sect, rsrcRVA);
    if (base == 0xFFFFFFFF) {
        vw_buf_cat_line(out, L"[error] cannot locate .rsrc file offset");
        hfree(d); return;
    }
    wsprintfW(line, L".rsrc RVA=0x%X  size=%u  fileOff=0x%X", rsrcRVA, rsrcSize, base);
    vw_buf_cat_line(out, line);
    vw_buf_cat_line(out, L"");
    vw_buf_cat_line(out, L"Resources:");
    walk_res(d, base, rsrcSize, 0, 0, 0, 0, 0, 0, out);
    hfree(d);
}

/* ---- directory tree dump ---- */
void peview_dump_dir_tree(const WCHAR *path, BUF *out)
{
    u32 sz, lf, opt, dd, nsec, optsize, magic, rsrcRVA, rsrcSize, base, sect;
    u8 *d = read_file(path, &sz);
    WCHAR line[256];
    if (!d) { vw_buf_cat_line(out, L"[error] cannot read file"); return; }
    if (sz < 0x40 || d[0] != 'M') { vw_buf_cat_line(out, L"[error] not PE"); hfree(d); return; }
    lf = rd32(d, 0x3C);
    nsec = rd16(d, lf + 6);
    optsize = rd16(d, lf + 20);
    opt = lf + 24;
    magic = rd16(d, opt);
    dd = opt + (magic == 0x20B ? 112 : 96);
    sect = lf + 24 + optsize;
    rsrcRVA = rd32(d, dd + 16);
    rsrcSize = rd32(d, dd + 20);
    vw_buf_cat_line(out, L"【目录树】dump .rsrc 三级目录树原始结构：偏移/名称/ID/DIR|DATA");
    wsprintfW(line, L"File: %s", path);
    vw_buf_cat_line(out, line);
    if (!rsrcRVA || !rsrcSize) {
        vw_buf_cat_line(out, L"No resource directory");
        hfree(d); return;
    }
    base = rva_to_off(d, nsec, sect, rsrcRVA);
    if (base == 0xFFFFFFFF) {
        vw_buf_cat_line(out, L"[error] cannot locate .rsrc");
        hfree(d); return;
    }
    wsprintfW(line, L".rsrc RVA=0x%X size=%u fileOff=0x%X", rsrcRVA, rsrcSize, base);
    vw_buf_cat_line(out, line);
    vw_buf_cat_line(out, L"");
    {
        u32 named, idn, i;
        named = rd16(d, base + 12);
        idn = rd16(d, base + 14);
        wsprintfW(line, L"[ROOT] named=%u id=%u", named, idn);
        vw_buf_cat_line(out, line);
        for (i = 0; i < named + idn; i++) {
            u32 e = base + 16 + i * 8;
            u32 idv = rd32(d, e);
            u32 off = rd32(d, e + 4);
            int isstr = (idv & 0x80000000) != 0;
            int isdir = (off & 0x80000000) != 0;
            u32 sub = off & 0x7FFFFFFF;
            wsprintfW(line, L"  #%u id=0x%08X %s off=0x%08X %s",
                      i, idv, isstr ? L"(str)" : L"(id)",
                      off, isdir ? L"DIR" : L"DATA");
            vw_buf_cat_line(out, line);
            if (isdir) {
                u32 nn2 = rd16(d, base + sub + 12);
                u32 id2 = rd16(d, base + sub + 14);
                u32 j;
                wsprintfW(line, L"    [DIR] named=%u id=%u", nn2, id2);
                vw_buf_cat_line(out, line);
                for (j = 0; j < nn2 + id2; j++) {
                    u32 e2 = base + sub + 16 + j * 8;
                    u32 iv2 = rd32(d, e2);
                    u32 of2 = rd32(d, e2 + 4);
                    int s2 = (iv2 & 0x80000000) != 0;
                    int d2 = (of2 & 0x80000000) != 0;
                    u32 s2b = of2 & 0x7FFFFFFF;
                    wsprintfW(line, L"      #%u id=0x%08X %s %s",
                              j, iv2, s2 ? L"(str)" : L"(id)",
                              d2 ? L"DIR" : L"DATA");
                    vw_buf_cat_line(out, line);
                    if (d2) {
                        u32 nn3 = rd16(d, base + s2b + 12);
                        u32 id3 = rd16(d, base + s2b + 14);
                        u32 k;
                        wsprintfW(line, L"        [DIR] named=%u id=%u", nn3, id3);
                        vw_buf_cat_line(out, line);
                        for (k = 0; k < nn3 + id3; k++) {
                            u32 e3 = base + s2b + 16 + k * 8;
                            u32 iv3 = rd32(d, e3);
                            u32 of3 = rd32(d, e3 + 4);
                            u32 doff = of3 & 0x7FFFFFFF;
                            u32 rva = rd32(d, base + doff);
                            u32 dsize = rd32(d, base + doff + 4);
                            wsprintfW(line, L"          #%u lang=0x%04X -> RVA=0x%X size=%u",
                                      k, iv3, rva, dsize);
                            vw_buf_cat_line(out, line);
                        }
                    } else {
                        u32 rva = rd32(d, base + s2b);
                        u32 dsize = rd32(d, base + s2b + 4);
                        wsprintfW(line, L"        LEAF RVA=0x%X size=%u", rva, dsize);
                        vw_buf_cat_line(out, line);
                    }
                }
            } else {
                u32 rva = rd32(d, base + sub);
                u32 dsize = rd32(d, base + sub + 4);
                wsprintfW(line, L"    LEAF RVA=0x%X size=%u", rva, dsize);
                vw_buf_cat_line(out, line);
            }
        }
    }
    hfree(d);
}