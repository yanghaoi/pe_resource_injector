#include "peres.h"

/* 随机文本素材池 */

const WCHAR *const g_companies[] = {
    L"Contoso Ltd.", L"Fabrikam, Inc.", L"Northwind Traders",
    L"Tailspin Toys", L"Adventure Works", L"Litware Inc.",
    L"Blue Yonder Airlines", L"Coho Vineyard & Winery",
    L"Proseware, Inc.", L"Wide World Importers", L"Trey Research",
    L"Lucerne Publishing"
};
const WCHAR *const g_products[] = {
    L"Desktop Runtime", L"Media Component", L"Document Viewer",
    L"Sync Service", L"Update Agent", L"Core Library",
    L"Utility Suite", L"Client Shell", L"Toolkit", L"Platform Package"
};
const WCHAR *const g_descs[] = {
    L"Application component", L"Core module", L"User interface host",
    L"Background service", L"Helper utility", L"Support library",
    L"Runtime host", L"Configuration tool"
};
const u16 g_langs[] = {
    0x0409, 0x0804, 0x0404, 0x0407, 0x040C, 0x0410,
    0x0411, 0x0412, 0x0419, 0x0416, 0x0405, 0x041D
};

void gen_version_string(WCHAR *out)
{
    WCHAR *p = out;
    p = wcat_u32(p, rnd_range(1, 12));   p = wcat(p, L".");
    p = wcat_u32(p, rnd_range(0, 20));   p = wcat(p, L".");
    p = wcat_u32(p, rnd_range(0, 9999)); p = wcat(p, L".");
    p = wcat_u32(p, rnd_range(0, 9999));
}

void randomize_vinfo(VINFO *v)
{
    WCHAR tmp[192];

    mfill(v, 0, sizeof(*v));
    wcopy(v->company, g_companies[rnd32() % COUNTOF(g_companies)]);
    wcopy(v->product, g_products [rnd32() % COUNTOF(g_products)]);
    wcopy(v->desc,    g_descs    [rnd32() % COUNTOF(g_descs)]);
    gen_version_string(v->fileVer);
    gen_version_string(v->prodVer);

    tmp[0] = 0; wcat(tmp, L"mod"); rnd_hexstr(tmp + wlen(tmp), 8); wcat(tmp, L".exe");
    wcopy(v->internal, tmp);
    tmp[0] = 0; wcat(tmp, L"bin"); rnd_hexstr(tmp + wlen(tmp), 6); wcat(tmp, L".exe");
    wcopy(v->origName, tmp);

    tmp[0] = 0;
    wcat(tmp, L"Copyright (c) ");
    wcat_u32(tmp, rnd_range(2015, 2026));
    wcat(tmp, L" ");
    wcat(tmp, v->company);
    wcat(tmp, L". All rights reserved.");
    wcopy(v->copyright, tmp);

    /* fvMS/fvLS/pvMS/pvLS 不在这里生成：do_inject 每次都会从 fileVer
       字符串重新解析覆盖，这里生成只会造成"DWORD 与显示字符串不对应"的隐患 */
    v->lang      = g_langs[rnd32() % COUNTOF(g_langs)];
    v->codepage  = 1200;
    v->fileOS    = VOS_NT_WINDOWS32;
    v->fileType  = VFT_APP;
}

/* VS_VERSIONINFO 二进制块构造 */

u8 *build_version_block(const VINFO *v, u32 *outSize)
{
    BUF b;
    u32 offRoot, offSFI, offST, offVFI, offV;
    VS_FIXEDFILEINFO ffi;
    WCHAR langKey[16];
    int i;

    static const WCHAR *const KEYS[8] = {
        L"CompanyName", L"FileDescription", L"FileVersion", L"InternalName",
        L"LegalCopyright", L"OriginalFilename", L"ProductName", L"ProductVersion"
    };
    const WCHAR *VALS[8];

    VALS[0] = v->company;   VALS[1] = v->desc;
    VALS[2] = v->fileVer;   VALS[3] = v->internal;
    VALS[4] = v->copyright; VALS[5] = v->origName;
    VALS[6] = v->product;   VALS[7] = v->prodVer;

    if (!buf_init(&b, 1024)) return NULL;

    offRoot = b.len;
    buf_u16(&b, 0);
    buf_u16(&b, (u16)sizeof(VS_FIXEDFILEINFO));
    buf_u16(&b, 0);
    buf_wstr(&b, L"VS_VERSION_INFO");
    buf_align4(&b);

    ffi.dwSignature        = 0xFEEF04BD;
    ffi.dwStrucVersion     = 0x00010000;
    ffi.dwFileVersionMS    = v->fvMS;
    ffi.dwFileVersionLS    = v->fvLS;
    ffi.dwProductVersionMS = v->pvMS;
    ffi.dwProductVersionLS = v->pvLS;
    ffi.dwFileFlagsMask    = 0x3F;
    ffi.dwFileFlags        = 0;
    ffi.dwFileOS           = v->fileOS;
    ffi.dwFileType         = v->fileType;
    ffi.dwFileSubtype      = VFT2_UNKNOWN;
    ffi.dwFileDateMS       = 0;
    ffi.dwFileDateLS       = 0;
    buf_raw(&b, &ffi, sizeof(ffi));

    buf_align4(&b);
    offSFI = b.len;
    buf_u16(&b, 0); buf_u16(&b, 0); buf_u16(&b, 1);
    buf_wstr(&b, L"StringFileInfo");
    buf_align4(&b);

        offST = b.len;
        buf_u16(&b, 0); buf_u16(&b, 0); buf_u16(&b, 1);
        langKey[0] = 0;
        wcat_hex(wcat_hex(langKey, v->lang, 4), v->codepage, 4);
        buf_wstr(&b, langKey);
        buf_align4(&b);

            for (i = 0; i < 8; i++) {
                u32 offS = b.len;
                u32 vlen = (wlen(VALS[i]) + 1) * (u32)sizeof(WCHAR);
                buf_u16(&b, 0);
                buf_u16(&b, (u16)vlen);
                buf_u16(&b, 1);
                buf_wstr(&b, KEYS[i]);
                buf_align4(&b);
                buf_raw(&b, VALS[i], vlen);
                buf_align4(&b);
                buf_patch16(&b, offS, (u16)(b.len - offS));
            }

        buf_patch16(&b, offST, (u16)(b.len - offST));
    buf_patch16(&b, offSFI, (u16)(b.len - offSFI));

    buf_align4(&b);
    offVFI = b.len;
    buf_u16(&b, 0); buf_u16(&b, 0); buf_u16(&b, 1);
    buf_wstr(&b, L"VarFileInfo");
    buf_align4(&b);

        offV = b.len;
        buf_u16(&b, 0); buf_u16(&b, 4); buf_u16(&b, 0);
        buf_wstr(&b, L"Translation");
        buf_align4(&b);
        buf_u16(&b, v->lang);
        buf_u16(&b, v->codepage);
        buf_patch16(&b, offV, (u16)(b.len - offV));

    buf_patch16(&b, offVFI, (u16)(b.len - offVFI));
    buf_patch16(&b, offRoot, (u16)(b.len - offRoot));

    if (outSize) *outSize = b.len;
    return b.d;
}
