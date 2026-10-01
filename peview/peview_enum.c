#include "peview.h"

static const WCHAR *const VW_RT[] = {
    L"0", L"CURSOR", L"BITMAP", L"ICON", L"MENU", L"DIALOG", L"STRING",
    L"FONTDIR", L"FONT", L"ACCEL", L"RCDATA", L"MESSAGETABLE",
    L"GROUP_CURSOR", L"13", L"GROUP_ICON", L"15", L"VERSION",
    L"17", L"18", L"19", L"20", L"21", L"22", L"23", L"MANIFEST"
};

static const WCHAR *enum_rt_name(LPWSTR p)
{
    static WCHAR buf[32];
    u32 v = (u32)(ULONG_PTR)p;
    if ((v >> 16) == 0) {
        if (v < COUNTOF(VW_RT)) return VW_RT[v];
        wsprintfW(buf, L"%u", v);
        return buf;
    }
    return p;
}

static const WCHAR *enum_name_str(LPWSTR p)
{
    static WCHAR buf[32];
    u32 v = (u32)(ULONG_PTR)p;
    if ((v >> 16) == 0) {
        wsprintfW(buf, L"id=%u", v);
        return buf;
    }
    return p;
}

static BOOL CALLBACK enum_lang_cb(HMODULE hm, LPCWSTR type, LPCWSTR name,
                                   WORD lang, LONG_PTR lp)
{
    BUF *out = (BUF *)lp;
    WCHAR line[256];
    wsprintfW(line, L"    lang=0x%04X", lang);
    vw_buf_cat_line(out, line);
    return TRUE;
}

static BOOL CALLBACK enum_name_cb(HMODULE hm, LPCWSTR type, LPWSTR name,
                                   LONG_PTR lp)
{
    BUF *out = (BUF *)lp;
    WCHAR line[256];
    wsprintfW(line, L"  name=%s", enum_name_str(name));
    vw_buf_cat_line(out, line);
    EnumResourceLanguagesW(hm, type, name, enum_lang_cb, lp);
    return TRUE;
}

static BOOL CALLBACK enum_type_cb(HMODULE hm, LPWSTR type, LONG_PTR lp)
{
    BUF *out = (BUF *)lp;
    WCHAR line[256];
    wsprintfW(line, L"type=%s", enum_rt_name(type));
    vw_buf_cat_line(out, line);
    EnumResourceNamesW(hm, type, enum_name_cb, lp);
    return TRUE;
}

void peview_enum_resources(const WCHAR *path, BUF *out)
{
    HMODULE hm;
    WCHAR line[256];

    vw_buf_cat_line(out, L"【API 枚举·系统】LoadLibraryEx 加载后 EnumResourceTypesW 枚举，结果由 Windows 加载器保证");
    wsprintfW(line, L"文件: %s", path);
    vw_buf_cat_line(out, line);

    hm = LoadLibraryExW(path, NULL, 0x00000002);
    if (!hm) {
        DWORD err = GetLastError();
        wsprintfW(line, L"[错误] LoadLibraryEx 失败, GetLastError=%u", err);
        vw_buf_cat_line(out, line);
        return;
    }

    vw_buf_cat_line(out, L"Windows API 枚举结果:");
    vw_buf_cat_line(out, L"");
    EnumResourceTypesW(hm, enum_type_cb, (LONG_PTR)out);
    FreeLibrary(hm);
}