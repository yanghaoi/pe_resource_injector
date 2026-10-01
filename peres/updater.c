#include "peres.h"

BOOL is_prnd(const WCHAR *s)
{
    return wlen(s) >= 5 && s[0] == L'P' && s[1] == L'R' &&
           s[2] == L'N' && s[3] == L'D' && s[4] == L'_';
}

BOOL CALLBACK cb_del_lang(HMODULE hMod, LPCWSTR type, LPCWSTR name,
                                 WORD lang, LONG_PTR lp)
{
    DELCTX *c = (DELCTX *)lp;
    (void)hMod;
    UpdateResourceW(c->hUpdate, type, name, lang, NULL, 0);
    c->deleted++;
    return TRUE;
}

BOOL name_is_ours(LPWSTR name)
{
    if (IS_INTRESOURCE(name)) {
        u32 id = (u32)(ULONG_PTR)name;
        return (id >= 60000 && id <= 60999);
    }
    return is_prnd(name);
}

BOOL CALLBACK cb_del_any_name(HMODULE hMod, LPCWSTR type, LPWSTR name, LONG_PTR lp)
{
    (void)name;
    EnumResourceLanguagesW(hMod, type, name, cb_del_lang, lp);
    return TRUE;
}

BOOL CALLBACK cb_scan_name(HMODULE hMod, LPCWSTR type, LPWSTR name, LONG_PTR lp)
{
    if (name_is_ours(name)) EnumResourceLanguagesW(hMod, type, name, cb_del_lang, lp);
    return TRUE;
}

BOOL CALLBACK cb_scan_type(HMODULE hMod, LPWSTR type, LONG_PTR lp)
{
    if (!IS_INTRESOURCE(type)) {
        if (is_prnd(type)) EnumResourceNamesW(hMod, type, cb_del_any_name, lp);
    } else {
        u32 id = (u32)(ULONG_PTR)type;
        if (id == 10 || id == 2) EnumResourceNamesW(hMod, type, cb_scan_name, lp);
    }
    return TRUE;
}

int cleanup_injected(HANDLE hUp, const WCHAR *dst)
{
    HMODULE hm = LoadLibraryExW(dst, NULL, LOAD_LIBRARY_AS_DATAFILE);
    DELCTX ctx;
    ctx.hUpdate = hUp;
    ctx.deleted = 0;
    if (!hm) return 0;
    EnumResourceTypesW(hm, cb_scan_type, (LONG_PTR)&ctx);
    FreeLibrary(hm);
    return ctx.deleted;
}

/* 统计"上次注入的随机资源"还剩几个 —— 用于清理后如实校验。
   注意：实测在资源很多（数百个以上）的文件上，EndUpdateResource 有时
   并不会真正提交删除请求，文件字节完全不变。这时必须如实告诉用户，
   不能只报"清理 N 项"就了事。 */

BOOL CALLBACK cb_cnt_lang(HMODULE hMod, LPCWSTR type, LPCWSTR name,
                                 WORD lang, LONG_PTR lp)
{
    (void)hMod; (void)type; (void)name; (void)lang;
    ((CNTCTX *)lp)->n++;
    return TRUE;
}

BOOL CALLBACK cb_cnt_name(HMODULE hMod, LPCWSTR type, LPWSTR name, LONG_PTR lp)
{
    if (name_is_ours(name)) EnumResourceLanguagesW(hMod, type, name, cb_cnt_lang, lp);
    return TRUE;
}

BOOL CALLBACK cb_cnt_any_name(HMODULE hMod, LPCWSTR type, LPWSTR name, LONG_PTR lp)
{
    EnumResourceLanguagesW(hMod, type, name, cb_cnt_lang, lp);
    return TRUE;
}

BOOL CALLBACK cb_cnt_type(HMODULE hMod, LPWSTR type, LONG_PTR lp)
{
    if (!IS_INTRESOURCE(type)) {
        if (is_prnd(type)) EnumResourceNamesW(hMod, type, cb_cnt_any_name, lp);
    } else {
        u32 id = (u32)(ULONG_PTR)type;
        if (id == 10 || id == 2) EnumResourceNamesW(hMod, type, cb_cnt_name, lp);
    }
    return TRUE;
}

int count_injected(const WCHAR *path)
{
    HMODULE hm = LoadLibraryExW(path, NULL, LOAD_LIBRARY_AS_DATAFILE);
    CNTCTX c;
    c.n = 0;
    if (!hm) return -1;
    EnumResourceTypesW(hm, cb_cnt_type, (LONG_PTR)&c);
    FreeLibrary(hm);
    return c.n;
}


BOOL CALLBACK enum_lang_proc(HMODULE hMod, LPCWSTR type, LPCWSTR name,
                                    WORD lang, LONG_PTR lp)
{
    LANGLIST *L = (LANGLIST *)lp;
    (void)hMod; (void)type; (void)name;
    if (L->n < 64) L->langs[L->n++] = lang;
    return TRUE;
}

/* ---------------------------------------------------------------------------
 * 用 UpdateResource 写入全部资源
 *
 * 为什么一律走 UpdateResource，而不自己拼资源目录？
 *   实测自己构造的资源目录，在「字符串名类型(如 "MUI") + 整数 ID 类型
 *   (如 RT_BITMAP/RT_RCDATA)」混合出现时，Windows 资源 API 会看不到其中
 *   一部分类型：EnumResourceTypesW 直接跳过它们，FindResource 也失败。
 *   而由 UpdateResource / EndUpdateResource 生成的目录是系统自己维护的，
 *   不存在这个兼容性问题。所以本程序只在「目标完全没有资源目录」时
 *   补一个空目录让 UpdateResource 能用，绝不自己拼完整目录。
 * ------------------------------------------------------------------------- */
/* onlyIdx >= 0 时，这一趟只写 items[onlyIdx] 这一个资源（单独开一个会话） */
BOOL updater_write_pass(const WCHAR *out, const RESITEM *items, int nItems,
                               int onlyIdx, BOOL wantStrType, BOOL doCleanup,
                               BOOL delVer, const WCHAR *tag, u32 *nAdded)
{
    WCHAR buf[512];
    HANDLE hUp;
    u32 i, cnt = 0, written = 0;

    if (onlyIdx >= 0) {
        if (onlyIdx >= nItems) return TRUE;
        cnt = 1;
    } else {
        for (i = 0; i < (u32)nItems; i++)
            if (items[i].typeStr == wantStrType) cnt++;
    }
    /* 这一趟没有要写的资源；但如果还需要执行「清理」，会话仍要开 */
    if (cnt == 0 && !(doCleanup && cb_checked(7))) return TRUE;

    hUp = BeginUpdateResourceW(out, FALSE);
    if (!hUp) {
        log_err(L"BeginUpdateResource", GetLastError());
        log_add(L"  常见原因：文件被占用 / 只读 / 需要管理员权限。");
        return FALSE;
    }

    if (doCleanup && cb_checked(7)) {
        int n = cleanup_injected(hUp, out);
        wsprintfW(buf, L"  清理上次注入的随机资源: %d 项", n);
        log_add(buf);
    }

    /* RT_VERSION 必须按真实语言逐个删除，猜语言会让 EndUpdateResource 报 1359 */
    if (delVer) {
        LANGLIST L;
        HMODULE hm = LoadLibraryExW(out, NULL, LOAD_LIBRARY_AS_DATAFILE);
        L.n = 0;
        if (hm) {
            EnumResourceLanguagesW(hm, RT_VERSION, MAKEINTRESOURCE(VS_VERSION_INFO),
                                   enum_lang_proc, (LONG_PTR)&L);
            FreeLibrary(hm);
        }
        for (i = 0; i < (u32)L.n; i++)
            UpdateResourceW(hUp, RT_VERSION, MAKEINTRESOURCE(VS_VERSION_INFO),
                            L.langs[i], NULL, 0);
        if (L.n) {
            wsprintfW(buf, L"  已清除原有 RT_VERSION 资源（%d 种语言）", L.n);
            log_add(buf);
        }
    }

    for (i = 0; i < (u32)nItems; i++) {
        LPCWSTR lpType, lpName;
        WCHAR tbuf[64], nbuf[64];
        if (onlyIdx >= 0) { if ((int)i != onlyIdx) continue; }
        else if (items[i].typeStr != wantStrType) continue;

        lpType = items[i].typeStr ? items[i].tstr : MAKEINTRESOURCE(items[i].tid);
        lpName = items[i].nameStr ? items[i].nstr : MAKEINTRESOURCE(items[i].nid);

        if (!UpdateResourceW(hUp, lpType, lpName, items[i].lang,
                             items[i].data, items[i].size)) {
            if (items[i].typeStr) wsprintfW(tbuf, L"\"%s\"", items[i].tstr);
            else                  wsprintfW(tbuf, L"%u", items[i].tid);
            if (items[i].nameStr) wsprintfW(nbuf, L"\"%s\"", items[i].nstr);
            else                  wsprintfW(nbuf, L"%u(0x%X)", items[i].nid, items[i].nid);
            wsprintfW(buf, L"  [错误] UpdateResource 失败 type=%s name=%s "
                           L"lang=0x%04X size=%u",
                      tbuf, nbuf, items[i].lang, items[i].size);
            log_add(buf);
            log_err(L"UpdateResource", GetLastError());
            EndUpdateResourceW(hUp, TRUE);
            return FALSE;
        }
        written++;
        (*nAdded)++;
    }

    if (!EndUpdateResourceW(hUp, FALSE)) {
        log_err(L"EndUpdateResource", GetLastError());
        return FALSE;
    }
    wsprintfW(buf, L"  UpdateResource 写入 %u 个资源（%s）", written, tag);
    log_add(buf);
    return TRUE;
}

/* order = 0：先一次性写「整数 ID 类型名」，再逐个写「字符串类型名」
 * order = 1：先逐个写「字符串类型名」，再一次性写「整数 ID 类型名」
 *
 * 之所以要分趟、还要能换顺序，都是实测出来的坑：
 *   1. 同一个 BeginUpdateResource 会话里，先写「字符串类型名」资源、
 *      再写「字符串名」资源会直接失败 ERROR_NOT_SUPPORTED (50)；
 *   2. 多个「字符串类型名」资源放同一趟，系统重建目录时会丢掉别的资源；
 *   3. 两种顺序各自只在部分样本上正确 —— 所以由调用方写完后校验，
 *      不满意就恢复文件换另一种顺序重试。 */
BOOL updater_write_all(const WCHAR *out, const RESITEM *items, int nItems,
                              u32 randItems, int order, u32 *nAdded)
{
    BOOL haveVer = FALSE, first = TRUE;
    u32 i;

    (void)randItems;

    for (i = 0; i < (u32)nItems; i++)
        if (!items[i].typeStr && items[i].tid == 16) haveVer = TRUE;

    if (order == 0) {
        if (!updater_write_pass(out, items, nItems, -1, FALSE, first,
                                haveVer, L"标准类型", nAdded))
            return FALSE;
        first = FALSE;
        for (i = 0; i < (u32)nItems; i++) {
            if (!items[i].typeStr) continue;
            if (!updater_write_pass(out, items, nItems, (int)i, TRUE, first,
                                    haveVer && first, L"自定义类型", nAdded))
                return FALSE;
            first = FALSE;
        }
    } else {
        for (i = 0; i < (u32)nItems; i++) {
            if (!items[i].typeStr) continue;
            if (!updater_write_pass(out, items, nItems, (int)i, TRUE, first,
                                    haveVer && first, L"自定义类型", nAdded))
                return FALSE;
            first = FALSE;
        }
        if (!updater_write_pass(out, items, nItems, -1, FALSE, first,
                                haveVer && first, L"标准类型", nAdded))
            return FALSE;
    }
    return TRUE;
}

/* 写完后逐个 FindResource 复查：UpdateResource 报成功 ≠ 系统真能找到 */
int verify_items(const WCHAR *path, const RESITEM *items, int nItems)
{
    HMODULE hm;
    int ok = 0;
    u32 i;

    hm = LoadLibraryExW(path, NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (!hm) return -1;
    for (i = 0; i < (u32)nItems; i++) {
        LPCWSTR lpType = items[i].typeStr ? items[i].tstr
                                          : MAKEINTRESOURCE(items[i].tid);
        LPCWSTR lpName = items[i].nameStr ? items[i].nstr
                                          : MAKEINTRESOURCE(items[i].nid);
        if (FindResourceW(hm, lpName, lpType)) ok++;
    }
    FreeLibrary(hm);
    return ok;
}

/* ===========================================================================
 * 11. 主流程
 * =========================================================================== */
