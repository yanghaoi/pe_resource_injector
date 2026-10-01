#include "peres.h"

void do_inject(void)
{
    WCHAR tgt[MAX_PATH * 2], out[MAX_PATH * 2], tpl[MAX_PATH * 2];
    WCHAR buf[1024];
    VINFO v;
    PEHDR hT, hS;
    RESCOL col;
    RESITEM *items = NULL;
    int  nItems = 0, capItems;
    u32  nAdded = 0;
    u32  i, dot;
    u16  lang;
    BOOL haveTpl = FALSE, copyVer = FALSE, copyMeta = FALSE;
    int  cat;
    u32  verSize = 0, rcSize = 0, bmSize = 0, cxSize = 0, randItems = 0;
    u8  *verData = NULL, *rcData = NULL, *bmData = NULL, *cxData = NULL;

    mfill(tgt, 0, sizeof(tgt));
    mfill(out, 0, sizeof(out));
    mfill(tpl, 0, sizeof(tpl));
    g_lastOut[0] = 0;

    if (g_gui) { get_edit(g_edPath, tgt, MAX_PATH * 2); get_edit(g_edSrc, tpl, MAX_PATH * 2); }
    else       { wcopy(tgt, g_cliPath); wcopy(tpl, g_cliSrc); }

    if (tgt[0] == 0) {
        if (g_gui) MessageBoxW(g_hwnd, L"请先选择或拖入一个目标 PE 文件。",
                               L"提示", MB_ICONINFORMATION);
        return;
    }

    log_add(L"=========================================================");
    wsprintfW(buf, L"[目标] %s", tgt);
    log_add(buf);

    if (!pe_read_header(tgt, &hT)) {
        log_add(L"  [错误] 目标不是有效的 PE 文件，或无法读取（被占用 / 无权限）。");
        if (g_gui) MessageBoxW(g_hwnd, L"无法解析为目标 PE 文件，请确认文件有效且未被占用。",
                               L"失败", MB_ICONERROR);
        return;
    }
    wsprintfW(buf, L"  Machine=0x%04X  节数=%u  TimeDateStamp=0x%08X  CheckSum=0x%08X  链接器=%u.%u",
              hT.machine, hT.nSections, hT.timeStamp, hT.checkSum,
              hT.linkerMaj, hT.linkerMin);
    log_add(buf);
    wsprintfW(buf, L"  SizeOfImage=0x%08X  资源目录 RVA=0x%08X (%u 字节)  签名目录 off=0x%08X (%u 字节)",
              hT.sizeOfImage, hT.rsrcRVA, hT.rsrcSize, hT.secDirOff, hT.secDirSize);
    log_add(buf);

    /* ---- 源模板 ---- */
    rescol_init(&col, MAX_COPY_ITEMS);
    if (tpl[0]) {
        BOOL any = FALSE;
        for (cat = 0; cat < NCOPY; cat++) if (cp_checked(cat)) any = TRUE;
        if (any) {
            if (!pe_read_header(tpl, &hS)) {
                log_add(L"  [警告] 源 PE 无法解析，跳过复制。");
            } else {
                HMODULE hm = LoadLibraryExW(tpl, NULL, LOAD_LIBRARY_AS_DATAFILE);
                if (hm) {
                    COLCTX ctx;
                    ctx.col = &col;
                    for (cat = 0; cat < NCOPY; cat++) ctx.want[cat] = cp_checked(cat);
                    EnumResourceTypesW(hm, cb_type, (LONG_PTR)&ctx);
                    FreeLibrary(hm);
                }
                haveTpl = TRUE;
                wsprintfW(buf, L"[源模板] %s —— 收集 %d 个资源条目（%u 字节%s）",
                          tpl, col.n, col.bytes, col.skipped ? L"，部分跳过" : L"");
                log_add(buf);
                wsprintfW(buf, L"  源：TimeDateStamp=0x%08X  CheckSum=0x%08X  链接器=%u.%u  子系统=%u",
                          hS.timeStamp, hS.checkSum, hS.linkerMaj, hS.linkerMin, hS.subsystem);
                log_add(buf);
            }
        }
    }
    copyVer  = haveTpl && cp_checked(0);
    copyMeta = haveTpl && cp_checked(6);

    /* ---- 输出路径 ---- */
    {
        BOOL inplace = g_gui ? (SendMessageW(g_rbCopy, BM_GETCHECK, 0, 0) != BST_CHECKED)
                             : g_inplace;
        if (!inplace) {
            dot = wlen(tgt);
            while (dot > 0 && tgt[dot] != L'.' && tgt[dot] != L'\\' && tgt[dot] != L'/') dot--;
            if (dot > 0 && tgt[dot] == L'.') {
                mcopy(out, tgt, dot * sizeof(WCHAR));
                wcat(wcat(out, L".patched"), tgt + dot);
            } else {
                wcat(wcat(out, tgt), L".patched");
            }
            if (!CopyFileW(tgt, out, FALSE)) { log_err(L"创建副本", GetLastError()); goto cleanup; }
            wsprintfW(buf, L"  已创建副本: %s", out);
            log_add(buf);
        } else {
            WCHAR bak[MAX_PATH * 2];
            mfill(bak, 0, sizeof(bak));
            wcat(wcat(bak, tgt), L".bak");
            wcopy(out, tgt);
            if (!CopyFileW(tgt, bak, FALSE)) { log_err(L"备份原文件", GetLastError()); goto cleanup; }
            wsprintfW(buf, L"  已备份: %s", bak);
            log_add(buf);
        }
    }
    wcopy(g_lastOut, out);

    /* ---- 版本信息取值 ---- */
    ui_collect(&v);
    if (!g_gui && !copyVer) randomize_vinfo(&v);
    v.fileOS   = VOS_NT_WINDOWS32;
    v.fileType = VFT_APP;
    v.codepage = 1200;
    v.lang     = cb_checked(4) ? g_langs[rnd32() % COUNTOF(g_langs)] : 0x0409;

    {
        u32 a = 0, b = 0, c = 0, d = 0, stage = 0;
        const WCHAR *p = v.fileVer;
        while (*p) {
            if (*p >= L'0' && *p <= L'9') {
                u32 *t = (stage == 0) ? &a : (stage == 1 ? &b : (stage == 2 ? &c : &d));
                if (*t < 429496729u) *t = *t * 10 + (u32)(*p - L'0');
                else *t = 0xFFFFFFFFu;   /* 溢出钳制：字段值本身是 WORD 拼接，超界无意义 */
            } else if (*p == L'.') {
                if (stage < 3) stage++;
            }
            p++;
        }
        v.fvMS = (a << 16) | b;
        v.fvLS = (c << 16) | d;
        v.pvMS = v.fvMS;
        v.pvLS = v.fvLS;
    }
    lang = MAKELANGID(v.lang, (v.lang == 0x0409) ? SUBLANG_ENGLISH_US : SUBLANG_DEFAULT);

    /* ---- 组装条目：先复制的，再随机的 ---- */
    capItems = col.n + 8;
    if (capItems < 8) capItems = 8;
    items = (RESITEM *)halloc(sizeof(RESITEM) * (u32)capItems);
    if (!items) { log_add(L"  [错误] 内存不足。"); goto cleanup; }

    for (i = 0; i < (u32)col.n && nItems < capItems; i++) {
        if (copyVer && !col.it[i].typeStr && col.it[i].tid == 16) continue;
        items[nItems] = col.it[i];
        items[nItems].owned = FALSE;
        nItems++;
    }

    if (copyVer) {
        BOOL got = FALSE;
        for (i = 0; i < (u32)col.n && nItems < capItems; i++)
            if (!col.it[i].typeStr && col.it[i].tid == 16) {
                items[nItems] = col.it[i];
                items[nItems].owned = FALSE;
                nItems++;
                got = TRUE;
                break;
            }
        if (got) log_add(L"  版本信息：使用源 PE 的 RT_VERSION（覆盖手动/随机值）");
    } else if (cb_checked(0)) {
        verData = build_version_block(&v, &verSize);
        if (!verData) { log_add(L"  [错误] 构造版本资源失败。"); goto cleanup; }
        items[nItems].typeStr = FALSE; items[nItems].tid = 16;
        items[nItems].nameStr = FALSE; items[nItems].nid = 1;
        items[nItems].lang = lang;
        items[nItems].data = verData; items[nItems].size = verSize;
        items[nItems].owned = FALSE;
        nItems++;
        wsprintfW(buf, L"  版本资源已构造: %u 字节, lang=0x%04X cp=%u",
                  verSize, v.lang, v.codepage);
        log_add(buf);
    }

    if (cb_checked(1) && nItems < capItems) {
        WCHAR nm[32];
        rcSize = rnd_range(512, 65536);
        rcData = make_random_blob(rcSize);
        wcopy(nm, L"PRND_");
        rnd_hexstr(nm + wlen(nm), 8);
        items[nItems].typeStr = FALSE; items[nItems].tid = 10;
        items[nItems].nameStr = TRUE;  wcopy(items[nItems].nstr, nm);
        items[nItems].lang = MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL);
        items[nItems].data = rcData; items[nItems].size = rcSize;
        items[nItems].owned = FALSE;
        nItems++; randItems++;
    }
    if (cb_checked(2) && nItems < capItems) {
        u32 w = rnd_range(16, 128), h = rnd_range(16, 128);
        bmData = make_random_bitmap((int)w, (int)h, &bmSize);
        items[nItems].typeStr = FALSE; items[nItems].tid = 2;
        items[nItems].nameStr = FALSE; items[nItems].nid = rnd_range(60000, 60999);
        items[nItems].lang = MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL);
        items[nItems].data = bmData; items[nItems].size = bmSize;
        items[nItems].owned = FALSE;
        nItems++; randItems++;
    }
    if (cb_checked(3) && nItems < capItems) {
        WCHAR tn[32], nm[32];
        cxSize = rnd_range(256, 8192);
        cxData = make_random_blob(cxSize);
        wcopy(tn, L"PRND_BLOB_"); rnd_hexstr(tn + wlen(tn), 6);
        wcopy(nm, L"PRND_");      rnd_hexstr(nm + wlen(nm), 8);
        items[nItems].typeStr = TRUE; wcopy(items[nItems].tstr, tn);
        items[nItems].nameStr = TRUE; wcopy(items[nItems].nstr, nm);
        items[nItems].lang = MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL);
        items[nItems].data = cxData; items[nItems].size = cxSize;
        items[nItems].owned = FALSE;
        nItems++; randItems++;
    }

    /* ---- 写入资源 ----
     * 目标没有资源目录时 UpdateResource 会失败（ERROR 1359），必须先补一个
     * .rsrc 节；但这里只放【空】资源目录，真正的资源一律交给 UpdateResource
     * 写，让 Windows 自己构建目录（详见 updater_write_all 的注释）。 */
    if (nItems > 0 || (cb_checked(7) && hT.rsrcRVA != 0 && hT.rsrcSize != 0)) {
        BOOL needEmpty = (hT.rsrcRVA == 0 || hT.rsrcSize == 0) && nItems > 0;
        u32  savedAdded = nAdded;
        int  order, done = 0;

        for (order = 0; order < 2 && !done; order++) {
            int seen;
            if (order == 1) {
                /* 上一种顺序写出来的资源系统认不全，恢复原始副本重试 */
                if (!CopyFileW(tgt, out, FALSE)) {
                    log_err(L"恢复副本以便重试", GetLastError());
                    break;
                }
                nAdded = savedAdded;
                log_add(L"  [重试] 换一种资源提交顺序…");
            }
            if (needEmpty) {
                u8  emptyDir[16];
                u32 newRVA = 0;
                mfill(emptyDir, 0, sizeof(emptyDir));
                if (order == 0)
                    log_add(L"  目标没有资源目录：先创建空资源目录并新增 .rsrc 节");
                if (!pe_append_resource_section(out, emptyDir, 16, &newRVA)) {
                    log_add(L"  [错误] 追加 .rsrc 节失败（可能节表已满，无法新增节）。");
                    goto cleanup;
                }
                if (order == 0) {
                    wsprintfW(buf, L"  新节 .rsrc RVA=0x%08X", newRVA);
                    log_add(buf);
                }

            }
            if (!updater_write_all(out, items, nItems, randItems, order, &nAdded))
                break;

            seen = verify_items(out, items, nItems);
            if (seen < 0) { done = 1; break; }        /* 读不回来，没法校验，接受 */
            if (seen >= nItems) { done = 1; break; }
            wsprintfW(buf, L"  [校验] 只有 %d/%d 个资源能被系统识别，换顺序重试",
                      seen, nItems);
            log_add(buf);
        }
        if (!done) {
            log_add(L"  [警告] 资源已写入，但系统不能完全识别；可用资源管理器复查。");
        }
        if (cb_checked(7)) {
            int left = count_injected(out);
            if (left > 0) {
                wsprintfW(buf, L"  [提示] 仍有 %d 项上次的随机资源没被真正删除"
                               L"（Windows 未提交删除请求，文件未变化）。", left);
                log_add(buf);
            }
        }
    }

    /* ---- PE 元数据 ---- */
    if (copyMeta) {
        if (pe_patch_u32(out, hT.e_lfanew + 8, hS.timeStamp)) {
            wsprintfW(buf, L"  [OK] 复制 TimeDateStamp <- 0x%08X", hS.timeStamp);
            log_add(buf); nAdded++;
        }
        if (pe_patch_u32(out, hT.e_lfanew + 24 + 64, hS.checkSum)) {
            wsprintfW(buf, L"  [OK] 复制 CheckSum <- 0x%08X", hS.checkSum);
            log_add(buf); nAdded++;
        }
        if (pe_patch_u16(out, hT.e_lfanew + 24 + 2, hS.linkerMaj) &&
            pe_patch_u16(out, hT.e_lfanew + 24 + 3, hS.linkerMin)) {
            wsprintfW(buf, L"  [OK] 复制链接器版本 <- %u.%u", hS.linkerMaj, hS.linkerMin);
            log_add(buf); nAdded++;
        }
    } else {
        if (cb_checked(5)) {
            u32 now = time_now_stamp();
            if (pe_patch_u32(out, hT.e_lfanew + 8, now)) {
                wsprintfW(buf, L"  [OK] TimeDateStamp -> 0x%08X", now);
                log_add(buf); nAdded++;
            } else log_err(L"修补 TimeDateStamp", GetLastError());
        }
        if (cb_checked(6)) {
            if (pe_patch_u32(out, hT.e_lfanew + 24 + 64, 0)) {
                log_add(L"  [OK] OptionalHeader.CheckSum -> 0");
                nAdded++;
            } else log_err(L"修补 CheckSum", GetLastError());
        }
    }

    /* ---- 读回校验版本资源 ---- */
    if (copyVer || cb_checked(0)) {
        DWORD dummy = 0;
        DWORD sz = GetFileVersionInfoSizeW(out, &dummy);
        if (sz) {
            void *blk = halloc(sz);
            wsprintfW(buf, L"  [校验] GetFileVersionInfoSize = %u 字节", sz);
            log_add(buf);
            if (blk && GetFileVersionInfoW(out, 0, sz, blk)) {
                void *vp = NULL;
                UINT ul = 0;
                WCHAR q[64];
                u16 vl = 0x0409;
                if (VerQueryValueW(blk, L"\\VarFileInfo\\Translation", &vp, &ul) && vp && ul >= 4)
                    vl = ((u16 *)vp)[0];
                wcopy(q, L"\\StringFileInfo\\");
                wcat_hex(q + wlen(q), vl, 4);
                wcat_hex(q + wlen(q), 1200, 4);
                wcat(q, L"\\CompanyName");
                if (VerQueryValueW(blk, q, &vp, &ul) && vp) {
                    wsprintfW(buf, L"  [校验] %s => \"%s\"", q, (const WCHAR *)vp);
                    log_add(buf);
                } else {
                    log_add(L"  [校验] 版本资源已写入，但按该语言查询失败。");
                }
            }
            hfree(blk);
        } else {
            log_add(L"  [校验] 警告：写回后仍读不到版本资源。");
        }
    }

    /* ---- 签名复制（必须最后做：证书表位于文件末尾） ---- */
    if (sigcopy_checked() && tpl[0]) {
        u32 cs = 0;
        u8 *cert = pe_read_cert_table(tpl, &cs);
        if (!cert) {
            log_add(L"  [签名] 源 PE 没有嵌入式签名，跳过复制。");
        } else {
            wsprintfW(buf, L"  [签名] 从源读取证书表 %u 字节", cs);
            log_add(buf);
            if (pe_write_cert_table(out, cert, cs)) {
                LONG tr = verify_trust(out);
                wsprintfW(buf, L"  [签名] 已写入输出文件。WinVerifyTrust=0x%08X : %s",
                          (u32)tr, trust_text(tr));
                log_add(buf);
                if (tr != 0) {
                    log_add(L"  [签名] 说明：Authenticode 摘要覆盖除证书表外的全部文件内容，");
                    log_add(L"         换到另一个文件后必然不匹配。此操作只能让\"签名数据存在\"，");
                    log_add(L"         不能让它通过校验；如需有效签名，请用 signtool 重新签署。");
                }
                nAdded++;
            } else {
                log_add(L"  [错误] 写入证书表失败。");
            }
            hfree(cert);
        }
    }

    wsprintfW(buf, L"[完成] 共 %u 项改动 -> %s", nAdded, out);
    log_add(buf);

    if (g_gui) {
        WCHAR msg[640];
        wsprintfW(msg,
            L"注入完成，共 %u 项改动。\r\n\r\n输出文件：\r\n%s\r\n\r\n"
            L"注意：修改资源必然改变文件哈希，并使原有数字签名失效。",
            nAdded, out);
        MessageBoxW(g_hwnd, msg, L"完成", MB_ICONINFORMATION);
    }

cleanup:
    rescol_free(&col);
    hfree(items);
    hfree(verData);
    hfree(rcData);
    hfree(bmData);
    hfree(cxData);
}

/* ===========================================================================
 * 12. 布局与窗口过程
 * =========================================================================== */
