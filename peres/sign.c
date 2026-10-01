#include "peres.h"

const WCHAR *trust_text(LONG r)
{
    switch ((u32)r) {
    case 0x00000000: return L"签名有效且受信任";
    case 0x800B0100: return L"没有签名 (TRUST_E_NOSIGNATURE)";
    case 0x800B0101: return L"证书已过期 (CERT_E_EXPIRED)";
    case 0x800B0109: return L"根证书不受信任 (CERT_E_UNTRUSTEDROOT)";
    case 0x800B010A: return L"证书链不完整 (CERT_E_CHAINING)";
    case 0x800B010B: return L"证书用途不正确 (CERT_E_WRONG_USAGE)";
    case 0x800B010C: return L"证书已被吊销 (CERT_E_REVOKED)";
    case 0x80096010: return L"数字摘要不匹配 (TRUST_E_BAD_DIGEST) —— 文件内容与签名不符";
    case 0x80096001: return L"签名结构错误 (TRUST_E_PROVIDER_UNKNOWN)";
    case 0x80090006: return L"无效签名 (NTE_BAD_SIGNATURE)";
    default:         return L"其它错误";
    }
}

LONG verify_trust(const WCHAR *path)
{
    /* WINTRUST_ACTION_GENERIC_VERIFY_V2 定义在 softpub.h，这里直接内联该 GUID
       值以避免引入额外的头文件与依赖：
       { 0x00AAC56B, 0xCD44, 0x11D0, { 0x8C,0xC2,0x00,0xC0,0x4F,0xC2,0x95,0xEE } } */
    GUID guid;
    guid.Data1    = 0x00AAC56Bu;
    guid.Data2    = 0xCD44u;
    guid.Data3    = 0x11D0u;
    guid.Data4[0] = 0x8Cu; guid.Data4[1] = 0xC2u; guid.Data4[2] = 0x00u; guid.Data4[3] = 0xC0u;
    guid.Data4[4] = 0x4Fu; guid.Data4[5] = 0xC2u; guid.Data4[6] = 0x95u; guid.Data4[7] = 0xEEu;
    WINTRUST_FILE_INFO fi;
    WINTRUST_DATA wd;

    mfill(&fi, 0, sizeof(fi));
    fi.cbStruct      = sizeof(fi);
    fi.pcwszFilePath = path;

    mfill(&wd, 0, sizeof(wd));
    wd.cbStruct            = sizeof(wd);
    wd.dwUIChoice          = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice       = WTD_CHOICE_FILE;
    wd.dwStateAction       = WTD_STATEACTION_IGNORE;
    wd.pFile               = &fi;

    return WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &guid, &wd);
}

void fmt_filetime(WCHAR *out, FILETIME ft)
{
    FILETIME lt;
    SYSTEMTIME st;
    if (!FileTimeToLocalFileTime(&ft, &lt) || !FileTimeToSystemTime(&lt, &st)) {
        wcopy(out, L"(未知)");
        return;
    }
    out[0] = 0;
    wcat_u32(out, st.wYear); wcat(out, L"-");
    if (st.wMonth < 10) wcat(out, L"0");
    wcat_u32(out, st.wMonth); wcat(out, L"-");
    if (st.wDay < 10) wcat(out, L"0");
    wcat_u32(out, st.wDay);
}

void show_signature(const WCHAR *path, const WCHAR *title)
{
    HCERTSTORE hStore = NULL;
    HCRYPTMSG  hMsg = NULL;
    DWORD enc = 0, ct = 0, ft = 0;
    PCCERT_CONTEXT pCert = NULL;
    WCHAR buf[640];
    LONG tr;
    int  idx = 0;

    sig_clear();
    wsprintfW(buf, L"【%s】%s", title, path);
    sig_line(buf);

    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, (const void *)path,
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0,
                          &enc, &ct, &ft, &hStore, &hMsg, NULL)) {
        sig_line(L"  结果：文件中没有嵌入的 PKCS#7 签名（未签名，或不是嵌入式格式）");
        tr = verify_trust(path);
        wsprintfW(buf, L"  WinVerifyTrust = 0x%08X : %s", (u32)tr, trust_text(tr));
        sig_line(buf);
        return;
    }

    {
        DWORD signers = 0, cb = sizeof(signers);
        if (CryptMsgGetParam(hMsg, CMSG_SIGNER_COUNT_PARAM, 0, &signers, &cb)) {
            wsprintfW(buf, L"  签名者数量：%u", signers);
            sig_line(buf);
        }
    }

    while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != NULL) {
        WCHAR subj[256], iss[256], ser[200], tp[200];
        WCHAR nb[64], na[64];
        BYTE  hash[64];
        DWORD dwd = sizeof(hash);      /* 入参必须是缓冲区大小，不能是 0 */
        int k;
        u32 z;

        idx++;
        subj[0] = 0; iss[0] = 0; ser[0] = 0; tp[0] = 0;

        CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, subj, 256);
        CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                           CERT_NAME_ISSUER_FLAG, NULL, iss, 256);

        for (k = (int)pCert->pCertInfo->SerialNumber.cbData - 1; k >= 0; k--) {
            wcat_hex(ser + wlen(ser), pCert->pCertInfo->SerialNumber.pbData[k], 2);
            if (k) wcat(ser, L" ");
        }
        if (CertGetCertificateContextProperty(pCert, CERT_HASH_PROP_ID, hash, &dwd) && dwd <= 64)
            for (z = 0; z < dwd; z++) wcat_hex(tp + wlen(tp), hash[z], 2);

        fmt_filetime(nb, pCert->pCertInfo->NotBefore);
        fmt_filetime(na, pCert->pCertInfo->NotAfter);

        wsprintfW(buf, L"  证书 #%d  使用者：%s", idx, subj); sig_line(buf);
        wsprintfW(buf, L"           颁发者：%s", iss);         sig_line(buf);
        wsprintfW(buf, L"           序列号：%s", ser);         sig_line(buf);
        wsprintfW(buf, L"           有效期：%s ~ %s", nb, na); sig_line(buf);
        wsprintfW(buf, L"           SHA1  ：%s", tp);          sig_line(buf);
    }

    if (hStore) CertCloseStore(hStore, 0);
    if (hMsg) CryptMsgClose(hMsg);

    tr = verify_trust(path);
    wsprintfW(buf, L"  WinVerifyTrust = 0x%08X : %s", (u32)tr, trust_text(tr));
    sig_line(buf);
}

/* ===========================================================================
 * 10. 读回现有版本信息 / 清理上次注入
 * =========================================================================== */

void do_read_existing(void)
{
    static const WCHAR *const KEYS[8] = {
        L"CompanyName", L"FileDescription", L"FileVersion", L"InternalName",
        L"LegalCopyright", L"OriginalFilename", L"ProductName", L"ProductVersion"
    };
    WCHAR path[MAX_PATH * 2];
    WCHAR key[64];
    DWORD dummy = 0, sz;
    void *blk, *vp;
    UINT ul;
    VINFO v;
    WCHAR *dst[8];
    int i;

    mfill(path, 0, sizeof(path));
    get_edit(g_edPath, path, MAX_PATH * 2);
    if (path[0] == 0) return;

    sz = GetFileVersionInfoSizeW(path, &dummy);
    if (!sz) { log_add(L"  该文件没有版本资源（或读取失败）。"); return; }
    blk = halloc(sz);
    if (!blk) return;
    if (!GetFileVersionInfoW(path, 0, sz, blk)) {
        hfree(blk);
        log_add(L"  GetFileVersionInfo 失败。");
        return;
    }

    mfill(&v, 0, sizeof(v));
    v.lang = 0x0409;
    v.codepage = 1200;
    vp = NULL; ul = 0;
    if (VerQueryValueW(blk, L"\\VarFileInfo\\Translation", &vp, &ul) && vp && ul >= 4) {
        v.lang = ((u16 *)vp)[0];
        v.codepage = 1200;
    }

    dst[0] = v.company;   dst[1] = v.desc;      dst[2] = v.fileVer;  dst[3] = v.internal;
    dst[4] = v.copyright; dst[5] = v.origName;  dst[6] = v.product;  dst[7] = v.prodVer;

    for (i = 0; i < 8; i++) {
        dst[i][0] = 0;
        wcopy(key, L"\\StringFileInfo\\");
        wcat_hex(key + wlen(key), v.lang, 4);
        wcat_hex(key + wlen(key), v.codepage, 4);
        wcat(key, L"\\");
        wcat(key, KEYS[i]);
        vp = NULL; ul = 0;
        if (VerQueryValueW(blk, key, &vp, &ul) && vp) {
            u32 n = wlen((const WCHAR *)vp);
            if (n > 120) n = 120;
            mcopy(dst[i], vp, n * sizeof(WCHAR));
            dst[i][n] = 0;
        }
    }
    hfree(blk);
    ui_apply(&v);
    {
        WCHAR b[256];
        wsprintfW(b, L"  已读取现有版本信息（lang=0x%04X，统一按 cp=1200 显示）。", v.lang);
        log_add(b);
    }
}


