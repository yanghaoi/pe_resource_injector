#include "peview.h"

static const WCHAR *const SCAN_DIRS[] = {
    L"C:\\Windows\\System32\\drivers",
    L"C:\\Windows\\System32",
    L"C:\\Program Files",
    L"C:\\Program Files (x86)",
    L"C:\\Windows"
};
#define N_SCAN_DIRS (COUNTOF(SCAN_DIRS))

static u32 check_sig_dir(const WCHAR *path)
{
    HANDLE h;
    u8 buf[0x800];
    DWORD rd = 0;
    u32 lf, opt, magic, dd, off, sz;

    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    if (!ReadFile(h, buf, sizeof(buf), &rd, NULL) || rd < 0x400) {
        CloseHandle(h); return 0;
    }
    CloseHandle(h);

    if (buf[0] != 'M' || buf[1] != 'Z') return 0;
    lf = rd32(buf, 0x3C);
    if (lf + 24 > rd) return 0;
    if (buf[lf] != 'P' || buf[lf+1] != 'E') return 0;
    magic = rd16(buf, lf + 24);
    opt = lf + 24;
    dd = opt + (magic == 0x20B ? 112 : 96);
    off = dd + 4 * 8;
    if (off + 8 > rd) return 0;

    sz = rd32(buf, off + 4);
    return sz;
}

static BOOL has_pe_ext(const WCHAR *name)
{
    u32 n = wlen(name);
    if (n < 5) return FALSE;
    if (name[n-4] == L'.' && (name[n-3] == L'e' || name[n-3] == L'E') &&
        (name[n-2] == L'x' || name[n-2] == L'X') &&
        (name[n-1] == L'e' || name[n-1] == L'E')) return TRUE;
    if (n < 5) return FALSE;
    if (name[n-4] == L'.' && (name[n-3] == L'd' || name[n-3] == L'D') &&
        (name[n-2] == L'l' || name[n-2] == L'L') &&
        (name[n-1] == L'l' || name[n-1] == L'L')) return TRUE;
    if (n < 5) return FALSE;
    if (name[n-4] == L'.' && (name[n-3] == L's' || name[n-3] == L'S') &&
        (name[n-2] == L'y' || name[n-2] == L'Y') &&
        (name[n-1] == L's' || name[n-1] == L'S')) return TRUE;
    return FALSE;
}

static void scan_dir(const WCHAR *dir, BUF *out, int *count, int maxCount)
{
    WCHAR pattern[MAX_PATH * 2];
    WIN32_FIND_DATAW fd;
    HANDLE hFind;

    if (*count >= maxCount) return;

    wsprintfW(pattern, L"%s\\*", dir);
    hFind = FindFirstFileW(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (!has_pe_ext(fd.cFileName)) continue;
        if (*count >= maxCount) break;
        {
            WCHAR full[MAX_PATH * 2];
            u32 sigSz;
            wsprintfW(full, L"%s\\%s", dir, fd.cFileName);
            sigSz = check_sig_dir(full);
            if (sigSz > 0) {
                WCHAR line[512];
                wsprintfW(line, L"  %8u  %10lu  %s", sigSz,
                          fd.nFileSizeLow, full);
                vw_buf_cat_line(out, line);
                (*count)++;
            }
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
}

void peview_scan_signatures(BUF *out)
{
    int i, count = 0;
    WCHAR line[128];

    vw_buf_cat_line(out, L"扫描系统目录中的已签名 PE 文件...");
    vw_buf_cat_line(out, L"  SigSize    FileSize    Path");
    vw_buf_cat_line(out, L"");

    for (i = 0; i < (int)N_SCAN_DIRS && count < 50; i++) {
        wsprintfW(line, L"[扫描] %s", SCAN_DIRS[i]);
        vw_buf_cat_line(out, line);
        scan_dir(SCAN_DIRS[i], out, &count, 50);
    }

    wsprintfW(line, L"共找到 %d 个已签名文件", count);
    vw_buf_cat_line(out, line);
}
void peview_scan_directory(const WCHAR *dir, BUF *out)
{
    int count = 0;
    WCHAR line[MAX_PATH * 2];

    wsprintfW(line, L"扫描目录: %s", dir);
    vw_buf_cat_line(out, line);
    vw_buf_cat_line(out, L"  SigSize    FileSize    Path");
    vw_buf_cat_line(out, L"");

    scan_dir(dir, out, &count, 500);

    wsprintfW(line, L"共找到 %d 个已签名文件", count);
    vw_buf_cat_line(out, line);
}

void peview_file_signature(const WCHAR *path, BUF *out)
{
    HANDLE h;
    u8 *d;
    DWORD sz, rd = 0;
    u32 lf, opt, magic, dd, off, sigOff, sigSize;
    WCHAR line[256];

    wsprintfW(line, L"文件: %s", path);
    vw_buf_cat_line(out, line);

    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        vw_buf_cat_line(out, L"[错误] 无法打开文件");
        return;
    }
    sz = GetFileSize(h, NULL);
    if (sz == 0 || sz == INVALID_FILE_SIZE) {
        vw_buf_cat_line(out, L"[错误] 无法获取文件大小");
        CloseHandle(h); return;
    }
    d = (u8 *)halloc(sz);
    if (!d) { CloseHandle(h); return; }
    if (!ReadFile(h, d, sz, &rd, NULL) || rd != sz) {
        vw_buf_cat_line(out, L"[错误] 读取失败");
        hfree(d); CloseHandle(h); return;
    }
    CloseHandle(h);

    if (d[0] != 'M' || d[1] != 'Z') {
        vw_buf_cat_line(out, L"[错误] 不是 PE 文件");
        hfree(d); return;
    }
    lf = rd32(d, 0x3C);
    if (d[lf] != 'P' || d[lf+1] != 'E') {
        vw_buf_cat_line(out, L"[错误] PE 签名不匹配");
        hfree(d); return;
    }

    opt = lf + 24;
    magic = rd16(d, opt);
    dd = opt + (magic == 0x20B ? 112 : 96);
    off = dd + 4 * 8;  /* Security Directory = 数据目录第 4 项 */

    sigOff  = rd32(d, off);
    sigSize = rd32(d, off + 4);

    wsprintfW(line, L"文件大小: %u 字节", sz);
    vw_buf_cat_line(out, line);
    wsprintfW(line, L"Security Directory: 文件偏移=0x%X  大小=%u", sigOff, sigSize);
    vw_buf_cat_line(out, line);
    vw_buf_cat_line(out, L"");

    if (!sigSize) {
        vw_buf_cat_line(out, L"此文件没有数字签名（Security Directory 为空）");
        hfree(d); return;
    }

    vw_buf_cat_line(out, L"数字签名信息:");
    if (sigOff + 8 <= sz) {
        u32 dwLength  = rd32(d, sigOff);
        u16 wRevision = rd16(d, sigOff + 4);
        u16 wCertType = rd16(d, sigOff + 6);
        wsprintfW(line, L"  dwLength      = %u", dwLength);
        vw_buf_cat_line(out, line);
        wsprintfW(line, L"  wRevision     = 0x%04X", wRevision);
        vw_buf_cat_line(out, line);
        wsprintfW(line, L"  wCertificateType = %u (%s)",
                  wCertType,
                  wCertType == 1 ? L"X509" :
                  wCertType == 2 ? L"PKCS7" : L"Unknown");
        vw_buf_cat_line(out, line);
        if (sigOff + dwLength <= sz) {
            wsprintfW(line, L"  证书数据      = %u 字节", dwLength - 8);
            vw_buf_cat_line(out, line);
        }
    } else {
        vw_buf_cat_line(out, L"  [警告] 证书表偏移越界");
    }
    hfree(d);
}