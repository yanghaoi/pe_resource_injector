#include "peres.h"

int cli_split(WCHAR *cl, WCHAR *av[], int max)
{
    int n = 0;
    while (*cl && n < max) {
        while (*cl == L' ' || *cl == L'\t') cl++;
        if (!*cl) break;
        if (*cl == L'"') {
            cl++;
            av[n++] = cl;
            while (*cl && *cl != L'"') cl++;
            if (*cl) *cl++ = 0;
        } else {
            av[n++] = cl;
            while (*cl && *cl != L' ' && *cl != L'\t') cl++;
            if (*cl) *cl++ = 0;
        }
    }
    return n;
}

void cli_apply_list(const WCHAR *list, BOOL *arr, int n, BOOL val)
{
    while (*list) {
        if (*list >= L'0' && *list <= L'9') {
            int d = *list - L'0';
            if (d >= 0 && d < n) arr[d] = val;
        }
        list++;
    }
}

int wprefix(const WCHAR *s, const WCHAR *p)
{
    while (*p) {
        if (*s != *p) return 0;
        s++; p++;
    }
    return 1;
}

void cli_help(void)
{
    int i;
    log_add(L"peres.exe —— PE 资源 / 元数据 / 签名 克隆注入器（纯 C / Win32 / 无 CRT）");
    log_add(L"");
    log_add(L"用法: peres.exe <目标PE> [选项]");
    log_add(L"  --src=<源PE>     指定模板 PE，从中复制资源与元数据");
    log_add(L"  --copy=0,1,2     指定要复制的类别（编号见下）");
    log_add(L"  --nocopy=3       取消某个类别");
    log_add(L"  --copysig        把源 PE 的签名数据复制到输出文件");
    log_add(L"  --showsig        只显示目标文件签名信息并退出");
    log_add(L"  --inplace        就地修改（默认另存为 <原名>.patched）");
    log_add(L"  --on=3,4 / --off=0,2   打开 / 关闭随机选项");
    log_add(L"");
    log_add(L"复制类别:");
    for (i = 0; i < NCOPY; i++) {
        WCHAR b[160];
        wsprintfW(b, L"  %d %s", i, g_copyLabels[i]);
        log_add(b);
    }
    log_add(L"");
    log_add(L"随机 / 元数据选项:");
    for (i = 0; i < 8; i++) {
        WCHAR b[160];
        wsprintfW(b, L"  %d %s", i, g_cbLabels[i]);
        log_add(b);
    }
}
