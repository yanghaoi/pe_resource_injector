#include "peres.h"

void log_console(const WCHAR *s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    char   mb[1024];
    int    n;
    DWORD  wr = 0;

    n = WideCharToMultiByte(CP_UTF8, 0, s, -1, mb, (int)sizeof(mb) - 2, NULL, NULL);
    if (n <= 0) return;
    mb[n - 1] = '\r'; mb[n] = '\n'; mb[n + 1] = 0;
    WriteFile(h, mb, (DWORD)(n + 1), &wr, NULL);
}

void log_add(const WCHAR *s)
{
    DWORD len;
    if (!g_gui) { log_console(s); return; }
    if (!g_edLog) return;
    len = (DWORD)SendMessageW(g_edLog, WM_GETTEXTLENGTH, 0, 0);
    SendMessageW(g_edLog, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessageW(g_edLog, EM_REPLACESEL, 0, (LPARAM)s);
    SendMessageW(g_edLog, EM_REPLACESEL, 0, (LPARAM)L"\r\n");
    SendMessageW(g_edLog, EM_SCROLLCARET, 0, 0);
}

void sig_line(const WCHAR *s)
{
    log_add(s);
    if (g_gui && g_lbSig) SendMessageW(g_lbSig, LB_ADDSTRING, 0, (LPARAM)s);
}

void sig_clear(void)
{
    if (g_gui && g_lbSig) SendMessageW(g_lbSig, LB_RESETCONTENT, 0, 0);
}

void log_err(const WCHAR *what, DWORD err)
{
    WCHAR buf[640];
    WCHAR msg[256];
    DWORD r = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                             NULL, err, 0, msg, 255, NULL);
    if (!r) msg[0] = 0;
    wsprintfW(buf, L"  [错误] %s 失败，GetLastError=%u (0x%08X) %s", what, err, err, msg);
    log_add(buf);
}
