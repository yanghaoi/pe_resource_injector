#include "peres.h"

/* ---------------------------------------------------------------------------
 * 无 CRT 必备：___chkstk_ms
 * 函数栈帧超过一页（4KB）时 MinGW 的 GCC 会插入 call ___chkstk_ms 逐页触碰
 * 栈空间。该符号平时由 CRT 提供，这里必须自己实现。
 * 入口：rax = 待分配字节数；不得破坏 rax（后面还要 sub rax,rsp）。
 * --------------------------------------------------------------------------- */
/* ---------------------------------------------------------------------------
 * 无 CRT 必备：___chkstk_ms
 * 函数栈帧超过一页（4KB）时 MinGW 的 GCC 会插入 call ___chkstk_ms 逐页触碰
 * 栈空间。该符号平时由 CRT 提供，这里必须自己实现。
 * 入口：rax = 待分配字节数；不得破坏 rax（后面还要 sub rax,rsp）。
 * --------------------------------------------------------------------------- */
__asm__(
    ".globl ___chkstk_ms\n\t"
    "___chkstk_ms:\n\t"
    "  pushq %rcx\n\t"
    "  pushq %rax\n\t"
    "  cmpq  $0x1000, %rax\n\t"
    "  leaq  24(%rsp), %rcx\n\t"
    "  jb    1f\n\t"
    "2:\n\t"
    "  subq  $0x1000, %rcx\n\t"
    "  testq %rax, -8(%rcx)\n\t"
    "  subq  $0x1000, %rax\n\t"
    "  cmpq  $0x1000, %rax\n\t"
    "  ja    2b\n\t"
    "1:\n\t"
    "  subq  %rax, %rcx\n\t"
    "  testq %rax, -8(%rcx)\n\t"
    "  popq  %rax\n\t"
    "  popq  %rcx\n\t"
    "  ret\n\t"
);

/* 全局选项与路径（命令行 / GUI 共用） */

BOOL  g_gui     = TRUE;
BOOL  g_opt[8];
BOOL  g_copy[NCOPY];
BOOL  g_copySig = FALSE;
BOOL  g_inplace = FALSE;
BOOL  g_onlySig = FALSE;
WCHAR g_cliPath[MAX_PATH * 2];
WCHAR g_cliSrc[MAX_PATH * 2];

/* 入口 */

void WINAPI WinMainCRTStartup(void)
{
    WNDCLASSW wc;
    MSG msg;
    HINSTANCE hi = GetModuleHandleW(NULL);
    RECT rc;

    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    rnd_seed();

    g_opt[0] = TRUE; g_opt[1] = TRUE;  g_opt[2] = TRUE;  g_opt[3] = FALSE;
    g_opt[4] = FALSE; g_opt[5] = TRUE; g_opt[6] = TRUE;  g_opt[7] = TRUE;
    g_copy[0] = TRUE; g_copy[1] = TRUE; g_copy[2] = TRUE; g_copy[3] = TRUE;
    g_copy[4] = TRUE; g_copy[5] = TRUE; g_copy[6] = FALSE;

    {
        WCHAR  cmdline[2048];
        WCHAR *av[16];
        int n, i, haveFile = 0, wantHelp = 0;

        mfill(cmdline, 0, sizeof(cmdline));
        {
            const WCHAR *s = GetCommandLineW();
            u32 k = 0;
            while (s[k] && k < 2047) { cmdline[k] = s[k]; k++; }
            if (cmdline[0] == L'"') {
                k = 1;
                while (cmdline[k] && cmdline[k] != L'"') k++;
                if (cmdline[k]) k++;
            } else {
                k = 0;
                while (cmdline[k] && cmdline[k] != L' ' && cmdline[k] != L'\t') k++;
            }
            n = cli_split(cmdline + k, av, 16);
        }
        for (i = 0; i < n; i++) {
            if (av[i][0] != L'-' || av[i][1] != L'-') {
                if (!haveFile && av[i][0]) { wcopy(g_cliPath, av[i]); haveFile = 1; }
                continue;
            }
            if (!wcmpi(av[i], L"--help")) wantHelp = 1;
            else if (!wcmpi(av[i], L"--inplace")) g_inplace = TRUE;
            else if (!wcmpi(av[i], L"--copysig")) g_copySig = TRUE;
            else if (!wcmpi(av[i], L"--showsig")) g_onlySig = TRUE;
            else if (wprefix(av[i], L"--src="))    wcopy(g_cliSrc, av[i] + 6);
            else if (wprefix(av[i], L"--copy="))   cli_apply_list(av[i] + 7, g_copy, NCOPY, TRUE);
            else if (wprefix(av[i], L"--nocopy=")) cli_apply_list(av[i] + 9, g_copy, NCOPY, FALSE);
            else if (wprefix(av[i], L"--on="))     cli_apply_list(av[i] + 5, g_opt, 8, TRUE);
            else if (wprefix(av[i], L"--off="))    cli_apply_list(av[i] + 6, g_opt, 8, FALSE);
        }
        if (wantHelp) { g_gui = FALSE; cli_help(); CoUninitialize(); ExitProcess(0); }
        if (haveFile) g_gui = FALSE;
    }

    if (!g_gui) {
        if (g_onlySig) show_signature(g_cliPath, L"目标文件签名");
        else           do_inject();
        CoUninitialize();
        ExitProcess(0);
    }

    g_font = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                         DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                         DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE,
                         L"Microsoft YaHei UI");
    if (!g_font)
        g_font = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                             DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE,
                             L"Segoe UI");

    mfill(&wc, 0, sizeof(wc));
    wc.lpfnWndProc   = wnd_proc;
    wc.hInstance     = hi;
    wc.hCursor       = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"PeResInjectorCls";
    if (!RegisterClassW(&wc)) ExitProcess(1);

    rc.left = 0; rc.top = 0; rc.right = 1020; rc.bottom = 900;
    AdjustWindowRect(&rc, WS_OVERLAPPEDWINDOW, FALSE);

    g_hwnd = CreateWindowExW(0, L"PeResInjectorCls",
                             L"PE 资源 / 元数据 / 签名 克隆注入器  —  纯 C / Win32 API / 无 CRT",
                             WS_OVERLAPPEDWINDOW,
                             CW_USEDEFAULT, CW_USEDEFAULT,
                             rc.right - rc.left, rc.bottom - rc.top,
                             NULL, NULL, hi, NULL);
    if (!g_hwnd) ExitProcess(1);

    build_ui();
    ShowWindow(g_hwnd, SW_SHOW);
    UpdateWindow(g_hwnd);

    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    CoUninitialize();
    ExitProcess(0);
}
