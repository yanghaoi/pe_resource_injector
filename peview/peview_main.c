#include "peview.h"

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


void WINAPI WinMainCRTStartup(void)
{
    WNDCLASSW wc;
    MSG msg;
    HINSTANCE hi = GetModuleHandleW(NULL);
    RECT rc;

    rnd_seed();

    g_vw_font = CreateFontW(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                            CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                            DEFAULT_PITCH | FF_DONTCARE, L"Consolas");
    if (!g_vw_font)
        g_vw_font = CreateFontW(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                                CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                                DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

    mfill(&wc, 0, sizeof(wc));
    wc.lpfnWndProc   = peview_wnd_proc;
    wc.hInstance     = hi;
    wc.hCursor       = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"PeViewCls";
    if (!RegisterClassW(&wc)) ExitProcess(1);

    rc.left = 0; rc.top = 0; rc.right = 800; rc.bottom = 600;
    AdjustWindowRect(&rc, WS_OVERLAPPEDWINDOW, FALSE);

    g_vw_hwnd = CreateWindowExW(0, L"PeViewCls",
        L"PE 查看器  —  PE头 / 资源 / 目录树 / 签名扫描",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        rc.right - rc.left, rc.bottom - rc.top,
        NULL, NULL, hi, NULL);
    if (!g_vw_hwnd) ExitProcess(1);

    DragAcceptFiles(g_vw_hwnd, TRUE);
    ShowWindow(g_vw_hwnd, SW_SHOW);
    UpdateWindow(g_vw_hwnd);

    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    ExitProcess(0);
}