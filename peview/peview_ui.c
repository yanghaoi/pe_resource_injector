#include "peview.h"


HWND g_vw_hwnd    = NULL;
HWND g_vw_edPath  = NULL;
HWND g_vw_edResult = NULL;
HFONT g_vw_font   = NULL;

static HWND s_btnBrowse = NULL;
static HWND s_btnHeader = NULL;
static HWND s_btnList   = NULL;
static HWND s_btnEnum   = NULL;
static HWND s_btnDir    = NULL;
static HWND s_btnSig    = NULL;


static HWND mk_btn(const WCHAR *text, int id, int x, int y, int w, int h)
{
    return CreateWindowExW(0, L"BUTTON", text,
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        x, y, w, h, g_vw_hwnd, (HMENU)(ULONG_PTR)id, NULL, NULL);
}

void peview_build_ui(HWND hwnd)
{
    g_vw_edPath = CreateWindowExW(0, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | WS_BORDER,
        0, 0, 0, 0, hwnd, (HMENU)ID_VW_ED_PATH, NULL, NULL);

    s_btnBrowse = mk_btn(L"浏览", ID_VW_BTN_BROWSE, 0, 0, 60, 24);
    s_btnHeader = mk_btn(L"PE 头信息", ID_VW_BTN_HEADER, 0, 0, 90, 24);
    s_btnList   = mk_btn(L"资源列表", ID_VW_BTN_LISTRES, 0, 0, 90, 24);
    s_btnEnum   = mk_btn(L"API枚举资源", ID_VW_BTN_ENUMRES, 0, 0, 90, 24);
    s_btnDir    = mk_btn(L"目录树",   ID_VW_BTN_DIRTREE, 0, 0, 90, 24);
    s_btnSig    = mk_btn(L"签名扫描", ID_VW_BTN_SIGSCAN, 0, 0, 90, 24);

    g_vw_edResult = CreateWindowExW(0, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL |
        ES_READONLY | WS_VSCROLL | WS_BORDER,
        0, 0, 0, 0, hwnd, (HMENU)ID_VW_ED_RESULT, NULL, NULL);

    {
        HWND all[] = { g_vw_edPath, s_btnBrowse, s_btnHeader, s_btnList,
                       s_btnEnum, s_btnDir, s_btnSig, g_vw_edResult };
        int i;
        for (i = 0; i < (int)COUNTOF(all); i++)
            SendMessageW(all[i], WM_SETFONT, (WPARAM)g_vw_font, 0);
    }

}

void peview_layout(int cw, int ch)
{
    int y = 8, gap = 6;
    int btnW = 90, btnH = 24;
    int x = gap;

    MoveWindow(g_vw_edPath, x, y, cw - gap * 2 - btnW - gap, 22, TRUE);
    x += cw - gap * 2 - btnW - gap + gap;
    MoveWindow(s_btnBrowse, x, y - 1, btnW, btnH, TRUE);

    y += 22 + gap;
    x = gap;
    MoveWindow(s_btnHeader, x, y, btnW, btnH, TRUE); x += btnW + gap;
    MoveWindow(s_btnList,   x, y, btnW, btnH, TRUE); x += btnW + gap;
    MoveWindow(s_btnEnum,   x, y, btnW, btnH, TRUE); x += btnW + gap;
    MoveWindow(s_btnDir,    x, y, btnW, btnH, TRUE); x += btnW + gap;
    MoveWindow(s_btnSig,    x, y, btnW, btnH, TRUE);

    y += btnH + gap;
    MoveWindow(g_vw_edResult, gap, y, cw - gap * 2, ch - y - gap, TRUE);
}

static void vw_browse(void)
{
    OPENFILENAMEW ofn;
    WCHAR path[MAX_PATH * 2] = {0};
    mfill(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_vw_hwnd;
    ofn.lpstrFilter = L"PE 文件 (*.exe;*.dll;*.sys)\0*.exe;*.dll;*.sys\0所有文件\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = COUNTOF(path);
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (GetOpenFileNameW(&ofn))
        SetWindowTextW(g_vw_edPath, path);
}

static void get_path(WCHAR *out, u32 cap)
{
    GetWindowTextW(g_vw_edPath, out, (int)cap);
}

static void show_result(BUF *b)
{
    WCHAR nul = 0;
    buf_raw(b, &nul, sizeof(WCHAR));
    SetWindowTextW(g_vw_edResult, (const WCHAR *)b->d);
}

static void run_func(void (*fn)(const WCHAR *, BUF *))
{
    WCHAR path[MAX_PATH * 2] = {0};
    BUF b;
    get_path(path, COUNTOF(path));
    if (!path[0]) { SetWindowTextW(g_vw_edResult, L"请先选择或输入 PE 文件路径"); return; }
    if (!buf_init(&b, 4096)) return;
    fn(path, &b);
    show_result(&b);
    hfree(b.d);
}

static void run_sigscan(void)
{
    WCHAR path[MAX_PATH * 2] = {0};
    BUF b;
    DWORD attr;
    get_path(path, COUNTOF(path));
    if (!buf_init(&b, 4096)) return;
    if (!path[0]) {
        peview_scan_signatures(&b);
    } else {
        attr = GetFileAttributesW(path);
        if (attr == INVALID_FILE_ATTRIBUTES) {
            vw_buf_cat_line(&b, L"[错误] 路径不存在");
        } else if (attr & FILE_ATTRIBUTE_DIRECTORY) {
            peview_scan_directory(path, &b);
        } else {
            peview_file_signature(path, &b);
        }
    }
    show_result(&b);
    hfree(b.d);
}

LRESULT CALLBACK peview_wnd_proc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_CREATE:
        g_vw_hwnd = h;
        peview_build_ui(h);
        return 0;
    case WM_SIZE:
        peview_layout(LOWORD(l), HIWORD(l));
        return 0;
    case WM_COMMAND: {
        int id = LOWORD(w);
        switch (id) {
        case ID_VW_BTN_BROWSE:  vw_browse(); return 0;
        case ID_VW_BTN_HEADER:  run_func(peview_dump_header);  return 0;
        case ID_VW_BTN_LISTRES: run_func(peview_list_resources); return 0;
        case ID_VW_BTN_ENUMRES: run_func(peview_enum_resources); return 0;
        case ID_VW_BTN_DIRTREE: run_func(peview_dump_dir_tree); return 0;
        case ID_VW_BTN_SIGSCAN: run_sigscan(); return 0;
        }
        return 0;
    }
    case WM_DROPFILES: {
        WCHAR path[MAX_PATH * 2] = {0};
        HDROP hd = (HDROP)w;
        if (DragQueryFileW(hd, 0, path, COUNTOF(path)))
            SetWindowTextW(g_vw_edPath, path);
        DragFinish(hd);
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}