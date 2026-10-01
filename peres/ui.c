#include "peres.h"

/* GUI 控件标签 */

const WCHAR *const g_labels[8] = {
    L"CompanyName:",     L"FileDescription:",   L"FileVersion:",    L"InternalName:",
    L"LegalCopyright:",  L"OriginalFilename:",  L"ProductName:",    L"ProductVersion:"
};

const WCHAR *const g_cbLabels[8] = {
    L"写入 RT_VERSION 版本信息资源",
    L"附加 RT_RCDATA 随机数据块",
    L"附加 RT_BITMAP 随机位图",
    L"附加自定义类型随机资源",
    L"随机化语言 ID（代码页固定 UTF-16）",
    L"随机化 PE 时间戳 TimeDateStamp",
    L"清除 PE 校验和 CheckSum（置 0）",
    L"清理上次注入的随机资源"
};

const WCHAR *const g_copyLabels[NCOPY] = {
    L"版本信息 (RT_VERSION)",
    L"图标 (RT_ICON / RT_GROUP_ICON)",
    L"清单 (RT_MANIFEST)",
    L"界面资源 (对话框/菜单/字符串/加速键)",
    L"位图 / 光标 / 字体 / RCDATA 等",
    L"自定义（非标准）类型资源",
    L"PE 元数据（时间戳/校验和/链接器版本）"
};

/* GUI 控件句柄与状态 */

HWND  g_hwnd      = NULL;
HWND  g_edPath    = NULL;
HWND  g_edSrc     = NULL;
HWND  g_edLog     = NULL;
HWND  g_lbSig     = NULL;
HWND  g_edVal[8];
HWND  g_cb[8];
HWND  g_cbCopy[NCOPY];
HWND  g_cbSigCopy = NULL;
HWND  g_rbCopy    = NULL;
HWND  g_rbInplace = NULL;
HFONT g_font      = NULL;
WCHAR g_lastOut[MAX_PATH * 2];

/* UI 辅助函数 */

void set_edit(HWND h, const WCHAR *s) { SetWindowTextW(h, s); }

void get_edit(HWND h, WCHAR *out, u32 cap)
{
    DWORD n = (DWORD)SendMessageW(h, WM_GETTEXTLENGTH, 0, 0);
    if (n >= cap) n = cap - 1;
    SendMessageW(h, WM_GETTEXT, (WPARAM)(n + 1), (LPARAM)out);
    out[n] = 0;
}

void ui_collect(VINFO *v)
{
    mfill(v, 0, sizeof(*v));
    get_edit(g_edVal[0], v->company,   128);
    get_edit(g_edVal[1], v->desc,      128);
    get_edit(g_edVal[2], v->fileVer,    64);
    get_edit(g_edVal[3], v->internal,  128);
    get_edit(g_edVal[4], v->copyright, 160);
    get_edit(g_edVal[5], v->origName,  128);
    get_edit(g_edVal[6], v->product,   128);
    get_edit(g_edVal[7], v->prodVer,    64);
}

void ui_apply(const VINFO *v)
{
    set_edit(g_edVal[0], v->company);
    set_edit(g_edVal[1], v->desc);
    set_edit(g_edVal[2], v->fileVer);
    set_edit(g_edVal[3], v->internal);
    set_edit(g_edVal[4], v->copyright);
    set_edit(g_edVal[5], v->origName);
    set_edit(g_edVal[6], v->product);
    set_edit(g_edVal[7], v->prodVer);
}

BOOL cb_checked(int i)
{
    if (!g_gui) return g_opt[i];
    return SendMessageW(g_cb[i], BM_GETCHECK, 0, 0) == BST_CHECKED;
}

BOOL cp_checked(int i)
{
    if (!g_gui) return g_copy[i];
    return SendMessageW(g_cbCopy[i], BM_GETCHECK, 0, 0) == BST_CHECKED;
}

BOOL sigcopy_checked(void)
{
    if (!g_gui) return g_copySig;
    return SendMessageW(g_cbSigCopy, BM_GETCHECK, 0, 0) == BST_CHECKED;
}

void do_browse(HWND target)
{
    OPENFILENAMEW ofn;
    WCHAR path[MAX_PATH * 2];
    static const WCHAR filter[] =
        L"可执行文件 (*.exe;*.dll;*.sys;*.ocx)\0*.exe;*.dll;*.sys;*.ocx;*.scr\0"
        L"所有文件 (*.*)\0*.*\0";

    mfill(&ofn, 0, sizeof(ofn));
    mfill(path, 0, sizeof(path));
    get_edit(target, path, MAX_PATH * 2);

    ofn.lStructSize  = sizeof(ofn);
    ofn.hwndOwner    = g_hwnd;
    ofn.lpstrFilter  = filter;
    ofn.nFilterIndex = 1;
    ofn.lpstrFile    = path;
    ofn.nMaxFile     = MAX_PATH * 2;
    ofn.Flags        = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
    ofn.lpstrDefExt  = L"exe";

    if (GetOpenFileNameW(&ofn)) set_edit(target, path);
}

/* 窗口布局与消息处理 */

void layout(int cw, int ch)
{
    int i;
    int leftW = 480;
    int rightX = 504;
    int rightW = cw - rightX - 12;
    int editW = cw - 110 - 122;

    if (editW < 200) editW = 200;
    if (rightW < 300) rightW = 300;

    MoveWindow(g_edPath, 110, 12, editW, 24, TRUE);
    MoveWindow(GetDlgItem(g_hwnd, ID_BTN_BROWSE), cw - 12 - 110, 11, 110, 26, TRUE);
    MoveWindow(g_edSrc,  110, 44, editW, 24, TRUE);
    MoveWindow(GetDlgItem(g_hwnd, ID_BTN_BSRC),  cw - 12 - 110, 43, 110, 26, TRUE);

    MoveWindow(GetDlgItem(g_hwnd, 9001), 12, 78, cw - 24, 52, TRUE);
    MoveWindow(g_rbCopy,    24,  98, 320, 20, TRUE);
    MoveWindow(g_rbInplace, 356, 98, 320, 20, TRUE);

    MoveWindow(GetDlgItem(g_hwnd, 9004), 12, 138, leftW, 200, TRUE);
    for (i = 0; i < NCOPY; i++)
        MoveWindow(g_cbCopy[i], 24, 158 + i * 24, leftW - 36, 20, TRUE);

    MoveWindow(GetDlgItem(g_hwnd, 9005), 12, 346, leftW, 232, TRUE);
    MoveWindow(g_lbSig, 24, 366, leftW - 36, 140, TRUE);
    MoveWindow(GetDlgItem(g_hwnd, ID_BTN_SIGT), 24,  514, 150, 28, TRUE);
    MoveWindow(GetDlgItem(g_hwnd, ID_BTN_SIGS), 184, 514, 150, 28, TRUE);
    MoveWindow(g_cbSigCopy, 24, 548, leftW - 36, 20, TRUE);

    MoveWindow(GetDlgItem(g_hwnd, 9002), rightX, 138, rightW, 270, TRUE);
    for (i = 0; i < 8; i++) {
        MoveWindow(GetDlgItem(g_hwnd, 9100 + i), rightX + 12, 160 + i * 26, 130, 20, TRUE);
        MoveWindow(g_edVal[i], rightX + 148, 158 + i * 26, rightW - 160, 23, TRUE);
    }
    MoveWindow(GetDlgItem(g_hwnd, ID_BTN_RAND),  rightX + 12,  376, 110, 28, TRUE);
    MoveWindow(GetDlgItem(g_hwnd, ID_BTN_READ),  rightX + 130, 376, 110, 28, TRUE);
    MoveWindow(GetDlgItem(g_hwnd, ID_BTN_CLEAR), rightX + 248, 376, 90,  28, TRUE);

    MoveWindow(GetDlgItem(g_hwnd, 9003), rightX, 416, rightW, 162, TRUE);
    for (i = 0; i < 8; i++) {
        int col = i / 4, row = i % 4;
        MoveWindow(g_cb[i], rightX + 12 + col * 240, 436 + row * 26, 228, 20, TRUE);
    }

    MoveWindow(GetDlgItem(g_hwnd, ID_BTN_GO),     12,  600, 200, 40, TRUE);
    MoveWindow(GetDlgItem(g_hwnd, ID_BTN_OPEN),   224, 600, 160, 40, TRUE);
    MoveWindow(GetDlgItem(g_hwnd, ID_BTN_CLRLOG), 396, 600, 120, 40, TRUE);

    if (ch > 660) MoveWindow(g_edLog, 12, 652, cw - 24, ch - 652 - 12, TRUE);
}

LRESULT CALLBACK wnd_proc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_SIZE:
        layout((int)LOWORD(l), (int)HIWORD(l));
        return 0;

    case WM_GETMINMAXINFO: {
        MINMAXINFO *mm = (MINMAXINFO *)l;
        mm->ptMinTrackSize.x = 1000;
        mm->ptMinTrackSize.y = 720;
        return 0;
    }

    case WM_DROPFILES: {
        HDROP hd = (HDROP)w;
        WCHAR p[MAX_PATH * 2];
        mfill(p, 0, sizeof(p));
        if (DragQueryFileW(hd, 0xFFFFFFFF, NULL, 0) >= 1) {
            DragQueryFileW(hd, 0, p, MAX_PATH * 2);
            set_edit(g_edPath, p);
            do_read_existing();
        }
        DragFinish(hd);
        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(w)) {
        case ID_BTN_BROWSE:
            do_browse(g_edPath);
            do_read_existing();
            return 0;
        case ID_BTN_BSRC:
            do_browse(g_edSrc);
            return 0;
        case ID_BTN_RAND: {
            VINFO t;
            randomize_vinfo(&t);
            ui_apply(&t);
            log_add(L"  已随机生成一组版本信息。");
            return 0;
        }
        case ID_BTN_READ:
            do_read_existing();
            return 0;
        case ID_BTN_CLEAR: {
            VINFO t;
            mfill(&t, 0, sizeof(t));
            ui_apply(&t);
            return 0;
        }
        case ID_BTN_SIGT: {
            WCHAR p[MAX_PATH * 2];
            mfill(p, 0, sizeof(p));
            get_edit(g_edPath, p, MAX_PATH * 2);
            if (p[0]) show_signature(p, L"目标文件签名");
            return 0;
        }
        case ID_BTN_SIGS: {
            WCHAR p[MAX_PATH * 2];
            mfill(p, 0, sizeof(p));
            get_edit(g_edSrc, p, MAX_PATH * 2);
            if (p[0]) show_signature(p, L"源文件签名");
            return 0;
        }
        case ID_BTN_CLRLOG:
            SetWindowTextW(g_edLog, L"");
            sig_clear();
            return 0;
        case ID_BTN_GO:
            do_inject();
            return 0;
        case ID_BTN_OPEN: {
            if (g_lastOut[0]) {
                WCHAR cmd[MAX_PATH * 3];
                WCHAR dir[MAX_PATH * 2];
                u32 n = wlen(g_lastOut), k = n;
                mfill(dir, 0, sizeof(dir));
                while (k > 0 && g_lastOut[k] != L'\\') k--;
                if (k > 0) { mcopy(dir, g_lastOut, k * sizeof(WCHAR)); dir[k] = 0; }
                wsprintfW(cmd, L"/select,\"%s\"", g_lastOut);
                ShellExecuteW(h, L"open", L"explorer.exe", cmd,
                              dir[0] ? dir : NULL, SW_SHOWNORMAL);
            }
            return 0;
        }
        }
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

HWND mk(const WCHAR *cn, const WCHAR *text, DWORD style,
               int x, int y, int w, int h, int id)
{
    DWORD ex = 0;
    if (wcmpi(cn, L"EDIT") == 0 || wcmpi(cn, L"LISTBOX") == 0) ex = WS_EX_CLIENTEDGE;
    {
        HWND r = CreateWindowExW(ex, cn, text, style | WS_CHILD | WS_VISIBLE,
                                 x, y, w, h, g_hwnd, (HMENU)(ULONG_PTR)id,
                                 GetModuleHandleW(NULL), NULL);
        if (r && g_font) SendMessageW(r, WM_SETFONT, (WPARAM)g_font, TRUE);
        return r;
    }
}

void build_ui(void)
{
    int i;

    mk(L"STATIC", L"目标 PE 文件：", 0, 12, 16, 95, 20, -1);
    g_edPath = mk(L"EDIT", L"", ES_AUTOHSCROLL, 110, 12, 700, 24, ID_ED_PATH);
    mk(L"BUTTON", L"浏览...", 0, 0, 0, 110, 26, ID_BTN_BROWSE);

    mk(L"STATIC", L"源 PE（模板）：", 0, 12, 48, 95, 20, -1);
    g_edSrc  = mk(L"EDIT", L"", ES_AUTOHSCROLL, 110, 44, 700, 24, ID_ED_SRC);
    mk(L"BUTTON", L"浏览...", 0, 0, 0, 110, 26, ID_BTN_BSRC);

    mk(L"BUTTON", L"输出方式", BS_GROUPBOX, 12, 78, 900, 52, 9001);
    g_rbCopy    = mk(L"BUTTON", L"另存为副本  <原文件名>.patched.exe（推荐）",
                     BS_AUTORADIOBUTTON | WS_GROUP, 24, 98, 320, 20, ID_RB_COPY);
    g_rbInplace = mk(L"BUTTON", L"就地修改（自动备份 <原文件名>.bak）",
                     BS_AUTORADIOBUTTON, 356, 98, 320, 20, ID_RB_INPLACE);
    SendMessageW(g_rbCopy, BM_SETCHECK, BST_CHECKED, 0);

    mk(L"BUTTON", L"从源 PE 复制（可叠加下面的随机 / 手填）",
       BS_GROUPBOX, 12, 138, 480, 200, 9004);
    for (i = 0; i < NCOPY; i++)
        g_cbCopy[i] = mk(L"BUTTON", g_copyLabels[i], BS_AUTOCHECKBOX,
                         24, 158 + i * 24, 444, 20, ID_CB_COPYBASE + i);

    mk(L"BUTTON", L"数字签名", BS_GROUPBOX, 12, 346, 480, 232, 9005);
    g_lbSig = mk(L"LISTBOX", L"", WS_VSCROLL | LBS_NOINTEGRALHEIGHT,
                 24, 366, 444, 140, ID_LB_SIG);
    mk(L"BUTTON", L"查看目标签名", 0, 24,  514, 150, 28, ID_BTN_SIGT);
    mk(L"BUTTON", L"查看源签名",   0, 184, 514, 150, 28, ID_BTN_SIGS);
    g_cbSigCopy = mk(L"BUTTON", L"把源 PE 的签名复制到输出文件（复制后摘要必然不匹配）",
                     BS_AUTOCHECKBOX, 24, 548, 444, 20, ID_CB_SIGCOPY);

    mk(L"BUTTON", L"版本信息（VS_VERSION_INFO / RT_VERSION）",
       BS_GROUPBOX, 504, 138, 480, 270, 9002);
    for (i = 0; i < 8; i++) {
        mk(L"STATIC", g_labels[i], 0, 516, 160 + i * 26, 130, 20, 9100 + i);
        g_edVal[i] = mk(L"EDIT", L"", ES_AUTOHSCROLL, 652, 158 + i * 26, 320, 23, ID_ED_BASE + i);
    }
    mk(L"BUTTON", L"随机生成", 0, 516, 376, 110, 28, ID_BTN_RAND);
    mk(L"BUTTON", L"读取现有", 0, 634, 376, 110, 28, ID_BTN_READ);
    mk(L"BUTTON", L"清空",     0, 752, 376, 90,  28, ID_BTN_CLEAR);

    mk(L"BUTTON", L"附加随机资源 / PE 元数据", BS_GROUPBOX, 504, 416, 480, 162, 9003);
    for (i = 0; i < 8; i++) {
        int col = i / 4, row = i % 4;
        g_cb[i] = mk(L"BUTTON", g_cbLabels[i], BS_AUTOCHECKBOX,
                     516 + col * 240, 436 + row * 26, 228, 20, ID_CB_BASE + i);
    }
    for (i = 0; i < 8; i++)
        if (g_opt[i]) SendMessageW(g_cb[i], BM_SETCHECK, BST_CHECKED, 0);
    for (i = 0; i < NCOPY; i++)
        if (g_copy[i]) SendMessageW(g_cbCopy[i], BM_SETCHECK, BST_CHECKED, 0);
    if (g_copySig) SendMessageW(g_cbSigCopy, BM_SETCHECK, BST_CHECKED, 0);

    mk(L"BUTTON", L"开始注入", BS_DEFPUSHBUTTON, 12,  600, 200, 40, ID_BTN_GO);
    mk(L"BUTTON", L"打开输出目录", 0, 224, 600, 160, 40, ID_BTN_OPEN);
    mk(L"BUTTON", L"清空日志", 0, 396, 600, 120, 40, ID_BTN_CLRLOG);

    g_edLog = mk(L"EDIT", L"",
                 ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
                 12, 652, 900, 120, ID_ED_LOG);

    DragAcceptFiles(g_hwnd, TRUE);
    log_add(L"PE 资源 / 元数据 / 签名 克隆注入器 已就绪。");
    log_add(L"用法：填好【目标 PE】与【源 PE（模板）】，勾选要复制的类别，再点【开始注入】。");
    log_add(L"说明：改资源必然改变文件哈希并使原签名失效；复制签名只复制数据，无法通过校验。");
}

/* ===========================================================================
 * 13. 命令行
 * =========================================================================== */

