#ifndef PEVIEW_H
#define PEVIEW_H

#include "peres.h"

#define ID_VW_ED_PATH     5001
#define ID_VW_BTN_BROWSE  5002
#define ID_VW_BTN_HEADER  5003
#define ID_VW_BTN_LISTRES 5004
#define ID_VW_BTN_ENUMRES 5005
#define ID_VW_BTN_DIRTREE 5006
#define ID_VW_BTN_SIGSCAN 5007
#define ID_VW_ED_RESULT   5008

extern HWND  g_vw_hwnd;
extern HWND  g_vw_edPath;
extern HWND  g_vw_edResult;
extern HFONT g_vw_font;

void vw_buf_cat(BUF *b, const WCHAR *s);
void vw_buf_cat_line(BUF *b, const WCHAR *s);

void peview_dump_header(const WCHAR *path, BUF *out);
void peview_list_resources(const WCHAR *path, BUF *out);
void peview_dump_dir_tree(const WCHAR *path, BUF *out);
void peview_enum_resources(const WCHAR *path, BUF *out);
void peview_scan_signatures(BUF *out);
void peview_scan_directory(const WCHAR *dir, BUF *out);
void peview_file_signature(const WCHAR *path, BUF *out);

LRESULT CALLBACK peview_wnd_proc(HWND h, UINT m, WPARAM w, LPARAM l);
void peview_build_ui(HWND hwnd);
void peview_layout(int cw, int ch);

#endif