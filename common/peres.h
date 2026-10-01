/* =============================================================================
 * peres.h  --  PE 资源 / 元数据 / 签名 克隆注入器  公共头文件
 *
 *   纯 C 语言 + 原生 Win32 API，不链接任何 C 运行时（无 CRT / -nostdlib）
 * =============================================================================
 */

#ifndef PERES_H
#define PERES_H

#define WIN32_LEAN_AND_MEAN 1
#define UNICODE 1
#define _UNICODE 1

#include <windows.h>
#include <winver.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <commdlg.h>
#include <shellapi.h>
#include <objbase.h>

/* ---- 基本类型 ---- */
typedef unsigned char       u8;
typedef unsigned short      u16;
typedef unsigned int        u32;
typedef unsigned long long  u64;

#define COUNTOF(a) (sizeof(a) / sizeof((a)[0]))

/* ---- 动态字节缓冲区 ---- */
typedef struct { u8 *d; u32 len; u32 cap; } BUF;

/* ---- 版本信息字段 ---- */
typedef struct {
    WCHAR company[128];
    WCHAR desc[128];
    WCHAR fileVer[64];
    WCHAR internal[128];
    WCHAR copyright[160];
    WCHAR origName[128];
    WCHAR product[128];
    WCHAR prodVer[64];
    u32   fvMS, fvLS, pvMS, pvLS;
    u16   lang;
    u16   codepage;
    u32   fileOS;
    u32   fileType;
} VINFO;

/* ---- 资源条目 ---- */
typedef struct {
    BOOL  typeStr; WCHAR tstr[64]; u32 tid;
    BOOL  nameStr; WCHAR nstr[64]; u32 nid;
    u16   lang;
    u8   *data;
    u32   size;
    BOOL  owned;
} RESITEM;

/* ---- PE 头解析结果 ---- */
typedef struct {
    u32 e_lfanew;
    u16 machine;
    u16 nSections;
    u16 optMagic;
    u32 timeStamp;
    u32 checkSum;
    u32 sectAlign;
    u32 fileAlign;
    u32 sizeOfImage;
    u32 sizeOfHeaders;
    u16 sizeOfOptHdr;
    u32 rsrcRVA;
    u32 rsrcSize;
    u32 secDirOff;      /* Security Directory：这里是"文件偏移"，不是 RVA */
    u32 secDirSize;
    u16 linkerMaj;
    u16 linkerMin;
    u16 subsystem;
    u32 fileSize;
    u32 ddOff;
} PEHDR;

/* ---- 资源收集器 ---- */
#define NCOPY 7

#define MAX_COPY_ITEMS  3000
#define MAX_COPY_BYTES  (160u * 1024 * 1024)

typedef struct {
    RESITEM *it;
    int      n;
    int      cap;
    u32      bytes;
    int      skipped;
} RESCOL;

typedef struct { RESCOL *col; BOOL want[NCOPY]; } COLCTX;
typedef struct { HANDLE hUpdate; int deleted; } DELCTX;
typedef struct { int n; } CNTCTX;
typedef struct { u16 langs[64]; int n; } LANGLIST;

/* ---- 控件 ID ---- */
#define ID_ED_PATH      1001
#define ID_BTN_BROWSE   1002
#define ID_RB_COPY      1003
#define ID_RB_INPLACE   1004
#define ID_BTN_RAND     1005
#define ID_BTN_READ     1006
#define ID_BTN_CLEAR    1007
#define ID_BTN_GO       1008
#define ID_BTN_OPEN     1009
#define ID_ED_LOG       1010
#define ID_ED_SRC       1011
#define ID_BTN_BSRC     1012
#define ID_LB_SIG       1013
#define ID_BTN_SIGT     1014
#define ID_BTN_SIGS     1015
#define ID_CB_SIGCOPY   1016
#define ID_BTN_CLRLOG   1017
#define ID_ED_BASE      2000
#define ID_CB_BASE      3000
#define ID_CB_COPYBASE  4000

#define NCOPY 7

/* ===========================================================================
 * 全局变量（定义在 ui.c / main.c / version.c / log.c 中）
 * =========================================================================== */

/* ui.c */
extern HWND  g_hwnd;
extern HWND  g_edPath;
extern HWND  g_edSrc;
extern HWND  g_edLog;
extern HWND  g_lbSig;
extern HWND  g_edVal[8];
extern HWND  g_cb[8];
extern HWND  g_cbCopy[NCOPY];
extern HWND  g_cbSigCopy;
extern HWND  g_rbCopy;
extern HWND  g_rbInplace;
extern HFONT g_font;
extern WCHAR g_lastOut[MAX_PATH * 2];
extern const WCHAR *const g_labels[8];
extern const WCHAR *const g_cbLabels[8];
extern const WCHAR *const g_copyLabels[NCOPY];

/* main.c */
extern BOOL  g_gui;
extern BOOL  g_opt[8];
extern BOOL  g_copy[NCOPY];
extern BOOL  g_copySig;
extern BOOL  g_inplace;
extern BOOL  g_onlySig;
extern WCHAR g_cliPath[MAX_PATH * 2];
extern WCHAR g_cliSrc[MAX_PATH * 2];

/* version.c */
extern const WCHAR *const g_companies[];
extern const WCHAR *const g_products[];
extern const WCHAR *const g_descs[];
extern const u16 g_langs[12];

/* ===========================================================================
 * 函数声明
 * =========================================================================== */

/* util.c */
void *mcopy(void *dst, const void *src, u32 n);
void *mfill(void *dst, int c, u32 n);
void *memcpy(void *dst, const void *src, unsigned long long n);
void *memset(void *dst, int c, unsigned long long n);
u32   wlen(const WCHAR *s);
WCHAR *wcopy(WCHAR *d, const WCHAR *s);
WCHAR *wcat(WCHAR *d, const WCHAR *s);
int   wcmpi(const WCHAR *a, const WCHAR *b);
WCHAR *wcat_u32(WCHAR *d, u32 v);
WCHAR *wcat_hex(WCHAR *d, u32 v, int digits);
u32   alignto(u32 v, u32 a);
void  put16(u8 *p, u32 off, u16 v);
void  put32(u8 *p, u32 off, u32 v);
u32   rd16(const u8 *p, u32 o);
u32   rd32(const u8 *p, u32 o);
void *halloc(u32 bytes);
void  hfree(void *p);
void  rnd_seed(void);
u32   rnd32(void);
u32   rnd_range(u32 lo, u32 hi);
void  rnd_bytes(u8 *p, u32 n);
void  rnd_hexstr(WCHAR *out, u32 n);

/* buffer.c */
int   buf_init(BUF *b, u32 cap);
int   buf_need(BUF *b, u32 extra);
void  buf_u16(BUF *b, u16 v);
void  buf_raw(BUF *b, const void *p, u32 n);
void  buf_zero(BUF *b, u32 n);
void  buf_wstr(BUF *b, const WCHAR *s);
void  buf_align4(BUF *b);
void  buf_patch16(BUF *b, u32 off, u16 v);

/* version.c */
u8   *build_version_block(const VINFO *v, u32 *outSize);
void  gen_version_string(WCHAR *out);
void  randomize_vinfo(VINFO *v);

/* pe.c */
BOOL  pe_parse(const u8 *buf, u32 size, PEHDR *h);
BOOL  pe_read_header(const WCHAR *path, PEHDR *h);
BOOL  pe_patch_u32(const WCHAR *path, u32 fileOffset, u32 value);
BOOL  pe_patch_u16(const WCHAR *path, u32 fileOffset, u16 value);
u32   time_now_stamp(void);
BOOL  pe_append_resource_section(const WCHAR *path, u8 *res, u32 resSize, u32 *outRVA);
u8   *pe_read_cert_table(const WCHAR *path, u32 *outSize);
BOOL  pe_write_cert_table(const WCHAR *path, const u8 *cert, u32 certSize);
u8   *make_random_blob(u32 size);
u8   *make_random_bitmap(int w, int h, u32 *outSize);

/* log.c */
void  log_console(const WCHAR *s);
void  log_add(const WCHAR *s);
void  sig_line(const WCHAR *s);
void  sig_clear(void);
void  log_err(const WCHAR *what, DWORD err);

/* rescol.c */
void  rescol_init(RESCOL *c, int cap);
void  rescol_free(RESCOL *c);
void  rescol_add(RESCOL *c, BOOL ts, const WCHAR *tstr, u32 tid,
                 BOOL ns, const WCHAR *nstr, u32 nid, u16 lang,
                 const u8 *data, u32 size);
int   type_category(LPWSTR type);
BOOL CALLBACK cb_type(HMODULE hm, LPWSTR type, LONG_PTR lp);

/* sign.c */
const WCHAR *trust_text(LONG r);
LONG  verify_trust(const WCHAR *path);
void  show_signature(const WCHAR *path, const WCHAR *title);

/* updater.c */
void  do_read_existing(void);
int   cleanup_injected(HANDLE hUp, const WCHAR *dst);
int   count_injected(const WCHAR *path);
BOOL  updater_write_all(const WCHAR *out, const RESITEM *items, int nItems,
                        u32 randItems, int order, u32 *nAdded);
int   verify_items(const WCHAR *path, const RESITEM *items, int nItems);

/* inject.c */
void  do_inject(void);

/* ui.c */
void  set_edit(HWND h, const WCHAR *s);
void  get_edit(HWND h, WCHAR *out, u32 cap);
void  ui_collect(VINFO *v);
void  ui_apply(const VINFO *v);
BOOL  cb_checked(int i);
BOOL  cp_checked(int i);
BOOL  sigcopy_checked(void);
void  do_browse(HWND target);
void  layout(int cw, int ch);
LRESULT CALLBACK wnd_proc(HWND h, UINT m, WPARAM w, LPARAM l);
void  build_ui(void);

/* cli.c */
int   cli_split(WCHAR *cl, WCHAR *av[], int max);
void  cli_apply_list(const WCHAR *list, BOOL *arr, int n, BOOL val);
int   wprefix(const WCHAR *s, const WCHAR *p);
void  cli_help(void);

#endif /* PERES_H */