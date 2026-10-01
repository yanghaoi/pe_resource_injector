#include "peres.h"

#define MAX_COPY_ITEMS 3000
#define MAX_COPY_BYTES (160u * 1024 * 1024)

void rescol_init(RESCOL *c, int cap)
{
    c->it = (RESITEM *)halloc(sizeof(RESITEM) * (u32)cap);
    c->n = 0;
    c->cap = c->it ? cap : 0;
    c->bytes = 0;
    c->skipped = 0;
}

void rescol_free(RESCOL *c)
{
    int i;
    for (i = 0; i < c->n; i++) if (c->it[i].owned) hfree(c->it[i].data);
    hfree(c->it);
    c->it = NULL; c->n = 0; c->cap = 0;
}

void rescol_add(RESCOL *c, BOOL ts, const WCHAR *tstr, u32 tid,
                       BOOL ns, const WCHAR *nstr, u32 nid,
                       u16 lang, const u8 *data, u32 size)
{
    RESITEM *r;
    if (c->n >= c->cap) { c->skipped++; return; }
    if (size > 32u * 1024 * 1024) { c->skipped++; return; }
    if (c->bytes + size > MAX_COPY_BYTES) { c->skipped++; return; }

    r = &c->it[c->n];
    mfill(r, 0, sizeof(*r));
    r->typeStr = ts;
    if (ts) { u32 k = wlen(tstr); if (k > 63) k = 63; mcopy(r->tstr, tstr, k * 2); }
    else r->tid = tid;
    r->nameStr = ns;
    if (ns) { u32 k = wlen(nstr); if (k > 63) k = 63; mcopy(r->nstr, nstr, k * 2); }
    else r->nid = nid;
    r->lang  = lang;
    r->size  = size;
    r->data  = (u8 *)halloc(size ? size : 1);
    if (!r->data) { c->skipped++; return; }
    if (data && size) mcopy(r->data, data, size);
    r->owned = TRUE;
    c->bytes += size;
    c->n++;
}

int type_category(LPWSTR type)
{
    if (IS_INTRESOURCE(type)) {
        u32 id = (u32)(ULONG_PTR)type;
        switch (id) {
        case 16: return 0;                       /* RT_VERSION   */
        case 3:  case 14: return 1;              /* ICON/GROUP_ICON */
        case 24: return 2;                       /* MANIFEST     */
        case 4:  case 5: case 6: case 9:
        case 11: case 17: return 3;              /* MENU/DIALOG/STRING/ACCEL/MSG/DLGINCLUDE */
        default: return 4;                       /* 其它标准类型 */
        }
    }
    return 5;                                    /* 自定义字符串类型 */
}


BOOL CALLBACK cb_lang(HMODULE hm, LPCWSTR type, LPCWSTR name, WORD lang, LONG_PTR lp)
{
    COLCTX *c = (COLCTX *)lp;
    HRSRC hr;
    HGLOBAL hg;
    void *p;
    DWORD sz;
    BOOL ts, ns;
    const WCHAR *tsS, *nsS;
    u32  tid, nid;

    hr = FindResourceW(hm, name, type);
    if (!hr) return TRUE;
    sz = SizeofResource(hm, hr);
    hg = LoadResource(hm, hr);
    if (!hg) return TRUE;
    p = LockResource(hg);
    if (!p || sz == 0) return TRUE;

    ts  = !IS_INTRESOURCE(type);
    tsS = ts ? (const WCHAR *)type : NULL;
    tid = ts ? 0 : (u32)(ULONG_PTR)type;
    ns  = !IS_INTRESOURCE(name);
    nsS = ns ? (const WCHAR *)name : NULL;
    nid = ns ? 0 : (u32)(ULONG_PTR)name;

    rescol_add(c->col, ts, tsS, tid, ns, nsS, nid, lang, (const u8 *)p, sz);
    return TRUE;
}

BOOL CALLBACK cb_name(HMODULE hm, LPCWSTR type, LPWSTR name, LONG_PTR lp)
{
    EnumResourceLanguagesW(hm, type, name, cb_lang, lp);
    return TRUE;
}

BOOL CALLBACK cb_type(HMODULE hm, LPWSTR type, LONG_PTR lp)
{
    COLCTX *c = (COLCTX *)lp;
    int cat = type_category(type);
    if (cat >= 0 && cat < NCOPY && c->want[cat])
        EnumResourceNamesW(hm, type, cb_name, lp);
    return TRUE;
}

/* ===========================================================================
 * 9. 数字签名：查看 / 复制
 * =========================================================================== */
