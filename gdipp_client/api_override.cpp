#include "stdafx.h"
#include "api_override.h"
#include "gdipp_client/gdi_painter.h"
#include "gdipp_client/global.h"
#include "gdipp_client/helper.h"
#include "gdipp_lib/scoped_rw_lock.h"
#include "gdipp_rpc/gdipp_rpc.h"

namespace gdipp
{

std::set<HDC> hdc_in_path;

bool is_valid_dc(HDC hdc)
{
	if (hdc == NULL)
		return false;

	// probably a printer
	if (GetDeviceCaps(hdc, TECHNOLOGY) != DT_RASDISPLAY)
		return false;

	// the DC use another std::map mode, which transform the GDI coordination space
	// we tried to implement MM_ANISOTROPIC, and found that the text looks worse than the native API
	if (GetMapMode(hdc) != MM_TEXT)
		return false;

	/*
	if ExtTextOut is called within an open path bracket, different draw function is required
	because GDI renders the path outline pretty good, and path is rarely used (one example is Google Earth)
	gdipp does not render HDC with path
	*/
	if (hdc_in_path.find(hdc) != hdc_in_path.end())
		return false;

	return true;
}

bool is_target_text(HDC hdc, bool is_glyph_index, LPCWSTR lpString, size_t c, const wchar_t *target_text, int start_index)
{
	/*
	return true if the current string is the target text (string or glyph index array)
	otherwise return false
	always return true if the target is invalid
	*/

	bool is_target;

	if (target_text == NULL)
		return true;

	if (c == 0)
		c = wcslen(lpString);
	c -= start_index;

	const size_t cmp_len = min(c, wcslen(target_text));
	if (cmp_len == 0)
		return true;

	if (is_glyph_index)
	{
		WORD *gi = new WORD[cmp_len];
		GetGlyphIndicesW(hdc, target_text, static_cast<int>(cmp_len), gi, 0);

		is_target = (wmemcmp(lpString + start_index, reinterpret_cast<const wchar_t *>(gi), cmp_len) == 0);

		delete[] gi;
	}
	else
		is_target = (wcsncmp(lpString + start_index, target_text, cmp_len) == 0);

	return is_target;
}
/*
bool fetch_glyph_run (bool is_glyph_index,
	bool is_pdy,
	LPCWSTR lpString,
	UINT c,
	CONST INT *lpDx,
	const dc_context &context,
	FT_Render_Mode render_mode,
	glyph_run &a_glyph_run,
	GLYPH_CACHE_LEVEL &cache_level)
{
	bool b_ret;
	renderer *renderer;

	switch (context.setting_cache->renderer)
	{
	case RENDERER_CLEARTYPE:
		return false;
	case RENDERER_GETGLYPHOUTLINE:
		renderer = new ggo_renderer;
		cache_level = SINGLE_GLYPH;
		break;
	case RENDERER_DIRECTWRITE:
		renderer = new dw_renderer;
		cache_level = GLYPH_RUN;
		break;
	case RENDERER_WIC:
		renderer = new wic_renderer;
		cache_level = NONE;
		break;
	default:
		renderer = new ft_renderer;
		cache_level = SINGLE_GLYPH;
		break;
	}

	b_ret = renderer->begin(&context, render_mode);
	if (b_ret)
	{
		if (cache_level >= GLYPH_RUN)
			b_ret = renderer->fetch_glyph_run(is_glyph_index, is_pdy, lpString, c, lpDx, a_glyph_run);

		renderer->end();
	}

	delete renderer;

	return b_ret;
}
*/

void adjust_glyph_bbox(bool is_pdy, CONST INT *lpDx, int char_extra, gdipp_rpc_bitmap_glyph_run *glyph_run, INT *ctrl_right, INT *black_right)
{
	/*
	adjust the glyph boxes from distance array
	 
	the dx array stores the distance from the left border of the current glyph to the next glyph
	the count of such array should be no less than the count of glyphs
	the last element indicates the distance between the right border of the control box of the glyph run and the left border of the last glyph
	if pdy flag is set, every 2 elements specifies the distance of the glyph in both X and Y axis

	gdipp matches the metrics of the glyph control box against the dx array, then adjusts black box accordingly
	dx array is application specific, therefore the boxes after adjustment are not cached
	*/

	assert(lpDx != NULL || char_extra != 0);

	const BYTE dx_skip = (is_pdy ? 2 : 1);
	*ctrl_right = 0;
	*black_right = 0;

	for (UINT i = 0; i < glyph_run->count; ++i)
	{
		if (i != 0)
		{
			// distance to shift right
			const int distance_shift = *ctrl_right - glyph_run->ctrl_boxes[i].left + char_extra;

			glyph_run->ctrl_boxes[i].left += distance_shift;
			glyph_run->ctrl_boxes[i].right += distance_shift;
			glyph_run->black_boxes[i].left += distance_shift;
			glyph_run->black_boxes[i].right += distance_shift;
		}

		if (lpDx == NULL)
			*ctrl_right = glyph_run->ctrl_boxes[i].right;
		else
			*ctrl_right += lpDx[i * dx_skip];
		*black_right = glyph_run->black_boxes[i].right;
	}

	*black_right = max(*black_right, *ctrl_right);
}

BOOL WINAPI ExtTextOutW_hook(HDC hdc, int x, int y, UINT options, CONST RECT * lprect, LPCWSTR lpString, UINT c, CONST INT *lpDx)
{
	bool b_ret;
	dc_context context;
	gdipp_rpc_bitmap_glyph_run glyph_run = {};

	// all GDI text painting functions calls ExtTextOutW eventually

	// no text to output
	if (lpString == NULL || c == 0)
		goto fail_safe_text_out;

	// rectangle is required but not specified
	// invalid call
	if (((options & ETO_OPAQUE) || (options & ETO_CLIPPED)) && (lprect == NULL))
		goto fail_safe_text_out;

	// completely clipped
	if ((options & ETO_CLIPPED) && IsRectEmpty(lprect))
		goto fail_safe_text_out;

	if (!is_valid_dc(hdc))
		goto fail_safe_text_out;

	const bool is_glyph_index = !!(options & ETO_GLYPH_INDEX);
	const bool is_pdy = !!(options & ETO_PDY);

#ifdef _DEBUG
	bool is_target_spec = false;
	//is_target_spec |= (x > 0);
	//is_target_spec |= (y > 0);
	//is_target_spec |= !!(options & ETO_GLYPH_INDEX));
	//is_target_spec |= !(options & ETO_GLYPH_INDEX);
	//is_target_spec |= (options == 4102);
	//is_target_spec |= (c == 17);
	if (is_target_spec)
		int a = 0;
	else
		;//goto fail_safe_text_out;

	const wchar_t *debug_text;
	debug_text = NULL;
	if (!is_target_text(hdc, is_glyph_index, lpString, c, debug_text, 0))
		goto fail_safe_text_out;
		//int a = 0;
#endif // _DEBUG

	// uncomment this lock to make rendering single-threaded
	//gdipp::lock("debug");

	// initialize the context of the current DC
	if (!context.init(hdc))
		goto fail_safe_text_out;

	// create painter and paint the glyph run
	error_status_t e;
	GDIPP_RPC_SESSION_HANDLE h_session = NULL;
	e = gdipp_rpc_begin_session(h_gdipp_rpc, reinterpret_cast<const byte *>(&context.log_font), sizeof(context.log_font), context.bmp_header.biBitCount, &h_session);
	if (e != 0 || h_session == NULL)
		goto fail_safe_text_out;

	e = gdipp_rpc_make_bitmap_glyph_run(h_gdipp_rpc, h_session, lpString, c, is_glyph_index, &glyph_run);
	gdipp_rpc_end_session(h_gdipp_rpc, &h_session);
	if (e != 0)
		goto fail_safe_text_out;

	const int char_extra = GetTextCharacterExtra(hdc);
	if (char_extra == 0x8000000)
		goto fail_safe_text_out;

	INT ctrl_right, black_right;
	if (lpDx == NULL && char_extra == 0)
	{
		ctrl_right = glyph_run.ctrl_boxes[glyph_run.count - 1].right;
		black_right = glyph_run.black_boxes[glyph_run.count - 1].right;
	}
	else
	{
		adjust_glyph_bbox(!!(options & ETO_PDY), lpDx, char_extra, &glyph_run, &ctrl_right, &black_right);
	}

	painter *painter;
	switch (client_config_instance.painter)
	{
	case client_config::PAINTER_D2D:
		//painter = new gdimm_wic_painter;
		//break;
	default:
		painter = new gdi_painter;
		break;
	}

	b_ret = painter->begin(&context);
	if (b_ret)
	{
		b_ret = painter->paint(x, y, options, lprect, glyph_run, ctrl_right, black_right);
		painter->end();
	}
	delete painter;

	for (UINT i = 0; i < glyph_run.count; ++i)
	{
		if (glyph_run.glyphs[i].buffer != NULL)
			MIDL_user_free(glyph_run.glyphs[i].buffer);
	}
	MIDL_user_free(glyph_run.glyphs);
	MIDL_user_free(glyph_run.ctrl_boxes);
	MIDL_user_free(glyph_run.black_boxes);

	if (b_ret)
		return TRUE;

fail_safe_text_out:
	return ExtTextOutW(hdc, x, y, options, lprect, lpString, c, lpDx);
}

int WINAPI DrawTextExA_hook(HDC hdc, LPSTR lpchText, int cchText, LPRECT lprc, UINT format, LPDRAWTEXTPARAMS lpdtp)
{
	// DrawTextA calls DrawTextExA eventually

	const int i_ret = DrawTextExA(hdc, lpchText, cchText, lprc, format, lpdtp);

	return i_ret;
}

int WINAPI DrawTextExW_hook(HDC hdc, LPWSTR lpchText, int cchText, LPRECT lprc, UINT format, LPDRAWTEXTPARAMS lpdtp)
{
	// DrawTextW calls DrawTextExW eventually

	const int i_ret = DrawTextExW(hdc, lpchText, cchText, lprc, format, lpdtp);

	return i_ret;
}

bool get_text_extent(HDC hdc, LPCWSTR lpString, int count, LPSIZE lpSize, bool is_glyph_index, int nMaxExtent, LPINT lpnFit, LPINT lpnDx)
{
	/*bool b_ret;

	if (lpString == NULL || lpSize == NULL || count == 0)
		return false;

	if (!is_valid_dc(hdc))
		return false;

#ifdef _DEBUG
	if (!is_target_text(hdc, is_glyph_index, lpString, 0, debug_text, 0))
		return false;
#endif // _DEBUG

	dc_context context;
	if (!context.init(hdc))
		return false;

	FT_Render_Mode render_mode;
	if (!get_render_mode(context.setting_cache, context.bmp_header.biBitCount, context.log_font.lfQuality, render_mode))
	{
		if (!get_render_mode(context.setting_cache, GetDeviceCaps(hdc, BITSPIXEL), context.log_font.lfQuality, render_mode))
			return false;
	}

	glyph_run a_glyph_run;
	GLYPH_CACHE_LEVEL cache_level;
	b_ret = fetch_glyph_run(is_glyph_index, false, lpString, count, NULL, context, render_mode, a_glyph_run, cache_level);
	if (!b_ret)
		return false;

	if (cache_level < GLYPH_RUN)
		return false;

	if (lpSize != NULL)
	{
		lpSize->cx = get_glyph_run_width(&a_glyph_run, true);
		lpSize->cy = context.outline_metrics->otmTextMetrics.tmHeight;
	}

	// for GetTextExtentExPoint series
	if (lpnFit != NULL || lpnDx != NULL)
	{
		std::list<RECT>::const_iterator box_iter;
		INT curr_index;
		for (box_iter = a_glyph_run.ctrl_boxes.begin(), curr_index = 0; box_iter != a_glyph_run.ctrl_boxes.end(); ++box_iter, ++curr_index)
		{
			if (lpnFit != NULL && box_iter->right <= nMaxExtent)
				*lpnFit = curr_index + 1;

			if (lpnDx != NULL)
				lpnDx[curr_index] = box_iter->right - a_glyph_run.ctrl_boxes.front().left;
		}
	}
*/
	return true;
}

BOOL APIENTRY GetTextExtentPoint32A_hook(HDC hdc, LPCSTR lpString, int c, LPSIZE lpSize)
{
	std::wstring wide_char_str;
	if (mb_to_wc(lpString, c, wide_char_str))
	{
		if (get_text_extent(hdc, wide_char_str.c_str(), static_cast<int>(wide_char_str.size()), lpSize, false))
			return TRUE;
	}

	return GetTextExtentPoint32A(hdc, lpString, c, lpSize);
}

BOOL APIENTRY GetTextExtentPoint32W_hook(HDC hdc, LPCWSTR lpString, int c, LPSIZE lpSize)
{
	if (get_text_extent(hdc, lpString, c, lpSize, false))
		return TRUE;
	else
		return GetTextExtentPoint32W(hdc, lpString, c, lpSize);
}

BOOL WINAPI GetTextExtentPointI_hook(HDC hdc, LPWORD pgiIn, int cgi, LPSIZE lpSize)
{
	if (get_text_extent(hdc, reinterpret_cast<LPCWSTR>(pgiIn), cgi, lpSize, true))
		return TRUE;
	else
		return GetTextExtentPointI(hdc, pgiIn, cgi, lpSize);
}

BOOL APIENTRY GetTextExtentExPointA_hook(HDC hdc, LPCSTR lpszString, int cchString, int nMaxExtent, LPINT lpnFit, LPINT lpnDx, LPSIZE lpSize)
{
	std::wstring wide_char_str;
	if (mb_to_wc(lpszString, cchString, wide_char_str))
	{
		if (get_text_extent(hdc, wide_char_str.c_str(), static_cast<int>(wide_char_str.size()), lpSize, false, nMaxExtent, lpnFit, lpnDx))
			return TRUE;
	}

	return GetTextExtentExPointA(hdc, lpszString, cchString, nMaxExtent, lpnFit, lpnDx, lpSize);
}

BOOL APIENTRY GetTextExtentExPointW_hook(HDC hdc, LPCWSTR lpszString, int cchString, int nMaxExtent, LPINT lpnFit, LPINT lpnDx, LPSIZE lpSize)
{
	if (get_text_extent(hdc, lpszString, cchString, lpSize, false, nMaxExtent, lpnFit, lpnDx))
		return TRUE;
	else
		return GetTextExtentExPointW(hdc, lpszString, cchString, nMaxExtent, lpnFit, lpnDx, lpSize);
}

BOOL WINAPI GetTextExtentExPointI_hook(HDC hdc, LPWORD lpwszString, int cwchString, int nMaxExtent, LPINT lpnFit, LPINT lpnDx, LPSIZE lpSize)
{
	if (get_text_extent(hdc, reinterpret_cast<LPCWSTR>(lpwszString), cwchString, lpSize, true, nMaxExtent, lpnFit, lpnDx))
		return TRUE;
	else
		return GetTextExtentExPointI(hdc, lpwszString, cwchString, nMaxExtent, lpnFit, lpnDx, lpSize);
}

void adjust_ggo_metrics(const dc_context *context, UINT uChar, UINT fuFormat, LPGLYPHMETRICS lpgm, CONST MAT2 *lpmat2)
{
	/*bool b_ret;

	const MAT2 identity_mat = {{0, 1}, {0, 0}, {0, 0}, {0, 1}};
	if (memcmp(lpmat2, &identity_mat, sizeof(MAT2)) != 0)
	{
		// current not support transformation matrices other than identity
		return;
	}

	ft_renderer ft_renderer;
	FT_OutlineGlyph target_glyph = NULL;

	b_ret = ft_renderer.begin(context, FT_RENDER_MODE_NORMAL);
	if (!b_ret)
		return;

	target_glyph = ft_renderer.get_outline_glyph(uChar, !!(fuFormat & GGO_GLYPH_INDEX));
	ft_renderer.end();

	if (target_glyph == NULL)
		return;

	FT_BBox glyph_bbox;
	FT_Outline_Get_CBox(&target_glyph->outline, &glyph_bbox);

	lpgm->gmBlackBoxX = int_from_26dot6(glyph_bbox.xMax - glyph_bbox.xMin);
	lpgm->gmBlackBoxY = int_from_26dot6(glyph_bbox.yMax - glyph_bbox.yMin);
	lpgm->gmptGlyphOrigin.x = int_from_26dot6(glyph_bbox.xMin);
	lpgm->gmptGlyphOrigin.y = int_from_26dot6(glyph_bbox.yMax);
	lpgm->gmCellIncX = static_cast<short>(int_from_16dot16(target_glyph->root.advance.x));
	lpgm->gmCellIncY = static_cast<short>(int_from_16dot16(target_glyph->root.advance.y));*/
}

DWORD WINAPI GetGlyphOutlineA_hook(HDC hdc, UINT uChar, UINT fuFormat, LPGLYPHMETRICS lpgm, DWORD cjBuffer, LPVOID pvBuffer, CONST MAT2 *lpmat2)
{
	/*const DWORD ggo_ret = GetGlyphOutlineA(hdc, uChar, fuFormat, lpgm, cjBuffer, pvBuffer, lpmat2);
	if (ggo_ret == GDI_ERROR)
		return ggo_ret;

	if (!!(fuFormat & (GGO_BITMAP | GGO_NATIVE)))
	{
		// do not adjust metrics if not only the glyph metrics are requested
		return ggo_ret;
	}

	if (!is_valid_dc(hdc))
		return ggo_ret;

	dc_context context;
	if (!context.init(hdc))
		return ggo_ret;

	if (context.setting_cache->renderer != RENDERER_FREETYPE)
		return ggo_ret;

	adjust_ggo_metrics(&context, uChar, fuFormat, lpgm, lpmat2);

	return ggo_ret;*/
	return 0;
}

DWORD WINAPI GetGlyphOutlineW_hook(HDC hdc, UINT uChar, UINT fuFormat, LPGLYPHMETRICS lpgm, DWORD cjBuffer, LPVOID pvBuffer, CONST MAT2 *lpmat2)
{
	/*const DWORD ggo_ret = GetGlyphOutlineW(hdc, uChar, fuFormat, lpgm, cjBuffer, pvBuffer, lpmat2);
	if (ggo_ret == GDI_ERROR)
		return ggo_ret;

#ifdef _DEBUG
	if (!is_target_text(hdc, !!(fuFormat & GGO_GLYPH_INDEX), reinterpret_cast<wchar_t *>(&uChar), 1, debug_text, 0))
		return ggo_ret;
#endif // _DEBUG

	if (!!(fuFormat & (GGO_BITMAP | GGO_NATIVE)))
		return ggo_ret;

	const MAT2 identity_mat = {{0, 1}, {0, 0}, {0, 0}, {0, 1}};
	if (memcmp(lpmat2, &identity_mat, sizeof(MAT2)) != 0)
	{
		// do not adjust if the transformation matrix is not identical
		return ggo_ret;
	}

	if (!is_valid_dc(hdc))
		return ggo_ret;

	dc_context context;
	if (!context.init(hdc))
		return ggo_ret;

	if (context.setting_cache->renderer != RENDERER_FREETYPE)
		return ggo_ret;

	adjust_ggo_metrics(&context, uChar, fuFormat, lpgm, lpmat2);

	return ggo_ret;*/
	return 0;
}

BOOL WINAPI AbortPath_hook(HDC hdc)
{
	BOOL b_ret = AbortPath(hdc);
	if (b_ret)
		hdc_in_path.erase(hdc);

	return b_ret;
}

BOOL WINAPI BeginPath_hook(HDC hdc)
{
	BOOL b_ret = BeginPath(hdc);
	if (b_ret)
		hdc_in_path.insert(hdc);

	return b_ret;
}

BOOL WINAPI EndPath_hook(HDC hdc)
{
	BOOL b_ret = EndPath(hdc);
	if (b_ret)
		hdc_in_path.erase(hdc);

	return b_ret;
}

HRESULT WINAPI ScriptPlace_hook(
	HDC                  hdc,        // In    Optional (see under caching)
	SCRIPT_CACHE         *psc,       // InOut Cache handle
	const WORD           *pwGlyphs,  // In    Glyph buffer from prior ScriptShape call
	int                  cGlyphs,    // In    Number of glyphs
	const SCRIPT_VISATTR *psva,      // In    Visual glyph attributes
	SCRIPT_ANALYSIS      *psa,       // InOut Result of ScriptItemize (may have fNoGlyphIndex set)
	int                  *piAdvance, // Out   Advance wdiths
	GOFFSET              *pGoffset,  // Out   x,y offset for combining glyph
	ABC                  *pABC)      // Out   Composite ABC for the whole run (Optional)
{
	SIZE text_extent;
	if (!get_text_extent(hdc, reinterpret_cast<LPCWSTR>(pwGlyphs), cGlyphs, (pABC == NULL ? NULL : &text_extent), !psa->fNoGlyphIndex, NULL, NULL, piAdvance))
		return ScriptPlace(hdc, psc, pwGlyphs, cGlyphs, psva, psa, piAdvance, pGoffset, pABC);

	int width_adjust = 0;
	if (piAdvance != NULL)
	{
		for (int i = cGlyphs - 1; i >= 0; i--)
		{
			if (i != 0)
				piAdvance[i] -= piAdvance[i - 1];

			if (psva[i].fZeroWidth)
			{
				width_adjust += -piAdvance[i];
				piAdvance[i] = 0;
			}
		}
	}

	// not support the offset for combining glyphs
	ZeroMemory(pGoffset, sizeof(GOFFSET) * cGlyphs);

	if (pABC != NULL)
	{
		pABC->abcA = 0;
		pABC->abcB = text_extent.cx + width_adjust;
		pABC->abcC = 0;
	}

	return S_OK;
}

#if defined GDIPP_INJECT_SANDBOX && !defined _M_X64

void inject_at_eip(LPPROCESS_INFORMATION lpProcessInformation)
{
	BOOL b_ret;
	DWORD dw_ret;

	// alloc buffer for the injection data
	// the minimum allocation unit is page
	SYSTEM_INFO sys_info;
	GetSystemInfo(&sys_info);
	BYTE *inject_buffer = new BYTE[sys_info.dwPageSize];
	memset(inject_buffer, 0xcc, sys_info.dwPageSize);

	// put gdimm path at the end of the buffer, leave space at the beginning for code
	const DWORD path_offset = sys_info.dwPageSize - MAX_PATH * sizeof(wchar_t);
	dw_ret = GetModuleFileNameW(h_self, reinterpret_cast<wchar_t *>(inject_buffer + path_offset), MAX_PATH);
	assert(dw_ret != 0);

	// get eip of the spawned thread
	CONTEXT ctx = {};
	ctx.ContextFlags = CONTEXT_CONTROL;
	b_ret = GetThreadContext(lpProcessInformation->hThread, &ctx);
	assert(b_ret);

	LPVOID inject_base = VirtualAllocEx(lpProcessInformation->hProcess, NULL, sys_info.dwPageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	assert(inject_base != NULL);

	register BYTE *p = inject_buffer;

#define emit_(t, x)	*reinterpret_cast<t* UNALIGNED>(p) = (t)(x); p += sizeof(t)
#define emit_db(b)	emit_(BYTE, b)
#define emit_dw(w)	emit_(WORD, w)
#define emit_dd(d)	emit_(DWORD, d)

	emit_db(0x50);		// push eax

	emit_db(0x68);		// push gdimm_path
	emit_dd((DWORD) inject_base + path_offset);
	emit_db(0xB8);		// mov eax, LoadLibraryW
	emit_dd(LoadLibraryW);
	emit_dw(0xD0FF);	// call eax

	emit_db(0x58);		// pop eax -> LoadLibraryW has return value

	emit_db(0x68);		// push original_eip
	emit_dd(ctx.Eip);
	emit_db(0xC3);		// retn -> serve as an absolute jmp

	// write injection data to target process space
	b_ret = WriteProcessMemory(lpProcessInformation->hProcess, inject_base, inject_buffer, sys_info.dwPageSize, NULL);
	assert(b_ret);

	delete[] inject_buffer;

	// notify code change
	b_ret = FlushInstructionCache(lpProcessInformation->hProcess, inject_base, sys_info.dwPageSize);
	assert(b_ret);

	// set eip to the entry point of the injection code
	ctx.Eip = reinterpret_cast<DWORD>(inject_base);
	b_ret = SetThreadContext(lpProcessInformation->hThread, &ctx);
	assert(b_ret);
}

BOOL
WINAPI
CreateProcessAsUserW_hook(
	HANDLE hToken,
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation)
{
	// if the token is not restricted, redirect the call to original API
	// service can inject
	if (!IsTokenRestricted(hToken))
	{
		return CreateProcessAsUserW(
			hToken,
			lpApplicationName,
			lpCommandLine,
			lpProcessAttributes,
			lpThreadAttributes,
			bInheritHandles,
			dwCreationFlags,
			lpEnvironment,
			lpCurrentDirectory,
			lpStartupInfo,
			lpProcessInformation);
	}

	// otherwise, the spawned process is restricted, and service cannot inject

	// injection at EIP requires the process be suspended
	// if CREATE_SUSPENDED is not specified in the creation flag, remember to resume process after injection
	bool is_suspended;
	if (dwCreationFlags & CREATE_SUSPENDED)
		is_suspended = true;
	else
	{
		is_suspended = false;
		dwCreationFlags |= CREATE_SUSPENDED;
	}

	if (!CreateProcessAsUserW(
		hToken,
		lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation))
		return FALSE;

	// since the spawned process can be restricted, EasyHook may not work
	// we inject LoadLibrary call at the entry point of the spawned thread
	inject_at_eip(lpProcessInformation);

	if (!is_suspended)
	{
		DWORD dw_ret = ResumeThread(lpProcessInformation->hThread);
		assert(dw_ret != -1);
	}

	return TRUE;
}

#endif // GDIPP_INJECT_SANDBOX && !_M_X64

LPTOP_LEVEL_EXCEPTION_FILTER WINAPI SetUnhandledExceptionFilter_hook(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)
{
	return NULL;
}

}
