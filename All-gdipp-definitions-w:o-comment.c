// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_client/api_override.cpp:
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

	
	// if ExtTextOut is called within an open path bracket, different draw function is required
	// because GDI renders the path outline pretty good, and path is rarely used (one example is Google Earth)
	// gdipp does not render HDC with path
	
	if (hdc_in_path.find(hdc) != hdc_in_path.end())
		return false;

	return true;
}

bool is_target_text(HDC hdc, bool is_glyph_index, LPCWSTR lpString, size_t c, const wchar_t *target_text, int start_index)
{
	
	// return true if the current string is the target text (string or glyph index array)
	// otherwise return false
	// always return true if the target is invalid
	

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



void adjust_glyph_bbox(bool is_pdy, CONST INT *lpDx, int char_extra, gdipp_rpc_bitmap_glyph_run *glyph_run, INT *ctrl_right, INT *black_right)
{
	
	// adjust the glyph boxes from distance array
	 
	// the dx array stores the distance from the left border of the current glyph to the next glyph
	// the count of such array should be no less than the count of glyphs
	// the last element indicates the distance between the right border of the control box of the glyph run and the left border of the last glyph
	// if pdy flag is set, every 2 elements specifies the distance of the glyph in both X and Y axis

	// gdipp matches the metrics of the glyph control box against the dx array, then adjusts black box accordingly
	// dx array is application specific, therefore the boxes after adjustment are not cached
	

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
	
}

DWORD WINAPI GetGlyphOutlineA_hook(HDC hdc, UINT uChar, UINT fuFormat, LPGLYPHMETRICS lpgm, DWORD cjBuffer, LPVOID pvBuffer, CONST MAT2 *lpmat2)
{
	
	return 0;
}

DWORD WINAPI GetGlyphOutlineW_hook(HDC hdc, UINT uChar, UINT fuFormat, LPGLYPHMETRICS lpgm, DWORD cjBuffer, LPVOID pvBuffer, CONST MAT2 *lpmat2)
{
	
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

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_client/api_override.h:
namespace gdipp
{

#ifndef GDIPP_INJECT_SANDBOX
// define if injection into restricted processes is desired
// defined to inject into Google Chrome render processes
#define GDIPP_INJECT_SANDBOX
#endif

bool is_target_text(HDC hdc, bool is_glyph_index, LPCWSTR lpString, const wchar_t *target_text, int start_index = 0);
bool get_text_extent(HDC hdc, LPCWSTR lpString, int count, LPSIZE lpSize, bool is_glyph_index, int nMaxExtent = 0, LPINT lpnFit = NULL, LPINT lpnDx = NULL);

BOOL WINAPI ExtTextOutW_hook(HDC hdc, int x, int y, UINT options, CONST RECT * lprect, LPCWSTR lpString, UINT c, CONST INT *lpDx);

int WINAPI DrawTextExA_hook(HDC hdc, LPSTR lpchText, int cchText, LPRECT lprc, UINT format, LPDRAWTEXTPARAMS lpdtp);
int WINAPI DrawTextExW_hook(HDC hdc, LPWSTR lpchText, int cchText, LPRECT lprc, UINT format, LPDRAWTEXTPARAMS lpdtp);

BOOL APIENTRY GetTextExtentPoint32A_hook(HDC hdc, LPCSTR lpString, int c, LPSIZE lpSize);
BOOL APIENTRY GetTextExtentPoint32W_hook(HDC hdc, LPCWSTR lpString, int c, LPSIZE lpSize);
BOOL WINAPI GetTextExtentPointI_hook(HDC hdc, LPWORD pgiIn, int cgi, LPSIZE lpSize);

BOOL APIENTRY GetTextExtentExPointA_hook(HDC hdc, LPCSTR lpszString, int cchString, int nMaxExtent, LPINT lpnFit, LPINT lpnDx, LPSIZE lpSize);
BOOL APIENTRY GetTextExtentExPointW_hook(HDC hdc, LPCWSTR lpszString, int cchString, int nMaxExtent, LPINT lpnFit, LPINT lpnDx, LPSIZE lpSize);
BOOL WINAPI GetTextExtentExPointI_hook(HDC hdc, LPWORD lpwszString, int cwchString, int nMaxExtent, LPINT lpnFit, LPINT lpnDx, LPSIZE lpSize);

DWORD WINAPI GetGlyphOutlineA_hook(HDC hdc, UINT uChar, UINT fuFormat, LPGLYPHMETRICS lpgm, DWORD cjBuffer, LPVOID pvBuffer, CONST MAT2 *lpmat2);
DWORD WINAPI GetGlyphOutlineW_hook(HDC hdc, UINT uChar, UINT fuFormat, LPGLYPHMETRICS lpgm, DWORD cjBuffer, LPVOID pvBuffer, CONST MAT2 *lpmat2);

BOOL WINAPI AbortPath_hook(HDC hdc);
BOOL WINAPI BeginPath_hook(HDC hdc);
BOOL WINAPI EndPath_hook(HDC hdc);

HRESULT WINAPI ScriptPlace_hook(
	HDC                  hdc,        // In    Optional (see under caching)
	SCRIPT_CACHE         *psc,       // InOut Cache handle
	const WORD           *pwGlyphs,  // In    Glyph buffer from prior ScriptShape call
	int                  cGlyphs,    // In    Number of glyphs
	const SCRIPT_VISATTR *psva,      // In    Visual glyph attributes
	SCRIPT_ANALYSIS      *psa,       // InOut Result of ScriptItemize (may have fNoGlyphIndex set)
	int                  *piAdvance, // Out   Advance wdiths
	GOFFSET              *pGoffset,  // Out   x,y offset for combining glyph
	ABC                  *pABC);     // Out   Composite ABC for the whole run (Optional)

#if defined GDIPP_INJECT_SANDBOX && !defined _M_X64
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
	LPPROCESS_INFORMATION lpProcessInformation);
#endif // GDIPP_INJECT_SANDBOX && !_M_X64

LPTOP_LEVEL_EXCEPTION_FILTER WINAPI SetUnhandledExceptionFilter_hook(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_client/com_override.cpp:
namespace gdipp
{

HMODULE WINAPI LoadLibraryA_hook(LPCSTR lpLibFileName)
{
	const HMODULE h_new_module = LoadLibraryA(lpLibFileName);

	hook_instance.install_delayed_hook(lpLibFileName, h_new_module);

	return h_new_module;
}

HMODULE WINAPI LoadLibraryW_hook(LPCWSTR lpLibFileName)
{
	const HMODULE h_new_module = LoadLibraryW(lpLibFileName);

	hook_instance.install_delayed_hook(lpLibFileName, h_new_module);

	return h_new_module;
}

HMODULE WINAPI LoadLibraryExA_hook(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
	const HMODULE h_new_module = LoadLibraryExA(lpLibFileName, hFile, dwFlags);

	hook_instance.install_delayed_hook(lpLibFileName, h_new_module);

	return h_new_module;
}

HMODULE WINAPI LoadLibraryExW_hook(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
	const HMODULE h_new_module = LoadLibraryExW(lpLibFileName, hFile, dwFlags);

	hook_instance.install_delayed_hook(lpLibFileName, h_new_module);

	return h_new_module;
}

//////////////////////////////////////////////////////////////////////////

typedef HRESULT (STDMETHODCALLTYPE *CreateDxgiSurfaceRenderTarget_type)(
	ID2D1Factory *,
	IDXGISurface *,
	CONST D2D1_RENDER_TARGET_PROPERTIES &,
	ID2D1RenderTarget **
	);
typedef void (STDMETHODCALLTYPE *DrawGlyphRun_type)(
	ID2D1RenderTarget *,
	D2D1_POINT_2F,
	CONST DWRITE_GLYPH_RUN *,
	ID2D1Brush *,
	DWRITE_MEASURING_MODE
	);

CreateDxgiSurfaceRenderTarget_type CreateDxgiSurfaceRenderTarget_orig = NULL;
DrawGlyphRun_type DrawGlyphRun_orig = NULL;

IFACEMETHODIMP_(void) DrawGlyphRun_hook(
	ID2D1RenderTarget *renderTarget,
	D2D1_POINT_2F baselineOrigin,
	CONST DWRITE_GLYPH_RUN *glyphRun,
	ID2D1Brush *foregroundBrush,
	DWRITE_MEASURING_MODE measuringMode
	)
{

}

IFACEMETHODIMP CreateDxgiSurfaceRenderTarget_hook(
	ID2D1Factory *pIFactory,
	IDXGISurface *dxgiSurface,
	CONST D2D1_RENDER_TARGET_PROPERTIES &renderTargetProperties,
	ID2D1RenderTarget **renderTarget
	)
{
	BOOL b_ret;

	const HRESULT hr = reinterpret_cast<CreateDxgiSurfaceRenderTarget_type>(*CreateDxgiSurfaceRenderTarget_orig)(pIFactory, dxgiSurface, renderTargetProperties, renderTarget);
	if (hr != S_OK)
		return hr;

	if (DrawGlyphRun_orig == NULL)
	{
		const scoped_rw_lock lock_w(scoped_rw_lock::CLIENT_COM_HOOK, false);
		if (DrawGlyphRun_orig == NULL)
		{
			const void **vfptr = *reinterpret_cast<const void ***>(*renderTarget);
			const void **hook_addr = vfptr + 29;

			// temporarily remove protection of the memory region
			DWORD new_protect = PAGE_READWRITE, old_protect;
			b_ret = VirtualProtect(hook_addr, sizeof(void *), new_protect, &old_protect);
			if (!b_ret)
				return hr;

			DrawGlyphRun_orig = reinterpret_cast<DrawGlyphRun_type>(*hook_addr);
			*hook_addr = &DrawGlyphRun_hook;

			VirtualProtect(hook_addr, sizeof(void *), old_protect, &new_protect);
		}
	}

	return hr;
}

HRESULT WINAPI D2D1CreateFactory_hook(D2D1_FACTORY_TYPE factoryType, REFIID riid, CONST D2D1_FACTORY_OPTIONS *pFactoryOptions, void **ppIFactory)
{
	BOOL b_ret;

	const HRESULT hr = D2D1CreateFactory(factoryType, riid, pFactoryOptions, ppIFactory);
	if (hr != S_OK)
		return hr;

	if (CreateDxgiSurfaceRenderTarget_orig == NULL)
	{
		const scoped_rw_lock lock_w(scoped_rw_lock::CLIENT_COM_HOOK, false);
		if (CreateDxgiSurfaceRenderTarget_orig == NULL)
		{
			ID2D1Factory *pIFactory = *reinterpret_cast<ID2D1Factory **>(ppIFactory);
			const void **vfptr = *reinterpret_cast<const void ***>(pIFactory);
			const void **hook_addr = vfptr + 15;

			// temporarily remove protection of the memory region
			DWORD new_protect = PAGE_READWRITE, old_protect;
			b_ret = VirtualProtect(hook_addr, sizeof(void *), new_protect, &old_protect);
			if (!b_ret)
				return hr;

			CreateDxgiSurfaceRenderTarget_orig = reinterpret_cast<CreateDxgiSurfaceRenderTarget_type>(*hook_addr);
			*hook_addr = &CreateDxgiSurfaceRenderTarget_hook;

			VirtualProtect(hook_addr, sizeof(void *), old_protect, &new_protect);
		}
	}

	return hr;
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_client/com_override.h:
namespace gdipp
{

HMODULE WINAPI LoadLibraryA_hook(LPCSTR lpLibFileName);
HMODULE WINAPI LoadLibraryW_hook(LPCWSTR lpLibFileName);
HMODULE WINAPI LoadLibraryExA_hook(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
HMODULE WINAPI LoadLibraryExW_hook(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);

HRESULT WINAPI D2D1CreateFactory_hook(D2D1_FACTORY_TYPE factoryType, REFIID riid, CONST D2D1_FACTORY_OPTIONS *pFactoryOptions, void **ppIFactory);

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_client/font_store.cpp:
namespace gdipp
{

font_store::font_store()
{
	_font_man_tls_index = TlsAlloc();
	assert(_font_man_tls_index != TLS_OUT_OF_INDEXES);
}

font_store::~font_store()
{
	BOOL b_ret;

	for (std::map<long, font_info>::const_iterator iter = _id_to_info.begin(); iter != _id_to_info.upper_bound(-1); ++iter)
	{
		// unregister linked fonts
		//DeleteObject(iter->second.linked_hfont);
	}

	b_ret = TlsFree(_font_man_tls_index);
	assert(b_ret);
}

font_info *font_store::lookup_font(long font_id)
{
	std::map<long, font_info>::iterator iter = _id_to_info.find(font_id);
	if (iter == _id_to_info.end())
		return NULL;

	return &iter->second;
}

long font_store::register_font(HDC font_holder, const wchar_t *font_face)
{

}

BOOL font_store::register_thread_font_man(gdimm_font_man *font_man)
{
}

const gdimm_font_man *font_store::lookup_thread_font_man()
{
	return static_cast<const gdimm_font_man *>(TlsGetValue(_font_man_tls_index));
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_client/gamma.cpp:
namespace gdipp
{

gamma::~gamma()
{
	for (std::map<double, BYTE *>::const_iterator iter = _gamma_ramps.begin(); iter != _gamma_ramps.end(); ++iter)
		delete[] iter->second;
}

const BYTE *gamma::get_ramp(double gamma)
{
	std::map<double, BYTE *>::const_iterator iter = _gamma_ramps.find(gamma);
	if (iter == _gamma_ramps.end())
	{
		// double-check lock
		const scoped_rw_lock lock_w(scoped_rw_lock::CLIENT_GAMMA, false);
		iter = _gamma_ramps.find(gamma);
		if (iter == _gamma_ramps.end())
			init_ramp(gamma);
	}

	return _gamma_ramps[gamma];
}

void gamma::init_ramp(double gamma)
{
	BYTE *new_ramp = new BYTE[256];
	const double gamma_inv = 1 / gamma;

	for (int i = 0; i < 256; ++i)
	{
		double a = pow(i / 255.0, gamma);
		new_ramp[i] = static_cast<BYTE>((pow(i / 255.0, gamma_inv) * 255));
	}

	_gamma_ramps[gamma] = new_ramp;
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_client/gamma.h:
namespace gdipp
{

class gamma
{
public:
	~gamma();

	const BYTE *get_ramp(double gamma);

private:
	void init_ramp(double gamma);

	std::map<double, BYTE *> _gamma_ramps;
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_client/gdi_painter.cpp:
namespace gdipp
{

DWORD tls_index = 0;

bool gdi_painter::begin(const dc_context *context)
{
	if (!painter::begin(context))
		return false;

	// ignore rotated DC
	if (_context->log_font.lfEscapement % 3600 != 0)
		return false;

	if (tls_index == 0)
		tls_index = TlsAlloc();

	_tls = reinterpret_cast<painter_tls *>(TlsGetValue(tls_index));
	if (_tls == NULL)
	{
		_tls = reinterpret_cast<painter_tls *>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(painter_tls)));
		TlsSetValue(tls_index, _tls);

		_tls->hdc_canvas = CreateCompatibleDC(NULL);
		_tls->last_hdc = NULL;
	}

	return true;
}

bool gdi_painter::paint(int x, int y, UINT options, CONST RECT *lprect, gdipp_rpc_bitmap_glyph_run &glyph_run, INT ctrl_right, INT black_right)
{
	BOOL b_ret, paint_success = FALSE;
	_ctrl_right = ctrl_right;
	_black_right = black_right;

	if (((TA_NOUPDATECP | TA_UPDATECP) & _text_alignment) == TA_UPDATECP)
	{
		POINT cp;
		b_ret = GetCurrentPositionEx(_context->hdc, &cp);
		assert(b_ret);

		_cursor.x = cp.x;
		_cursor.y = cp.y;
		_update_cp = true;
	}
	else
	{
		_cursor.x = x;
		_cursor.y = y;
		_update_cp = false;

		if (_tls->last_hdc != NULL)
			_tls->last_hdc = NULL;
	}

	const BYTE *gamma_ramps[3] = {gamma_instance.get_ramp(client_config_instance.gamma.red),
		gamma_instance.get_ramp(client_config_instance.gamma.green),
		gamma_instance.get_ramp(client_config_instance.gamma.blue)};

	_text_rgb_gamma.rgbRed = gamma_ramps[0][GetRValue(_text_color)];
	_text_rgb_gamma.rgbGreen = gamma_ramps[1][GetGValue(_text_color)];
	_text_rgb_gamma.rgbBlue = gamma_ramps[2][GetBValue(_text_color)];

	paint_success = paint_glyph_run(options, lprect, glyph_run);

	// if TA_UPDATECP is set, update current position after text out
	if (_update_cp && paint_success)
	{
		_tls->last_hdc = _context->hdc;

		b_ret = MoveToEx(_context->hdc, _cursor.x, _cursor.y, NULL);
		assert(b_ret);
	}

	return !!paint_success;
}

void gdi_painter::set_mono_mask_bits(const FT_BitmapGlyph glyph,
	const RECT &src_rect,
	BYTE *dest_bits,
	const RECT &dest_rect,
	int dest_pitch,
	bool project_bottom) const
{
	// the source bitmap is 1bpp, 8 pixels per byte, in most-significant order
	// the destination bitmap is 1bpp, 8 pixels per byte, in most-significant order
	// the source bitmap is not blended with the destination bitmap

	int src_row_ptr = src_rect.top * glyph->bitmap.pitch;
	int dest_row_ptr = dest_rect.top * dest_pitch;

	for (int src_curr_row = src_rect.top; src_curr_row < glyph->bitmap.rows; ++src_curr_row, src_row_ptr += glyph->bitmap.pitch)
	{
		int src_curr_column, dest_curr_column;
		for (src_curr_column = src_rect.left, dest_curr_column = dest_rect.left; src_curr_column < src_rect.right; ++src_curr_column, ++dest_curr_column)
		{
			// pointers to the current pixel
			// pointing to the beginning of a row
			const int src_px_ptr = src_row_ptr + src_curr_column / 8;
			const int dest_px_ptr = dest_row_ptr + dest_curr_column / 8;
			const BYTE src_bit_pos = 7 - src_curr_column % 8;
			const BYTE dest_bit_pos = 7 - dest_curr_column % 8;

			const bool is_bit_set = !!(glyph->bitmap.buffer[src_px_ptr] & (1 << src_bit_pos));

			if (is_bit_set)
				dest_bits[dest_px_ptr] |= (1 << dest_bit_pos);
			else
				dest_bits[dest_px_ptr] &= ~(1 << dest_bit_pos);
		}

		if (src_curr_row < src_rect.bottom - 1)
			dest_row_ptr += dest_pitch;
		else if (!project_bottom)
			break;
	}
}

void gdi_painter::set_gray_text_bits(const FT_BitmapGlyph glyph,
	const RECT &src_rect,
	BYTE *dest_bits,
	const RECT &dest_rect,
	int dest_pitch,
	bool project_bottom) const
{
	// the source bitmap is 8bpp with 256 gray levels
	// the destination bitmap is 32 bpp, in order of B, G, R, A channels
	// each row is aligned to DWORD
	// for LCD destination bitmaps, all color channels have the same value

	const WORD src_byte_per_px = 1;
	const WORD dest_byte_per_px = 4;

	int src_row_ptr = src_rect.top * glyph->bitmap.pitch;
	int dest_row_ptr = dest_rect.top * dest_pitch;

	for (int src_curr_row = src_rect.top; src_curr_row < glyph->bitmap.rows; ++src_curr_row, src_row_ptr += glyph->bitmap.pitch)
	{
		// pointers to the current pixel
		// pointing to the beginning of a row
		int src_px_ptr = src_row_ptr + src_rect.left * src_byte_per_px;
		int dest_px_ptr = dest_row_ptr + dest_rect.left * dest_byte_per_px;

		for (int src_curr_column = src_rect.left; src_curr_column < src_rect.right; ++src_curr_column, src_px_ptr += src_byte_per_px, dest_px_ptr += dest_byte_per_px)
		{
			const BYTE src_alpha = glyph->bitmap.buffer[src_px_ptr];
			const RGBQUAD src_color = {division_by_255(_text_rgb_gamma.rgbBlue, src_alpha),
				division_by_255(_text_rgb_gamma.rgbGreen, src_alpha),
				division_by_255(_text_rgb_gamma.rgbRed, src_alpha),
				src_alpha};

			// this approach is faster than setting each byte separately
			*reinterpret_cast<DWORD *>(dest_bits + dest_px_ptr) = *reinterpret_cast<const DWORD *>(&src_color);
		}

		if (src_curr_row < src_rect.bottom - 1)
			dest_row_ptr += dest_pitch;
		else if (!project_bottom)
			break;
	}
}

void gdi_painter::set_lcd_text_bits(const gdipp_rpc_bitmap_glyph &glyph,
	const RECT &src_rect,
	BYTE *dest_bits,
	const RECT &dest_rect,
	int dest_pitch,
	bool project_bottom,
	BYTE alpha) const
{
	// the source bitmap is 24bpp, in order of R, G, B channels
	// the destination bitmaps is 32bpp, in order of B, G, R, A channels
	// each row is aligned to DWORD

	const WORD src_byte_per_px = 3;
	const WORD dest_byte_per_px = 4;

	int src_row_ptr = src_rect.top * glyph.pitch;
	int dest_row_ptr = dest_rect.top * dest_pitch;

	for (int src_curr_row = src_rect.top; src_curr_row < glyph.rows; ++src_curr_row, src_row_ptr += glyph.pitch)
	{
		// pointers to the current pixel
		// pointing to the beginning of a row
		int src_px_ptr = src_row_ptr + src_rect.left * src_byte_per_px;
		int dest_px_ptr = dest_row_ptr + dest_rect.left * dest_byte_per_px;

		for (int src_curr_column = src_rect.left; src_curr_column < src_rect.right; ++src_curr_column, src_px_ptr += src_byte_per_px, dest_px_ptr += dest_byte_per_px)
		{
			// color components of the source bitmap
			RGBQUAD src_color = _text_rgb_gamma;

			// alpha components of the source bitmap
			// apply pixel geometry
			RGBQUAD src_alpha = {};
			if (client_config_instance.pixel_geometry == client_config::PIXEL_GEOMETRY_BGR)
			{
				src_alpha.rgbRed = glyph.buffer[src_px_ptr+2];
				src_alpha.rgbGreen = glyph.buffer[src_px_ptr+1];
				src_alpha.rgbBlue = glyph.buffer[src_px_ptr];
			}
			else
			{
				src_alpha.rgbRed = glyph.buffer[src_px_ptr];
				src_alpha.rgbGreen = glyph.buffer[src_px_ptr+1];
				src_alpha.rgbBlue = glyph.buffer[src_px_ptr+2];
			}

			// apply shadow alpha
			if (alpha != 255)
			{
				src_color.rgbRed = division_by_255(src_color.rgbRed, alpha);
				src_color.rgbGreen = division_by_255(src_color.rgbGreen, alpha);
				src_color.rgbBlue = division_by_255(src_color.rgbBlue, alpha);
				src_alpha.rgbRed = division_by_255(src_alpha.rgbRed, alpha);
				src_alpha.rgbGreen = division_by_255(src_alpha.rgbGreen, alpha);
				src_alpha.rgbBlue = division_by_255(src_alpha.rgbBlue, alpha);
			}

			// alpha blending
			RGBQUAD dest_color = {dest_bits[dest_px_ptr] + division_by_255(src_color.rgbBlue - dest_bits[dest_px_ptr], src_alpha.rgbBlue),
				dest_bits[dest_px_ptr+1] + division_by_255(src_color.rgbGreen - dest_bits[dest_px_ptr+1], src_alpha.rgbGreen),
				dest_bits[dest_px_ptr+2] + division_by_255(src_color.rgbRed - dest_bits[dest_px_ptr+2], src_alpha.rgbRed),
				0};

			
			// GDI's behavior:
			// if the destination pixel is modified, reset its alpha value to 0
			// otherwise, leave the alpha value untouched
			
			if (*reinterpret_cast<DWORD *>(&src_alpha) == 0)
				dest_color.rgbReserved = dest_bits[dest_px_ptr+3];

			*reinterpret_cast<DWORD *>(dest_bits + dest_px_ptr) = *reinterpret_cast<DWORD *>(&dest_color);
		}

		if (src_curr_row < src_rect.bottom - 1)
			dest_row_ptr += dest_pitch;
		else if (!project_bottom)
			break;
	}
}

BOOL gdi_painter::paint_mono(UINT options, CONST RECT *lprect, const gdipp_rpc_bitmap_glyph_run &glyph_run, const glyph_run_metrics &grm) const
{
	BOOL b_ret, paint_success;

	// the data source is FreeType bitmap with black/white mask
	// create GDI mask bitmap and use MaskBlt to complete text painting

	
	// the flow direction of the original bitmap is unrecoverable
	// it seems BitBlt would automatically convert the direction of its source bitmap if necessary
	// FreeType returns top-down bitmap, so we use top-down to simplify algorithm
	// note that the semantic of the direction from GDI is opposite to FreeType
	

	
	// Windows DIB and FreeType Bitmap have different ways to indicate bitmap direction
	// biHeight > 0 means the Windows DIB is bottom-up
	// biHeight < 0 means the Windows DIB is top-down
	// pitch > 0 means the FreeType bitmap is down flow
	// pitch > 0 means the FreeType bitmap is up flow
	

	const SIZE bbox_visible_size = {grm.visible_rect.right - grm.visible_rect.left, grm.visible_rect.bottom - grm.visible_rect.top};
	const BITMAPINFO bmp_info = {sizeof(BITMAPINFOHEADER), bbox_visible_size.cx, -bbox_visible_size.cy, 1, 1, BI_RGB};

	BYTE *mask_bits;
	const HBITMAP mask_bitmap = CreateDIBSection(_context->hdc, &bmp_info, DIB_RGB_COLORS, reinterpret_cast<VOID **>(&mask_bits), NULL, 0);
	assert(mask_bitmap != NULL);

	const int bk_mode = GetBkMode(_context->hdc);
	if (bk_mode == OPAQUE)
		paint_background(_context->hdc, &grm.visible_rect, _bg_color);

	for (UINT i = 0; i < glyph_run.count; ++i)
	{
		FT_BitmapGlyph bmp_glyph = reinterpret_cast<FT_BitmapGlyph>(&glyph_run.glyphs[i]);
		if (bmp_glyph == NULL)
			continue;

		assert(bmp_glyph->bitmap.pitch >= 0);

		// the bounding box of the current glyph in the DC bitmap
		RECT glyph_rect;
		glyph_rect.left = grm.baseline.x + glyph_run.black_boxes[i].left;
		glyph_rect.top = grm.baseline.y - bmp_glyph->top;
		glyph_rect.right = grm.baseline.x + glyph_run.black_boxes[i].right;
		glyph_rect.bottom = glyph_rect.top + bmp_glyph->bitmap.rows;

		// only paint the visible part of the source to the new bitmap
		RECT glyph_rect_in_bbox;
		const BOOL is_glyph_in_bbox = IntersectRect(&glyph_rect_in_bbox, &glyph_rect, &grm.visible_rect);
		if (is_glyph_in_bbox)
		{
			const RECT src_rect = {glyph_rect_in_bbox.left - glyph_rect.left,
				glyph_rect_in_bbox.top - glyph_rect.top,
				glyph_rect_in_bbox.right - glyph_rect.left,
				glyph_rect_in_bbox.bottom - glyph_rect.top};
			const RECT dest_rect = {glyph_rect_in_bbox.left - grm.visible_rect.left,
				glyph_rect_in_bbox.top - grm.visible_rect.top,
				glyph_rect_in_bbox.right - grm.visible_rect.left,
				glyph_rect_in_bbox.bottom - grm.visible_rect.top};
			const int dest_pitch = get_bmp_pitch(bbox_visible_size.cx, 1);

			set_mono_mask_bits(bmp_glyph, src_rect, mask_bits, dest_rect, dest_pitch, bbox_visible_size.cy == grm.extent.cy);
		}
	}

	// obviously shadow for monochrome bitmap is not possible

	HBRUSH text_brush = CreateSolidBrush(_text_color);
	assert(text_brush != NULL);
	const HBRUSH prev_brush = static_cast<const HBRUSH>(SelectObject(_context->hdc, text_brush));

	// foreground ROP: source brush
	// background ROP: destination color
	paint_success = MaskBlt(_context->hdc,
		grm.visible_rect.left,
		grm.visible_rect.top,
		bbox_visible_size.cx,
		bbox_visible_size.cy,
		_context->hdc,
		0,
		0,
		mask_bitmap,
		0,
		0,
		MAKEROP4(PATCOPY, 0x00AA0029));

	text_brush = static_cast<HBRUSH>(SelectObject(_context->hdc, prev_brush));
	b_ret = DeleteObject(text_brush);
	assert(b_ret);
	b_ret = DeleteObject(mask_bitmap);
	assert(b_ret);

	return paint_success;
}

BOOL gdi_painter::paint_gray(UINT options, CONST RECT *lprect, const gdipp_rpc_bitmap_glyph_run &glyph_run, const glyph_run_metrics &grm) const
{
	// the data source is FreeType bitmap with 256 gray levels
	// create GDI alpha bitmap and use AlphaBlend() to paint both solid and shadow text

	BOOL b_ret, paint_success;

	const SIZE bbox_visible_size = {grm.visible_rect.right - grm.visible_rect.left, grm.visible_rect.bottom - grm.visible_rect.top};

	const BITMAPINFO bmp_info = {sizeof(BITMAPINFOHEADER), bbox_visible_size.cx, -bbox_visible_size.cy, 1, 32, BI_RGB};
	const HBITMAP text_bitmap = CreateDIBSection(_context->hdc, &bmp_info, DIB_RGB_COLORS, reinterpret_cast<VOID **>(&_tls->text_bits), NULL, 0);
	assert(text_bitmap != NULL);
	const HBITMAP prev_bitmap = reinterpret_cast<const HBITMAP>(SelectObject(_tls->hdc_canvas, text_bitmap));
	b_ret = DeleteObject(prev_bitmap);
	assert(b_ret);

	const int bk_mode = GetBkMode(_context->hdc);
	if (bk_mode == OPAQUE)
		paint_background(_context->hdc, &grm.visible_rect, _bg_color);

	const int dest_pitch = get_bmp_pitch(bbox_visible_size.cx, 32);

	for (UINT i = 0; i < glyph_run.count; ++i)
	{
		FT_BitmapGlyph bmp_glyph = reinterpret_cast<FT_BitmapGlyph>(&glyph_run.glyphs[i]);
		if (bmp_glyph == NULL)
			continue;

		assert(bmp_glyph->bitmap.pitch >= 0);

		RECT glyph_rect;
		glyph_rect.left = grm.baseline.x + glyph_run.black_boxes[i].left;
		glyph_rect.top = grm.baseline.y - bmp_glyph->top;
		glyph_rect.right = grm.baseline.x + glyph_run.black_boxes[i].right;
		glyph_rect.bottom = glyph_rect.top + bmp_glyph->bitmap.rows;

		RECT glyph_rect_in_bbox;
		const BOOL is_glyph_in_bbox = IntersectRect(&glyph_rect_in_bbox, &glyph_rect, &grm.visible_rect);
		if (is_glyph_in_bbox)
		{
			const RECT src_rect = {glyph_rect_in_bbox.left - glyph_rect.left,
				glyph_rect_in_bbox.top - glyph_rect.top,
				glyph_rect_in_bbox.right - glyph_rect.left,
				glyph_rect_in_bbox.bottom - glyph_rect.top};
			const RECT dest_rect = {glyph_rect_in_bbox.left - grm.visible_rect.left,
				glyph_rect_in_bbox.top - grm.visible_rect.top,
				glyph_rect_in_bbox.right - grm.visible_rect.left,
				glyph_rect_in_bbox.bottom - grm.visible_rect.top};

			set_gray_text_bits(bmp_glyph, src_rect, _tls->text_bits, dest_rect, dest_pitch, bbox_visible_size.cy == grm.extent.cy);
		}
	}

	BLENDFUNCTION bf = {AC_SRC_OVER, 0, 255, AC_SRC_ALPHA};

	// AlphaBlend converts the source bitmap pixel format to match destination bitmap pixel format
	if (client_config_instance.shadow.alpha != 0)
	{
		bf.SourceConstantAlpha = client_config_instance.shadow.alpha;
		b_ret = AlphaBlend(_context->hdc,
			grm.visible_rect.left + client_config_instance.shadow.offset_x,
			grm.visible_rect.top + client_config_instance.shadow.offset_y,
			bbox_visible_size.cx,
			bbox_visible_size.cy,
			_tls->hdc_canvas,
			0,
			0,
			bbox_visible_size.cx,
			bbox_visible_size.cy,
			bf);
		if (!b_ret)
			return false;
	}

	bf.SourceConstantAlpha = 255;
	paint_success = AlphaBlend(_context->hdc,
		grm.visible_rect.left,
		grm.visible_rect.top,
		bbox_visible_size.cx,
		bbox_visible_size.cy,
		_tls->hdc_canvas,
		0,
		0,
		bbox_visible_size.cx,
		bbox_visible_size.cy,
		bf);

	return paint_success;
}

BOOL gdi_painter::paint_lcd(UINT options, CONST RECT *lprect, const gdipp_rpc_bitmap_glyph_run &glyph_run, const glyph_run_metrics &grm) const
{
	// the data source is FreeType bitmap with 256 gray levels in R, G, B channels
	// create GDI bitmap and optionally copy from DC, then use BitBlt() to paint both solid and shadow text

	BOOL b_ret, paint_success = TRUE;

	const SIZE bbox_visible_size = {grm.visible_rect.right - grm.visible_rect.left, grm.visible_rect.bottom - grm.visible_rect.top};

	
	// optimization for UPDATECP when background mode is TRANSPARENT
	// for the first time UPDATECP is seen, prepare the background in the canvas for the entire line instead of just the text
	// for the second and upward times UPDATECP is seen, directly use the background data in canvas, thus save the costly BitBlt
	// canvas is stored in TLS, and data in it is inherited across painting sessions
	// when background mode is OPAQUE, do NOT use this optimization
	

	LONG canvas_width = bbox_visible_size.cx;
	LONG canvas_offset = grm.visible_rect.left;
	bool new_bitmap = true;

	const int bk_mode = GetBkMode(_context->hdc);
	if (bk_mode == TRANSPARENT)
	{
		if (_update_cp)
		{
			canvas_width = _context->bmp_header.biWidth;
			canvas_offset = 0;
			new_bitmap = (_tls->last_hdc != _context->hdc);
		}
	}
	else if (bk_mode != OPAQUE)
	{
		// unknown background mode
		return FALSE;
	}

	if (new_bitmap)
	{
		const BITMAPINFO bmp_info = {sizeof(BITMAPINFOHEADER), canvas_width, -bbox_visible_size.cy, 1, 32, BI_RGB};
		const HBITMAP text_bitmap = CreateDIBSection(_context->hdc, &bmp_info, DIB_RGB_COLORS, reinterpret_cast<VOID **>(&_tls->text_bits), NULL, 0);
		assert(text_bitmap != NULL);
		const HBITMAP prev_bitmap = reinterpret_cast<const HBITMAP>(SelectObject(_tls->hdc_canvas, text_bitmap));
		b_ret = DeleteObject(prev_bitmap);
		assert(b_ret);
	}

	if (bk_mode == OPAQUE)
	{
		const RECT bk_rect = {0, 0, canvas_width, bbox_visible_size.cy};
		paint_success = paint_background(_tls->hdc_canvas, &bk_rect, _bg_color);
	}
	else if (new_bitmap)
	{
		assert(bk_mode == TRANSPARENT);

		// BitBlt overwrites rather than overlays, therefore retrieve the original DC bitmap if transparent
		// "If a rotation or shear transformation is in effect in the source device context, BitBlt returns an error"
		paint_success = BitBlt(_tls->hdc_canvas,
			0,
			0,
			canvas_width,
			bbox_visible_size.cy,
			_context->hdc,
			canvas_offset,
			grm.visible_rect.top,
			SRCCOPY);
	}

	if (paint_success)
	{
		const int dest_pitch = get_bmp_pitch(canvas_width, 32);

		for (UINT i = 0; i < glyph_run.count; ++i)
		{
			const gdipp_rpc_bitmap_glyph bmp_glyph = glyph_run.glyphs[i];
			if (bmp_glyph.buffer == NULL)
				continue;
			
			assert(bmp_glyph.pitch >= 0);

			// the rect of the current glyph in the source bitmap
			RECT solid_glyph_rect;
			solid_glyph_rect.left = grm.baseline.x + glyph_run.black_boxes[i].left;
			solid_glyph_rect.top = grm.baseline.y - bmp_glyph.top;
			solid_glyph_rect.right = grm.baseline.x + glyph_run.black_boxes[i].right;
			solid_glyph_rect.bottom = solid_glyph_rect.top + bmp_glyph.rows;

			RECT solid_rect_in_bbox;
			if (IntersectRect(&solid_rect_in_bbox, &solid_glyph_rect, &grm.visible_rect))
			{
				if (client_config_instance.shadow.alpha > 0)
				{
					const RECT shadow_glyph_rect = {solid_glyph_rect.left + client_config_instance.shadow.offset_x,
						solid_glyph_rect.top + client_config_instance.shadow.offset_y,
						solid_glyph_rect.right + client_config_instance.shadow.offset_x,
						solid_glyph_rect.bottom + client_config_instance.shadow.offset_y};

					RECT shadow_rect_in_bbox;
					if (IntersectRect(&shadow_rect_in_bbox, &shadow_glyph_rect, &grm.visible_rect))
					{
						const RECT shadow_src_rect = {shadow_rect_in_bbox.left - shadow_glyph_rect.left,
							shadow_rect_in_bbox.top - shadow_glyph_rect.top,
							shadow_rect_in_bbox.right - shadow_glyph_rect.left,
							shadow_rect_in_bbox.bottom - shadow_glyph_rect.top};
						const RECT shadow_dest_rect = {shadow_rect_in_bbox.left - grm.visible_rect.left,
							shadow_rect_in_bbox.top - grm.visible_rect.top,
							shadow_rect_in_bbox.right - grm.visible_rect.left,
							shadow_rect_in_bbox.bottom - grm.visible_rect.top};

						set_lcd_text_bits(bmp_glyph, shadow_src_rect, _tls->text_bits, shadow_dest_rect, dest_pitch, false, client_config_instance.shadow.alpha);
					}
				}

				// the visible rect part of the current glyph in the source bitmap
				const RECT solid_src_rect = {solid_rect_in_bbox.left - solid_glyph_rect.left,
					solid_rect_in_bbox.top - solid_glyph_rect.top,
					solid_rect_in_bbox.right - solid_glyph_rect.left,
					solid_rect_in_bbox.bottom - solid_glyph_rect.top};

				// the corresponding rect in the destination bitmap
				const RECT solid_dest_rect = {solid_rect_in_bbox.left - canvas_offset,
					solid_rect_in_bbox.top - grm.visible_rect.top,
					solid_rect_in_bbox.right - canvas_offset,
					solid_rect_in_bbox.bottom - grm.visible_rect.top};

				set_lcd_text_bits(bmp_glyph, solid_src_rect, _tls->text_bits, solid_dest_rect, dest_pitch, bbox_visible_size.cy == grm.extent.cy, 255);
			}
		}

		paint_success = BitBlt(_context->hdc,
			grm.visible_rect.left,
			grm.visible_rect.top,
			bbox_visible_size.cx,
			bbox_visible_size.cy,
			_tls->hdc_canvas,
			grm.visible_rect.left - canvas_offset,
			0,
			SRCCOPY);
	}

	return paint_success;
}

BOOL gdi_painter::paint_glyph_run(UINT options, CONST RECT *lprect, const gdipp_rpc_bitmap_glyph_run &glyph_run)
{
	
	// both ETO_OPAQUE and OPAQUE background mode need background filled
	// for ETO_OPAQUE, direct FillRect to the physical DC
	// for OPAQUE background mode, draw the background on canvas DC (it might be clipped eventually)
	
	if (options & ETO_OPAQUE)
		paint_background(_context->hdc, lprect, _bg_color);

	glyph_run_metrics grm;
	// actual bounding box occupied by the glyphs
	grm.extent.cx = get_glyph_run_width(glyph_run, _ctrl_right, _black_right, false);

	// nothing to paint
	if (grm.extent.cx == 0)
		return FALSE;

	grm.extent.cy = _context->outline_metrics->otmTextMetrics.tmHeight;
	const LONG bbox_ascent = _context->outline_metrics->otmTextMetrics.tmAscent;
	const LONG bbox_descent = _context->outline_metrics->otmTextMetrics.tmDescent;

	// adjusted baseline where the bitmap will be finally drawn before applying clipping
	grm.baseline = get_baseline(_text_alignment,
		_cursor.x,
		_cursor.y,
		grm.extent.cx,
		bbox_ascent,
		bbox_descent);

	grm.visible_rect.left = grm.baseline.x + glyph_run.black_boxes[0].left;
	grm.visible_rect.top = grm.baseline.y - bbox_ascent;
	grm.visible_rect.right = grm.visible_rect.left + grm.extent.cx;
	grm.visible_rect.bottom = grm.visible_rect.top + grm.extent.cy;

	// advance cursor by the width of the control box of the glyph run
	_cursor.x += _ctrl_right - glyph_run.ctrl_boxes[0].left;

	// apply clipping
	if (options & ETO_CLIPPED && !IntersectRect(&grm.visible_rect, &grm.visible_rect, lprect))
		return FALSE;

	switch (glyph_run.render_mode)
	{
		case FT_RENDER_MODE_LCD:
			return paint_lcd(options, lprect, glyph_run, grm);
		case FT_RENDER_MODE_NORMAL:
		case FT_RENDER_MODE_LIGHT:
			return paint_gray(options, lprect, glyph_run, grm);
		case FT_RENDER_MODE_MONO:
			return paint_mono(options, lprect, glyph_run, grm);
		default:
			return FALSE;
	}
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_client/gdi_painter.h:
namespace gdipp
{

struct painter_tls
{
	HDC hdc_canvas;
	HDC last_hdc;
	BYTE *text_bits;
};

class gdi_painter : public painter
{
public:
	bool begin(const dc_context *context);
	bool paint(int x, int y, UINT options, CONST RECT *lprect, gdipp_rpc_bitmap_glyph_run &glyph_run, INT ctrl_right, INT black_right);

private:
	struct glyph_run_metrics
	{
		
		// extent and baseline determine the bounding box before clipping
		// visible rectangle is the visible part after optional clipping
		// the area of visible rectangle is always less or equal to the extent
		
		SIZE extent;
		POINT baseline;
		RECT visible_rect;
	};

	void set_mono_mask_bits(const FT_BitmapGlyph glyph,
		const RECT &src_rect,
		BYTE *dest_bits,
		const RECT &dest_rect,
		int dest_pitch,
		bool project_bottom) const;
	void set_gray_text_bits(const FT_BitmapGlyph glyph,
		const RECT &src_rect,
		BYTE *dest_bits,
		const RECT &dest_rect,
		int dest_pitch,
		bool project_bottom) const;
	void set_lcd_text_bits(const gdipp_rpc_bitmap_glyph &glyph,
		const RECT &src_rect,
		BYTE *dest_bits,
		const RECT &dest_rect,
		int dest_pitch,
		bool project_bottom,
		BYTE alpha) const;

	BOOL paint_mono(UINT options, CONST RECT *lprect, const gdipp_rpc_bitmap_glyph_run &glyph_run, const glyph_run_metrics &grm) const;
	BOOL paint_gray(UINT options, CONST RECT *lprect, const gdipp_rpc_bitmap_glyph_run &glyph_run, const glyph_run_metrics &grm) const;
	BOOL paint_lcd(UINT options, CONST RECT *lprect, const gdipp_rpc_bitmap_glyph_run &glyph_run, const glyph_run_metrics &grm) const;
	BOOL paint_glyph_run(UINT options, CONST RECT *lprect, const gdipp_rpc_bitmap_glyph_run &glyph_run);

	painter_tls *_tls;
	INT _black_right;
	INT _ctrl_right;
	RGBQUAD _text_rgb_gamma;
	bool _update_cp;
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_client/gdipp_client.cpp:
namespace gdipp
{

HANDLE process_heap = GetProcessHeap();
	
bool init_rpc_client()
{
	if (process_heap == NULL)
		return false;

	RPC_WSTR binding_str;
	RPC_STATUS rpc_status;

	rpc_status = RpcStringBindingCompose(NULL, reinterpret_cast<RPC_WSTR>(L"ncalrpc"), NULL, reinterpret_cast<RPC_WSTR>(L"gdipp"), NULL, &binding_str);
	if (rpc_status != RPC_S_OK)
		return false;

	rpc_status = RpcBindingFromStringBinding(binding_str, &h_gdipp_rpc);
	if (rpc_status != RPC_S_OK)
		return false;

	rpc_status = RpcStringFree(&binding_str);
	if (rpc_status != RPC_S_OK)
		return false;

	return true;
}

}

void __RPC_FAR *__RPC_USER MIDL_user_allocate(size_t size)
{
	return HeapAlloc(gdipp::process_heap, HEAP_GENERATE_EXCEPTIONS, size);
}

void __RPC_USER MIDL_user_free(void __RPC_FAR *ptr)
{
	HeapFree(gdipp::process_heap, 0, ptr);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	BOOL b_ret;

	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
		{
			gdipp::h_self = hModule;

			wchar_t this_proc_name[MAX_PATH];
			DWORD dw_ret = GetModuleBaseNameW(GetCurrentProcess(), NULL, this_proc_name, MAX_PATH);
			assert(dw_ret != 0);

			if (gdipp::exclude_config::is_process_excluded(gdipp::config_instance, this_proc_name))
				return FALSE;

			OSVERSIONINFO ver_info = {sizeof(OSVERSIONINFO)};
			b_ret = GetVersionEx(&ver_info);
			if (!b_ret)
				return FALSE;
			gdipp::os_support_directwrite = (ver_info.dwMajorVersion >= 6);

			gdipp::scoped_rw_lock::initialize();

			if (!gdipp::init_rpc_client())
				return FALSE;

			gdipp::client_config_instance.parse(gdipp::config_instance);

			if (!gdipp::hook_instance.start())
				return FALSE;

			break;
		}
		case DLL_PROCESS_DETACH:
			gdipp::hook_instance.stop();
			break;
	}

	return TRUE;
}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_client/global.cpp:
namespace gdipp
{

HMODULE h_self = NULL;
bool os_support_directwrite;
RPC_BINDING_HANDLE h_gdipp_rpc;

config_file config_file_instance(L"client.conf");
config config_instance(config_file_instance);
client_config_static client_config_instance;
gamma gamma_instance;
hook hook_instance;
mem_man mem_man_instance;
//render_config_delta_cache render_config_delta_cache_instance(config_file_instance);

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_client/global.h:
namespace gdipp
{

extern HMODULE h_self;
extern bool os_support_directwrite;
extern RPC_BINDING_HANDLE h_gdipp_rpc;

extern config_file config_file_instance;
extern config config_instance;
extern client_config_static client_config_instance;
extern gamma gamma_instance;
extern hook hook_instance;
extern mem_man mem_man_instance;
//extern render_config_delta_cache render_config_delta_cache_instance;

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_client/helper.cpp:
namespace gdipp
{

bool dc_context::init(HDC hdc)
{
	outline_metrics = get_dc_metrics(hdc, _metric_buf);
	if (outline_metrics == NULL)
		return false;

	if (!get_dc_bmp_header(hdc, bmp_header))
		return false;

	this->hdc = hdc;

	log_font = get_log_font(hdc);
	log_font.lfWeight = get_gdi_weight_class(static_cast<unsigned short>(log_font.lfWeight));

	return true;
}

BYTE division_by_255(short number, short numerator)
{
	// there are many approaches to approximate number * numerator / 255
	// it is a trade-off between efficiency and accuracy

	const int t = number * numerator;
	return (((t + 255) >> 8) + t) >> 8;
}

POINT get_baseline(UINT alignment, int x, int y, int width, int ascent, int descent)
{
	POINT baseline = {x, y};

	switch ((TA_LEFT | TA_RIGHT | TA_CENTER) & alignment)
	{
	case TA_LEFT:
		break;
	case TA_RIGHT:
		baseline.x -= width;
		break;
	case TA_CENTER:
		baseline.x -= width / 2;
		break;
	}

	switch ((TA_TOP | TA_BOTTOM | TA_BASELINE) & alignment)
	{
	case TA_TOP:
		baseline.y += ascent;
		break;
	case TA_BOTTOM:
		baseline.y -= descent;
		break;
	case TA_BASELINE:
		break;
	}

	return baseline;
}

int get_bmp_pitch(int width, WORD bpp)
{
#define FT_PAD_FLOOR( x, n )  ( (x) & ~((n)-1) )
#define FT_PAD_ROUND( x, n )  FT_PAD_FLOOR( (x) + ((n)/2), n )
#define FT_PAD_CEIL( x, n )   FT_PAD_FLOOR( (x) + ((n)-1), n )

	return FT_PAD_CEIL(static_cast<int>(ceil(static_cast<double>(width * bpp) / 8)), sizeof(LONG));
}

bool get_dc_bmp_header(HDC hdc, BITMAPINFOHEADER &dc_bmp_header)
{
	dc_bmp_header.biSize = sizeof(BITMAPINFOHEADER);

	const HBITMAP dc_bitmap = static_cast<const HBITMAP>(GetCurrentObject(hdc, OBJ_BITMAP));
	if (dc_bitmap == NULL)
	{
		// currently no selected bitmap
		// use DC capability

		dc_bmp_header.biWidth = GetDeviceCaps(hdc, HORZRES);
		dc_bmp_header.biHeight = GetDeviceCaps(hdc, VERTRES);
		dc_bmp_header.biPlanes = GetDeviceCaps(hdc, PLANES);
		dc_bmp_header.biBitCount = GetDeviceCaps(hdc, BITSPIXEL);

		return false;
	}
	else
	{
		// do not return the color table
		dc_bmp_header.biBitCount = 0;
		const int i_ret = GetDIBits(hdc, dc_bitmap, 0, 0, NULL, reinterpret_cast<LPBITMAPINFO>(&dc_bmp_header), DIB_RGB_COLORS);
		assert(i_ret != 0);

		return true;
	}
}

OUTLINETEXTMETRICW *get_dc_metrics(HDC hdc, std::vector<BYTE> &metric_buf)
{
	// get outline metrics of the DC, which also include the text metrics

	UINT metric_size = GetOutlineTextMetricsW(hdc, 0, NULL);
	if (metric_size == 0)
		return NULL;

	metric_buf.resize(metric_size);
	OUTLINETEXTMETRICW *outline_metrics = reinterpret_cast<OUTLINETEXTMETRICW *>(&metric_buf[0]);
	metric_size = GetOutlineTextMetricsW(hdc, metric_size, outline_metrics);
	assert(metric_size != 0);

	return outline_metrics;
}

LONG get_glyph_run_width(const gdipp_rpc_bitmap_glyph_run &glyph_run, INT ctrl_right, INT black_right, bool is_control_width)
{
	const RECT *first_box_ptr;
	INT right;

	if (is_control_width)
	{
		// use control box metrics
		first_box_ptr = glyph_run.ctrl_boxes;
		right = ctrl_right;
	}
	else
	{
		// use black box metrics
		first_box_ptr = glyph_run.black_boxes;
		right = black_right;
	}

	if (glyph_run.ctrl_boxes[glyph_run.count - 1].left >= glyph_run.ctrl_boxes[0].left)
		return right - first_box_ptr->left;
	else
		return first_box_ptr->right - right;
}

LOGFONTW get_log_font(HDC hdc)
{
	HFONT h_font = reinterpret_cast<HFONT>(GetCurrentObject(hdc, OBJ_FONT));
	assert(h_font != NULL);

	LOGFONTW font_attr;
	GetObject(h_font, sizeof(LOGFONTW), &font_attr);

	return font_attr;
}

bool mb_to_wc(const char *multi_byte_str, int count, std::wstring &wide_char_str)
{
	int wc_str_len = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, multi_byte_str, count, NULL, 0);
	if (wc_str_len == 0)
		return false;

	wide_char_str.resize(wc_str_len);
	wc_str_len = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, multi_byte_str, count, &wide_char_str[0], wc_str_len);
	if (wc_str_len == 0)
		return false;

	return true;
}

BOOL paint_background(HDC hdc, const RECT *bg_rect, COLORREF bg_color)
{
	int i_ret;

	if (bg_color == CLR_INVALID)
		return FALSE;

	const HBRUSH bg_brush = CreateSolidBrush(bg_color);
	if (bg_brush == NULL)
		return FALSE;

	i_ret = FillRect(hdc, bg_rect, bg_brush);
	if (i_ret == 0)
		return FALSE;

	DeleteObject(bg_brush);
	return TRUE;
}

COLORREF parse_palette_color(HDC hdc, COLORREF color)
{
	// if input color is CLR_INVALID, return it unchanged.
	if (color == CLR_INVALID)
		return CLR_INVALID;

	COLORREF color_ret = color;

	// if the high-order byte is odd, use the selected palette whose index is specified in the low-order bytes
	// see PALETTEINDEX()
	if (!!(color_ret & 0x01000000))
	{
		const HPALETTE dc_palette = static_cast<const HPALETTE>(GetCurrentObject(hdc, OBJ_PAL));

		PALETTEENTRY pal_entry;
		const UINT entries = GetPaletteEntries(dc_palette, (color_ret & 0x00ffffff), 1, &pal_entry);

		// if the DC has no palette entry, this is an invalid color
		if (entries != 0)
			color_ret = RGB(pal_entry.peRed, pal_entry.peGreen, pal_entry.peBlue);
	}

	return color_ret;
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_client/helper.h:
namespace gdipp
{

class dc_context
{
	// data structures and metrics retrieved from HDC are commonly used by multiple gdipp components
	// since gdipp does not alter state of the DC except its selected bitmap during painting, all members are considered constant

public:
	// metrics of the selected bitmap in the DC
	BITMAPINFOHEADER bmp_header;

	// reference to the DC
	HDC hdc;

	// logical font of the selected font in the DC
	LOGFONTW log_font;

	// metrics of the text in the DC
	OUTLINETEXTMETRICW *outline_metrics;

	bool init(HDC hdc);

private:
	// actual data buffer of the OUTLINETEXTMETRICW structure
	std::vector<BYTE> _metric_buf;
};


// high-performance division method to approximate number * numerator / 255
BYTE division_by_255(short number, short numerator);

// apply alignment on the reference point and use it to calculate the baseline
POINT get_baseline(UINT alignment, int x, int y, int width, int ascent, int descent);

// for given bitmap width and bit count, compute the bitmap pitch
int get_bmp_pitch(int width, WORD bpp);

// retrieve BITMAPINFOHEADER from the selected bitmap of the given DC
bool get_dc_bmp_header(HDC hdc, BITMAPINFOHEADER &dc_dc_bmp_header);

// get outline metrics of the DC
OUTLINETEXTMETRICW *get_dc_metrics(HDC hdc, std::vector<BYTE> &metric_buf);

LONG get_glyph_run_width(const gdipp_rpc_bitmap_glyph_run &a_glyph_run, INT ctrl_right, INT black_right, bool is_control_width);

LOGFONTW get_log_font(HDC hdc);

bool mb_to_wc(const char *multi_byte_str, int count, std::wstring &wide_char_str);

BOOL paint_background(HDC hdc, const RECT *bg_rect, COLORREF bg_color);

COLORREF parse_palette_color(HDC hdc, COLORREF color);

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_client/hook.cpp:
namespace gdipp
{

// exported function for EasyHook remote hooking
EXTERN_C __declspec(dllexport) void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* remote_info)
{
	// the process is created suspended, wake it up
	RhWakeUpProcess();
}

bool char_str_ci_less::operator()(const char *string1, const char *string2) const
{
	// filename is insensitive in Windows
	return _stricmp(string1, string2) < 0;
}

bool wchar_str_ci_less::operator()(const wchar_t *string1, const wchar_t *string2) const
{
	return _wcsicmp(string1, string2) < 0;
}

bool hook::install_hook(LPCSTR lib_name, LPCSTR proc_name, void *hook_proc)
{
	// hook a procedure in the specified library that has been loaded before client
	// ANSI version

	const HMODULE h_lib = GetModuleHandleA(lib_name);
	if (h_lib == NULL)
		return false;

	return install_hook(h_lib, proc_name, hook_proc);
}

bool hook::install_hook(LPCWSTR lib_name, LPCSTR proc_name, void *hook_proc)
{
	// hook a procedure in the specified library that has been loaded before client
	// Unicode version

	const HMODULE h_lib = GetModuleHandleW(lib_name);
	if (h_lib == NULL)
		return false;

	return install_hook(h_lib, proc_name, hook_proc);
}

bool hook::install_delayed_hook(LPCSTR lib_name, HMODULE h_lib)
{
	// hook a procedure in the specified library that is dynamically loaded (e.g. by LoadLibrary())
	// the procedure is registered a priori via register_delayed_hook()
	// ANSI version
	
	bool b_ret = true;

	lib_hook_map_a::const_iterator lib_iter = _delayed_hooks_a.find(lib_name);
	if (lib_iter != _delayed_hooks_a.end())
	{
		for (hook_proc_map::const_iterator proc_iter = lib_iter->second->begin(); proc_iter != lib_iter->second->end(); ++proc_iter)
		{
			b_ret &= install_hook(h_lib, proc_iter->first, proc_iter->second);
			if (!b_ret)
				break;
		}
	}

	return b_ret;
}

bool hook::install_delayed_hook(LPCWSTR lib_name, HMODULE h_lib)
{
	// hook a procedure in the specified library that is dynamically loaded (e.g. by LoadLibrary())
	// the procedure is registered a priori via register_delayed_hook()
	// Unicode version

	bool b_ret = true;

	lib_hook_map_w::const_iterator lib_iter = _delayed_hooks_w.find(lib_name);
	if (lib_iter != _delayed_hooks_w.end())
	{
		for (hook_proc_map::const_iterator proc_iter = lib_iter->second->begin(); proc_iter != lib_iter->second->end(); ++proc_iter)
		{
			b_ret &= install_hook(h_lib, proc_iter->first, proc_iter->second);
			if (!b_ret)
				break;
		}
	}

	return b_ret;
}

bool hook::start()
{
	bool b_ret;

	b_ret = install_hook(L"gdi32.dll", "ExtTextOutW", ExtTextOutW_hook);
	if (b_ret)
	{
		// hook other GDI APIs only if ExtTextOut is successfully hooked

		// reserve for future use
// 		b_ret &= install_hook(L"user32.dll", "DrawTextExA", DrawTextExA_hook);
// 		b_ret &= install_hook(L"user32.dll", "DrawTextExW", DrawTextExW_hook);

// 		b_ret &= install_hook(L"gdi32.dll", "GetTextExtentPoint32A", GetTextExtentPoint32A_hook);
// 		b_ret &= install_hook(L"gdi32.dll", "GetTextExtentPoint32W", GetTextExtentPoint32W_hook);
// 		b_ret &= install_hook(L"gdi32.dll", "GetTextExtentPointI", GetTextExtentPointI_hook);
//
// 		b_ret &= install_hook(L"gdi32.dll", "GetTextExtentExPointA", GetTextExtentExPointA_hook);
// 		b_ret &= install_hook(L"gdi32.dll", "GetTextExtentExPointW", GetTextExtentExPointW_hook);
// 		b_ret &= install_hook(L"gdi32.dll", "GetTextExtentExPointI", GetTextExtentExPointI_hook);
//
// 		b_ret &= install_hook(L"gdi32.dll", "GetGlyphOutlineA", GetGlyphOutlineA_hook);
// 		b_ret &= install_hook(L"gdi32.dll", "GetGlyphOutlineW", GetGlyphOutlineW_hook);
//
// 		b_ret &= install_hook(L"gdi32.dll", "AbortPath", AbortPath_hook);
// 		b_ret &= install_hook(L"gdi32.dll", "BeginPath", BeginPath_hook);
// 		b_ret &= install_hook(L"gdi32.dll", "EndPath", EndPath_hook);
//
// 		install_hook(L"usp10.dll", "ScriptPlace", ScriptPlace_hook);

		// register hooks whose libraries are dynamically loaded by LoadLibrary
		//register_delayed_hook("d2d1.dll", L"d2d1.dll", "D2D1CreateFactory", D2D1CreateFactory_hook);

		if (!_delayed_hook_registry.empty())
		{
			install_hook(L"kernel32.dll", "LoadLibraryA", LoadLibraryA_hook);
			install_hook(L"kernel32.dll", "LoadLibraryExA", LoadLibraryExA_hook);
			install_hook(L"kernel32.dll", "LoadLibraryW", LoadLibraryW_hook);
			install_hook(L"kernel32.dll", "LoadLibraryExW", LoadLibraryExW_hook);
		}
	}

#if defined GDIPP_INJECT_SANDBOX && !defined _M_X64
	// currently not support inject at EIP for 64-bit processes
	b_ret &= install_hook(L"advapi32.dll", "CreateProcessAsUserW", CreateProcessAsUserW_hook);
#endif // GDIPP_INJECT_SANDBOX && !_M_X64

	return b_ret;
}

void hook::stop()
{
	NTSTATUS eh_ret;

	eh_ret = LhUninstallAllHooks();
	assert(eh_ret == 0);

	eh_ret = LhWaitForPendingRemovals();
	assert(eh_ret == 0);

	for (std::list<TRACED_HOOK_HANDLE>::const_iterator iter = _hooks.begin(); iter != _hooks.end(); ++iter)
		delete *iter;
}

bool hook::install_hook(HMODULE h_lib, LPCSTR proc_name, void *hook_proc)
{
	// hook a procedure in the specified library that has been loaded before client
	// use EasyHook
	
	NTSTATUS eh_ret;

	const FARPROC proc_addr = GetProcAddress(h_lib, proc_name);
	assert(proc_addr != NULL);

	TRACED_HOOK_HANDLE h_hook = new HOOK_TRACE_INFO();
	eh_ret = LhInstallHook(proc_addr, hook_proc, NULL, h_hook);
	assert(eh_ret == 0);

	ULONG thread_id_list = 0;
	eh_ret = LhSetExclusiveACL(&thread_id_list, 0, h_hook);
	assert(eh_ret == 0);

	_hooks.push_back(h_hook);

	return true;
}

void hook::register_delayed_hook(LPCSTR lib_name_a, LPCWSTR lib_name_w, LPCSTR proc_name, void *hook_proc)
{
	// register a procedure for delayed hook
	
	lib_hook_map_a::const_iterator lib_iter = _delayed_hooks_a.find(lib_name_a);
	if (lib_iter == _delayed_hooks_a.end())
	{
		_delayed_hook_registry.push_back(hook_proc_map());
		hook_proc_map *curr_hook_map = &_delayed_hook_registry.back();

		(*curr_hook_map)[proc_name] = hook_proc;
		_delayed_hooks_a[lib_name_a] = curr_hook_map;
		_delayed_hooks_w[lib_name_w] = curr_hook_map;
	}
	else
		(*lib_iter->second)[proc_name] = hook_proc;
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_client/hook.h:
namespace gdipp
{

struct char_str_ci_less
{
	bool operator()(const char *string1, const char *string2) const;
};

struct wchar_str_ci_less
{
	bool operator()(const wchar_t *string1, const wchar_t *string2) const;
};

class hook
{
public:
	bool install_hook(LPCSTR lib_name, LPCSTR proc_name, void *hook_proc);
	bool install_hook(LPCWSTR lib_name, LPCSTR proc_name, void *hook_proc);
	bool install_delayed_hook(LPCSTR lib_name, HMODULE h_lib);
	bool install_delayed_hook(LPCWSTR lib_name, HMODULE h_lib);
	bool start();
	void stop();

private:
	typedef std::map<const char *, void *> hook_proc_map;
	typedef std::map<const char *, hook_proc_map *, char_str_ci_less> lib_hook_map_a;
	typedef std::map<const wchar_t *, hook_proc_map *, wchar_str_ci_less> lib_hook_map_w;

	bool install_hook(HMODULE h_lib, LPCSTR proc_name, void *hook_proc);
	void register_delayed_hook(LPCSTR lib_name_a, LPCWSTR lib_name_w, LPCSTR proc_name, void *hook_proc);

	// procedure name => hook procedure pointer
	std::list<hook_proc_map> _delayed_hook_registry;
	lib_hook_map_a _delayed_hooks_a;
	lib_hook_map_w _delayed_hooks_w;

	std::list<TRACED_HOOK_HANDLE> _hooks;
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_client/mem_man.cpp:
namespace gdipp
{

mem_man::~mem_man()
{
	for (std::list<IUnknown *>::const_iterator iter = _com_ptr_store.begin(); iter != _com_ptr_store.end(); ++iter)
		(*iter)->Release();

	for (std::list<void *>::const_iterator iter = _mem_ptr_store.begin(); iter != _mem_ptr_store.end(); ++iter)
		delete *iter;
}

void mem_man::register_com_ptr(IUnknown *com_ptr)
{
	_com_ptr_store.push_back(com_ptr);
}

void mem_man::register_mem_ptr(void *mem_ptr)
{
	_mem_ptr_store.push_back(mem_ptr);
}

void mem_man::register_heap_ptr(LPVOID mem_ptr)
{
	HeapFree(GetProcessHeap(), 0, mem_ptr);
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_client/mem_man.h:
namespace gdipp
{

class mem_man
{
	// helper class to free static memory pointers

public:
	~mem_man();

	void register_com_ptr(IUnknown *com_ptr);
	void register_mem_ptr(void *mem_ptr);
	void register_heap_ptr(LPVOID mem_ptr);

private:
	std::list<IUnknown *> _com_ptr_store;
	std::list<void *> _mem_ptr_store;
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_client/painter.cpp:
namespace gdipp
{

painter::~painter()
{
}

bool painter::begin(const dc_context *context)
{
	_context = context;

	_text_alignment = GetTextAlign(_context->hdc);
	assert(_text_alignment != GDI_ERROR);

	_text_color = parse_palette_color(_context->hdc, GetTextColor(_context->hdc));
	if (_text_color == CLR_INVALID)
		_text_color = 0;

	// transparent DC may not have background color
	_bg_color = parse_palette_color(_context->hdc, GetBkColor(_context->hdc));

	return true;
}

void painter::end()
{
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_client/painter.h:
namespace gdipp
{

class painter
{
public:
	virtual ~painter();

	virtual bool begin(const dc_context *context);
	virtual void end();
	virtual bool paint(int x, int y, UINT options, CONST RECT *lprect, gdipp_rpc_bitmap_glyph_run &glyph_run, INT ctrl_right, INT black_right) = 0;

protected:
	const dc_context *_context;
	POINT _cursor;
	COLORREF _bg_color;
	FT_Render_Mode _render_mode;
	UINT _text_alignment;
	COLORREF _text_color;
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_client/wic_dib.cpp:
namespace gdipp
{

IFACEMETHODIMP gdimm_wic_dib_lock::QueryInterface(
	/* [in] */ REFIID riid,
	/* [iid_is][out] */ __RPC__deref_out void __RPC_FAR *__RPC_FAR *ppvObject)
{
	return E_NOTIMPL;
}

IFACEMETHODIMP_(ULONG) gdimm_wic_dib_lock::AddRef( void)
{
	return 0;
}

IFACEMETHODIMP_(ULONG) gdimm_wic_dib_lock::Release( void)
{
	return 0;
}

IFACEMETHODIMP gdimm_wic_dib_lock::GetSize(
	/* [out] */ __RPC__out UINT *puiWidth,
	/* [out] */ __RPC__out UINT *puiHeight)
{
	*puiWidth = _lock_rect->Width;
	*puiHeight = _lock_rect->Height;

	return S_OK;
}

IFACEMETHODIMP gdimm_wic_dib_lock::GetStride(
	/* [out] */ __RPC__out UINT *pcbStride)
{
	*pcbStride = get_bmp_pitch(_lock_rect->Width, _bmp_info->bmiHeader.biBitCount);

	return S_OK;
}

/* [local] */ IFACEMETHODIMP gdimm_wic_dib_lock::GetDataPointer(
	/* [out] */ UINT *pcbBufferSize,
	/* [out] */ BYTE **ppbData)
{
	*pcbBufferSize = get_bmp_pitch(_lock_rect->Width, _bmp_info->bmiHeader.biBitCount) * _lock_rect->Height;
	*ppbData = (BYTE *)_bits;

	return S_OK;
}

IFACEMETHODIMP gdimm_wic_dib_lock::GetPixelFormat(
	/* [out] */ __RPC__out WICPixelFormatGUID *pPixelFormat)
{
	*pPixelFormat = GUID_WICPixelFormat32bppBGR;

	return S_OK;
}

void gdimm_wic_dib_lock::initialize(const BITMAPINFO *bmp_info, VOID *bits)
{
	_bmp_info = bmp_info;
	_bits = bits;
}

void gdimm_wic_dib_lock::set_rect(const WICRect *lock_rect)
{
	_lock_rect = lock_rect;
}

IFACEMETHODIMP gdimm_wic_dib::QueryInterface(
	/* [in] */ REFIID riid,
	/* [iid_is][out] */ __RPC__deref_out void __RPC_FAR *__RPC_FAR *ppvObject)
{
	return E_NOTIMPL;
}

IFACEMETHODIMP_(ULONG) gdimm_wic_dib::AddRef( void)
{
	return 0;
}

IFACEMETHODIMP_(ULONG) gdimm_wic_dib::Release( void)
{
	return 0;
}

IFACEMETHODIMP gdimm_wic_dib::GetSize(
	/* [out] */ __RPC__out UINT *puiWidth,
	/* [out] */ __RPC__out UINT *puiHeight)
{
	*puiWidth = _bmp_info->bmiHeader.biWidth;
	*puiHeight = abs(_bmp_info->bmiHeader.biHeight);

	return S_OK;
}

IFACEMETHODIMP gdimm_wic_dib::GetPixelFormat(
	/* [out] */ __RPC__out WICPixelFormatGUID *pPixelFormat)
{
	switch (_bmp_info->bmiHeader.biBitCount)
	{
	case 1:
		*pPixelFormat = GUID_WICPixelFormatBlackWhite;
	case 8:
		*pPixelFormat = GUID_WICPixelFormat8bppGray;
	case 24:
	case 32:
		*pPixelFormat = GUID_WICPixelFormat32bppBGR;
		break;
	}

	return S_OK;
}

IFACEMETHODIMP gdimm_wic_dib::GetResolution(
	/* [out] */ __RPC__out double *pDpiX,
	/* [out] */ __RPC__out double *pDpiY)
{
	return E_NOTIMPL;
}

IFACEMETHODIMP gdimm_wic_dib::CopyPalette(
	/* [in] */ __RPC__in_opt IWICPalette *pIPalette)
{
	// we do not use palette
	return E_NOTIMPL;
}

IFACEMETHODIMP gdimm_wic_dib::CopyPixels(
	/* [unique][in] */ __RPC__in_opt const WICRect *prc,
	/* [in] */ UINT cbStride,
	/* [in] */ UINT cbBufferSize,
	/* [size_is][out] */ __RPC__out_ecount_full(cbBufferSize) BYTE *pbBuffer)
{
	// use lock instead
	return E_NOTIMPL;
}

IFACEMETHODIMP gdimm_wic_dib::Lock(
	/* [in] */ __RPC__in const WICRect *prcLock,
	/* [in] */ DWORD flags,
	/* [out] */ __RPC__deref_out_opt IWICBitmapLock **ppILock)
{
	_lock.set_rect(prcLock);
	*ppILock = &_lock;

	return S_OK;
}

IFACEMETHODIMP gdimm_wic_dib::SetPalette(
	/* [in] */ __RPC__in_opt IWICPalette *pIPalette)
{
	// we do not use palette
	return E_NOTIMPL;
}

IFACEMETHODIMP gdimm_wic_dib::SetResolution(
	/* [in] */ double dpiX,
	/* [in] */ double dpiY)
{
	return E_NOTIMPL;
}

void gdimm_wic_dib::initialize(const BITMAPINFO *bmp_info, VOID *bits)
{
	_bmp_info = bmp_info;
	_lock.initialize(bmp_info, bits);
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_client/wic_dib.h:
namespace gdipp
{

class gdimm_wic_dib_lock : public IWICBitmapLock
{
public:
	IFACEMETHOD(QueryInterface)(
		/* [in] */ REFIID riid,
		/* [iid_is][out] */ __RPC__deref_out void __RPC_FAR *__RPC_FAR *ppvObject);

	IFACEMETHOD_(ULONG, AddRef)( void);

	IFACEMETHOD_(ULONG, Release)( void);

public:
	IFACEMETHOD(GetSize)(
		/* [out] */ __RPC__out UINT *puiWidth,
		/* [out] */ __RPC__out UINT *puiHeight);

	IFACEMETHOD(GetStride)(
		/* [out] */ __RPC__out UINT *pcbStride);

	/* [local] */ IFACEMETHOD(GetDataPointer)(
		/* [out] */ UINT *pcbBufferSize,
		/* [out] */ BYTE **ppbData);

	IFACEMETHOD(GetPixelFormat)(
		/* [out] */ __RPC__out WICPixelFormatGUID *pPixelFormat);

public:
	void initialize(const BITMAPINFO *bmp_info, VOID *bits);
	void set_rect(const WICRect *lock_rect);

private:
	const WICRect *_lock_rect;
	const BITMAPINFO *_bmp_info;
	VOID *_bits;
};

class gdimm_wic_dib : public IWICBitmap
{
public:
	IFACEMETHOD(QueryInterface)(
		/* [in] */ REFIID riid,
		/* [iid_is][out] */ __RPC__deref_out void __RPC_FAR *__RPC_FAR *ppvObject);

	IFACEMETHOD_(ULONG, AddRef)( void);

	IFACEMETHOD_(ULONG, Release)( void);

public:
	IFACEMETHOD(GetSize)(
		/* [out] */ __RPC__out UINT *puiWidth,
		/* [out] */ __RPC__out UINT *puiHeight);

	IFACEMETHOD(GetPixelFormat)(
		/* [out] */ __RPC__out WICPixelFormatGUID *pPixelFormat);

	IFACEMETHOD(GetResolution)(
		/* [out] */ __RPC__out double *pDpiX,
		/* [out] */ __RPC__out double *pDpiY);

	IFACEMETHOD(CopyPalette)(
		/* [in] */ __RPC__in_opt IWICPalette *pIPalette);

	IFACEMETHOD(CopyPixels)(
		/* [unique][in] */ __RPC__in_opt const WICRect *prc,
		/* [in] */ UINT cbStride,
		/* [in] */ UINT cbBufferSize,
		/* [size_is][out] */ __RPC__out_ecount_full(cbBufferSize) BYTE *pbBuffer);

public:
	IFACEMETHOD(Lock)(
		/* [in] */ __RPC__in const WICRect *prcLock,
		/* [in] */ DWORD flags,
		/* [out] */ __RPC__deref_out_opt IWICBitmapLock **ppILock);

	IFACEMETHOD(SetPalette)(
		/* [in] */ __RPC__in_opt IWICPalette *pIPalette);

	IFACEMETHOD(SetResolution)(
		/* [in] */ double dpiX,
		/* [in] */ double dpiY);

public:
	void initialize(const BITMAPINFO *bmp_info, VOID *bits);

private:
	const BITMAPINFO *_bmp_info;
	gdimm_wic_dib_lock _lock;
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_client/wic_painter.cpp:
namespace gdipp
{

ID2D1Factory *gdimm_wic_painter::_d2d_factory = NULL;
IDWriteFactory *gdimm_wic_painter::_dw_factory = NULL;
IDWriteGdiInterop *gdimm_wic_painter::_dw_gdi_interop = NULL;

gdimm_wic_painter::gdimm_wic_painter()
{
	HRESULT hr;

	if (_d2d_factory == NULL)
	{
		hr = D2D1CreateFactory(D2D1_FACTORY_TYPE_MULTI_THREADED, &_d2d_factory);
		assert(hr == S_OK);

		mem_man_instance.register_com_ptr(_d2d_factory);
	}

	if (_dw_factory == NULL)
	{
		hr = DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory), reinterpret_cast<IUnknown **>(&_dw_factory));
		assert(hr == S_OK);

		mem_man_instance.register_com_ptr(_dw_factory);
	}

	if (_dw_gdi_interop == NULL)
	{
		hr = _dw_factory->GetGdiInterop(&_dw_gdi_interop);
		assert(hr == S_OK);

		mem_man_instance.register_com_ptr(_dw_gdi_interop);
	}
}

bool gdimm_wic_painter::begin(const dc_context *context, FT_Render_Mode render_mode)
{
	if (!painter::begin(context, render_mode))
		return false;

	// ignore rotated DC
	if (_context->log_font.lfEscapement % 3600 != 0)
		return false;

	_hdc_canvas = CreateCompatibleDC(NULL);
	if (_hdc_canvas == NULL)
		return false;

	switch (_context->setting_cache->hinting)
	{
	case 2:
		_dw_measuring_mode = DWRITE_MEASURING_MODE_GDI_NATURAL;
		break;
	case 3:
		_dw_measuring_mode = DWRITE_MEASURING_MODE_GDI_CLASSIC;
		break;
	default:
		_dw_measuring_mode = DWRITE_MEASURING_MODE_NATURAL;
		break;
	}
	_use_gdi_natural = (_dw_measuring_mode != DWRITE_MEASURING_MODE_GDI_CLASSIC);

	// BGR -> RGB
	_text_color = RGB(GetBValue(_text_color), GetGValue(_text_color), GetRValue(_text_color));
	_bg_color = RGB(GetBValue(_bg_color), GetGValue(_bg_color), GetRValue(_bg_color));

	_em_size = static_cast<FLOAT>(_context->outline_metrics->otmTextMetrics.tmHeight - _context->outline_metrics->otmTextMetrics.tmInternalLeading) - 0.3f;	// small adjustment to emulate GDI bbox
	_pixels_per_dip = GetDeviceCaps(_context->hdc, LOGPIXELSY) / 96.0f;

	return true;
}

void gdimm_wic_painter::end()
{
	DeleteDC(_hdc_canvas);
}

bool gdimm_wic_painter::paint(int x, int y, UINT options, CONST RECT *lprect, const void *text, UINT c, CONST INT *lpDx)
{
	BOOL b_ret;

	BOOL update_cursor;
	if (((TA_NOUPDATECP | TA_UPDATECP) & _text_alignment) == TA_UPDATECP)
	{
		POINT cp;
		b_ret = GetCurrentPositionEx(_context->hdc, &cp);
		assert(b_ret);

		_cursor.x = cp.x;
		_cursor.y = cp.y;
		update_cursor = true;
	}
	else
	{
		_cursor.x = x;
		_cursor.y = y;
		update_cursor = false;
	}

	const bool paint_success = draw_text(options, lprect, static_cast<LPCWSTR>(text), c, lpDx);

	// if TA_UPDATECP is set, update current position after text out
	if (update_cursor && paint_success)
	{
		b_ret = MoveToEx(_context->hdc, _cursor.x, _cursor.y, NULL);
		assert(b_ret);
	}

	return paint_success;
}

bool gdimm_wic_painter::prepare(LPCWSTR lpString, UINT c, LONG &bbox_width, IDWriteFontFace **dw_font_face, DWRITE_GLYPH_RUN &dw_glyph_run)
{
	HRESULT hr;

	hr = _dw_gdi_interop->CreateFontFaceFromHdc(_context->hdc, dw_font_face);
	assert(hr == S_OK);

	dw_glyph_run.fontFace = *dw_font_face;
	dw_glyph_run.fontEmSize = _em_size;
	dw_glyph_run.glyphCount = c;
	dw_glyph_run.glyphIndices = reinterpret_cast<const UINT16 *>(lpString);
	dw_glyph_run.glyphAdvances = (_advances.empty() ? NULL : _advances.data());
	dw_glyph_run.glyphOffsets = NULL;
	dw_glyph_run.isSideways = FALSE;
	dw_glyph_run.bidiLevel = 0;

	std::vector<DWRITE_GLYPH_METRICS> glyph_metrics(c);
	if (_dw_measuring_mode == DWRITE_MEASURING_MODE_NATURAL)
		hr = (*dw_font_face)->GetDesignGlyphMetrics(reinterpret_cast<const UINT16 *>(lpString), c, glyph_metrics.data());
	else
		hr = (*dw_font_face)->GetGdiCompatibleGlyphMetrics(_em_size,
		_pixels_per_dip,
		NULL,
		_use_gdi_natural,
		reinterpret_cast<const UINT16 *>(lpString),
		c,
		glyph_metrics.data());
	assert(hr == S_OK);

	UINT32 glyph_run_width = 0;
	for (UINT i = 0; i < c; ++i)
		glyph_run_width += glyph_metrics[i].advanceWidth;
	bbox_width = max(bbox_width, static_cast<LONG>(glyph_run_width * _em_size / _context->outline_metrics->otmEMSquare));

	// more accurate width than DirectWrite functions
	// 	SIZE text_extent;
	// 	b_ret = GetTextExtentPointI(_context->hdc, (LPWORD) lpString, c, &text_extent);
	// 	assert(b_ret);
	// 	bbox_width = max(bbox_width, (UINT32) text_extent.cx);

	return true;
}

bool gdimm_wic_painter::prepare(LPCWSTR lpString, UINT c, LONG &bbox_width, IDWriteTextLayout **dw_text_layout)
{
	HRESULT hr;
	bool b_ret;

	os2_metrics os2;
	b_ret = os2_metrics.init(_context->hdc);
	assert(b_ret);

	DWRITE_FONT_STYLE dw_font_style;
	if (!_context->outline_metrics->otmTextMetrics.tmItalic)
		dw_font_style = DWRITE_FONT_STYLE_NORMAL;
	else if (os2_metrics.is_italic())
		dw_font_style = DWRITE_FONT_STYLE_ITALIC;
	else
		dw_font_style = DWRITE_FONT_STYLE_OBLIQUE;

	CComPtr<IDWriteTextFormat> dw_text_format;
	hr = _dw_factory->CreateTextFormat(metric_family_name(_context->outline_metrics),
		NULL,
		static_cast<DWRITE_FONT_WEIGHT>(_context->outline_metrics->otmTextMetrics.tmWeight),
		dw_font_style,
		static_cast<DWRITE_FONT_STRETCH>(os2_metrics.get_usWidthClass()),
		_em_size,
		L"",
		&dw_text_format);
	assert(hr == S_OK);

	hr = dw_text_format->SetWordWrapping(DWRITE_WORD_WRAPPING_NO_WRAP);
	assert(hr == S_OK);

	if (_dw_measuring_mode == DWRITE_MEASURING_MODE_NATURAL)
	{
		hr = _dw_factory->CreateTextLayout(lpString,
			c,
			dw_text_format,
			static_cast<FLOAT>(_context->bmp_header.biWidth),
			0,
			dw_text_layout);
	}
	else
	{
		hr = _dw_factory->CreateGdiCompatibleTextLayout(lpString,
			c,
			dw_text_format,
			static_cast<FLOAT>(_context->bmp_header.biWidth),
			0,
			_pixels_per_dip,
			NULL,
			_use_gdi_natural,
			dw_text_layout);
	}
	assert(hr == S_OK);

	DWRITE_TEXT_METRICS text_bbox;
	hr = (*dw_text_layout)->GetMetrics(&text_bbox);
	assert(hr == S_OK);
	bbox_width = max(bbox_width, static_cast<LONG>(ceil(text_bbox.width)));

	// 	// more accurate width than DirectWrite functions
	// 	SIZE text_extent;
	// 	b_ret = GetTextExtentPoint32W(_context->hdc, lpString, c, &text_extent);
	// 	assert(b_ret);
	// 	bbox_width = max(bbox_width, reinterpret_cast<UINT32>(text_extent.cx));

	return true;
}

void gdimm_wic_painter::set_param(ID2D1RenderTarget *render_target)
{
	HRESULT hr;

	DWRITE_RENDERING_MODE dw_render_mode;
	if (_render_mode == FT_RENDER_MODE_MONO)
		dw_render_mode = DWRITE_RENDERING_MODE_ALIASED;
	else
	{
		switch (_context->setting_cache->hinting)
		{
		case 0:
			dw_render_mode = DWRITE_RENDERING_MODE_DEFAULT;
			break;
		case 2:
			dw_render_mode = DWRITE_RENDERING_MODE_CLEARTYPE_GDI_NATURAL;
			break;
		case 3:
			dw_render_mode = DWRITE_RENDERING_MODE_CLEARTYPE_GDI_CLASSIC;
			break;
		default:
			dw_render_mode = DWRITE_RENDERING_MODE_CLEARTYPE_NATURAL_SYMMETRIC;
			break;
		}
	}

	D2D1_TEXT_ANTIALIAS_MODE text_aa_mode;
	switch (_render_mode)
	{
	case FT_RENDER_MODE_NORMAL:
	case FT_RENDER_MODE_LIGHT:
		text_aa_mode = D2D1_TEXT_ANTIALIAS_MODE_GRAYSCALE;
		break;
	case FT_RENDER_MODE_MONO:
		text_aa_mode = D2D1_TEXT_ANTIALIAS_MODE_ALIASED;
		break;
	default:
		text_aa_mode = D2D1_TEXT_ANTIALIAS_MODE_CLEARTYPE;
		break;
	}

	DWRITE_PIXEL_GEOMETRY pixel_geometry;
	switch (_context->setting_cache->render_mode.pixel_geometry)
	{
	case PIXEL_GEOMETRY_BGR:
		pixel_geometry = DWRITE_PIXEL_GEOMETRY_BGR;
	default:
		pixel_geometry = DWRITE_PIXEL_GEOMETRY_RGB;
	}

	// use average gamma
	const FLOAT avg_gamma = static_cast<const FLOAT>(_context->setting_cache->gamma.red + _context->setting_cache->gamma.green + _context->setting_cache->gamma.blue) / 3;

	CComPtr<IDWriteRenderingParams> dw_render_params;
	hr = _dw_factory->CreateCustomRenderingParams(avg_gamma, 0.0f, 1.0f, pixel_geometry, dw_render_mode, &dw_render_params);
	assert(hr == S_OK);

	render_target->SetTextRenderingParams(dw_render_params);
	render_target->SetTextAntialiasMode(text_aa_mode);
}

bool gdimm_wic_painter::draw_text(UINT options, CONST RECT *lprect, LPCWSTR lpString, UINT c, CONST INT *lpDx)
{
	HRESULT hr;
	BOOL b_ret, paint_success;

	LONG bbox_width = 0;

	const int dx_skip = ((options & ETO_PDY) ? 2 : 1);
	if (lpDx != NULL)
	{
		_advances.resize(c);
		for (UINT i = 0; i < c; ++i)
		{
			_advances[i] = static_cast<FLOAT>(lpDx[i * dx_skip]);
			bbox_width += lpDx[i * dx_skip];
		}
	}

	if (bbox_width == 0)
		return false;

	LONG bbox_height = _context->outline_metrics->otmTextMetrics.tmHeight;
	const LONG bbox_ascent = _context->outline_metrics->otmTextMetrics.tmAscent;
	const LONG bbox_descent = _context->outline_metrics->otmTextMetrics.tmDescent;

	CComPtr<IDWriteFontFace> dw_font_face;
	DWRITE_GLYPH_RUN dw_glyph_run;
	CComPtr<IDWriteTextLayout> dw_text_layout;

	if (options & ETO_GLYPH_INDEX)
		b_ret = prepare(lpString, c, bbox_width, &dw_font_face, dw_glyph_run);
	else
		b_ret = prepare(lpString, c, bbox_width, &dw_text_layout);
	assert(b_ret);

	const POINT bbox_baseline = get_baseline(_text_alignment,
		_cursor.x,
		_cursor.y,
		bbox_width,
		bbox_ascent,
		bbox_descent);

	POINT bbox_origin = {bbox_baseline.x, bbox_baseline.y - bbox_ascent};

	_cursor.x += bbox_width;

	POINT canvas_origin = {};

	// calculate bbox after clipping
	if (options & ETO_CLIPPED)
	{
		RECT bmp_rect = {bbox_origin.x,
			bbox_origin.y,
			bbox_origin.x + bbox_width,
			bbox_origin.y + bbox_height};
		if (!IntersectRect(&bmp_rect, &bmp_rect, lprect))
			return false;

		bbox_width = bmp_rect.right - bmp_rect.left;
		bbox_height = bmp_rect.bottom - bmp_rect.top;
		canvas_origin.x = bbox_origin.x - bmp_rect.left;
		canvas_origin.y = bbox_origin.y - bmp_rect.top;
		bbox_origin.x = bmp_rect.left;
		bbox_origin.y = bmp_rect.top;
	}

	const BITMAPINFO bmp_info = {sizeof(BITMAPINFOHEADER), bbox_width, -bbox_height, 1, _context->bmp_header.biBitCount, BI_RGB};

	BYTE *text_bits;
	HBITMAP text_bitmap = CreateDIBSection(_context->hdc, &bmp_info, DIB_RGB_COLORS, reinterpret_cast<VOID **>(&text_bits), NULL, 0);
	assert(text_bitmap != NULL);
	SelectObject(_hdc_canvas, text_bitmap);

	_wic_bitmap.initialize(&bmp_info, text_bits);

	CComPtr<ID2D1RenderTarget> wic_render_target;
	hr = _d2d_factory->CreateWicBitmapRenderTarget(&_wic_bitmap, D2D1::RenderTargetProperties(), &wic_render_target);
	assert(hr == S_OK);

	set_param(wic_render_target);

	wic_render_target->BeginDraw();

	if (options & ETO_OPAQUE)
		paint_background(_context->hdc, lprect, _bg_color);

	const int bk_mode = GetBkMode(_context->hdc);
	if (bk_mode == OPAQUE)
	{
		wic_render_target->Clear(D2D1::ColorF(_bg_color));
		paint_success = TRUE;
	}
	else if (bk_mode == TRANSPARENT)
	{
		// "If a rotation or shear transformation is in effect in the source device context, BitBlt returns an error"
		paint_success = BitBlt(_hdc_canvas,
			0,
			0,
			bbox_width,
			bbox_height,
			_context->hdc,
			bbox_origin.x,
			bbox_origin.y,
			SRCCOPY);
	}

	if (paint_success)
	{
		CComPtr<ID2D1SolidColorBrush> text_brush;
		hr = wic_render_target->CreateSolidColorBrush(D2D1::ColorF(_text_color), &text_brush);
		assert(hr == S_OK);

		if (options & ETO_GLYPH_INDEX)
			wic_render_target->DrawGlyphRun(D2D1::Point2F(static_cast<FLOAT>(canvas_origin.x), static_cast<FLOAT>(canvas_origin.y + bbox_ascent)), &dw_glyph_run, text_brush, _dw_measuring_mode);
		else
			wic_render_target->DrawTextLayout(D2D1::Point2F(static_cast<FLOAT>(canvas_origin.x), static_cast<FLOAT>(canvas_origin.y)), dw_text_layout, text_brush);
	}

	hr = wic_render_target->EndDraw();

	paint_success = (hr == S_OK);
	if (paint_success)
	{
		paint_success = BitBlt(_context->hdc,
			bbox_origin.x,
			bbox_origin.y,
			bbox_width,
			bbox_height,
			_hdc_canvas,
			0,
			0,
			SRCCOPY);
	}

	b_ret = DeleteObject(text_bitmap);
	assert(b_ret);

	return !!paint_success;
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_client/wic_painter.h:
namespace gdipp
{

class gdimm_wic_painter : public painter
{
public:
	gdimm_wic_painter();

	virtual bool begin(const dc_context *context, FT_Render_Mode render_mode);
	void end();
	bool paint(int x, int y, UINT options, CONST RECT *lprect, const void *text, UINT c, CONST INT *lpDx);

private:
	bool prepare(LPCWSTR lpString, UINT c, LONG &bbox_width, IDWriteFontFace **dw_font_face, DWRITE_GLYPH_RUN &dw_glyph_run);
	bool prepare(LPCWSTR lpString, UINT c, LONG &bbox_width, IDWriteTextLayout **dw_text_layout);
	void set_param(ID2D1RenderTarget *render_target);
	bool draw_text(UINT options, CONST RECT *lprect, LPCWSTR lpString, UINT c, CONST INT *lpDx);

	static ID2D1Factory *_d2d_factory;
	static IDWriteFactory *_dw_factory;
	static IDWriteGdiInterop *_dw_gdi_interop;

	std::vector<FLOAT> _advances;
	DWRITE_MEASURING_MODE _dw_measuring_mode;
	HDC _hdc_canvas;
	FLOAT _pixels_per_dip;
	bool _use_gdi_natural;
	gdimm_wic_dib _wic_bitmap;

	FLOAT _em_size;
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_config/client_config_static.cpp:
namespace gdipp
{

client_config_static::gamma_static::gamma_static()
	: red(client_config::GAMMA_RED),
	green(client_config::GAMMA_GREEN),
	blue(client_config::GAMMA_BLUE)
{
}

client_config_static::shadow_static::shadow_static()
	: offset_x(client_config::SHADOW_OFFSET_X),
	offset_y(client_config::SHADOW_OFFSET_Y),
	alpha(client_config::SHADOW_ALPHA)
{
}

client_config_static::client_config_static()
	: painter(client_config::PAINTER),
	pixel_geometry(client_config::PIXEL_GEOMETRY)
{
}

void client_config_static::parse(const config &cfg)
{
	gamma.red = cfg.get_number(L"/gdipp/client/paint/gamma/red/text()", gamma.red);
	gamma.green = cfg.get_number(L"/gdipp/client/paint/gamma/green/text()", gamma.green);
	gamma.blue = cfg.get_number(L"/gdipp/client/paint/gamma/blue/text()", gamma.blue);
	painter = static_cast<client_config::PAINTER_TYPE>(cfg.get_number(L"/gdipp/client/paint/painter/text()", static_cast<int>(painter)));
	pixel_geometry = static_cast<client_config::PIXEL_GEOMETRY_TYPE>(cfg.get_number(L"/gdipp/client/paint/pixel_geometry/text()", static_cast<int>(pixel_geometry)));
	shadow.offset_x = cfg.get_number(L"/gdipp/client/paint/shadow/offset_x/text()", shadow.offset_x);
	shadow.offset_y = cfg.get_number(L"/gdipp/client/paint/shadow/offset_y/text()", shadow.offset_y);
	shadow.alpha = cfg.get_number(L"/gdipp/client/paint/shadow/alpha/text()", static_cast<int>(shadow.alpha));
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_config/client_config_static.h:
namespace gdipp
{

class GDIPP_API client_config_static
{
public:
	struct gamma_static
	{
		gamma_static();

		double red;
		double green;
		double blue;
	};

	struct shadow_static
	{
		shadow_static();

		int offset_x;
		int offset_y;
		unsigned char alpha;
	};

public:
	client_config_static();
	void parse(const config &cfg);

	gamma_static gamma;
	client_config::PAINTER_TYPE painter;
	client_config::PIXEL_GEOMETRY_TYPE pixel_geometry;
	shadow_static shadow;
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_config/config.cpp:
namespace gdipp
{

config::config(const config_file &config_file)
{
	if (config_file.empty())
		_root_node = NULL;
	else
		_root_node = config_file.get_config_xml();
}

config::config(const void *root_node)
	: _root_node(root_node)
{
}

const wchar_t *config::get_string(const wchar_t *config_path, const wchar_t *default_value) const
{
	if (_root_node == NULL)
		return NULL;

	const pugi::xml_node config_node = reinterpret_cast<const pugi::xml_document *>(_root_node)->select_single_node(config_path).node();
	if (config_node.empty())
		return default_value;

	return config_node.value();
}

size_t config::get_string_list(const wchar_t *config_path, const wchar_t **list_values) const
{
	if (_root_node == NULL)
		return 0;

	const pugi::xpath_node_set config_nodes = reinterpret_cast<const pugi::xml_document *>(_root_node)->select_nodes(config_path);
	const size_t config_node_count = config_nodes.size();
	if (list_values == NULL)
		return config_node_count;

	pugi::xpath_node_set::const_iterator iter;
	size_t i;
	for (iter = config_nodes.begin(), i = 0; iter != config_nodes.end(); ++iter, ++i)
		list_values[i] = iter->node().value();

	return config_node_count;
}

template<typename T>
T config::get_number(const wchar_t *config_path, T default_value) const
{
	if (_root_node == NULL)
		return default_value;

	const pugi::xml_node config_node = reinterpret_cast<const pugi::xml_document *>(_root_node)->select_single_node(config_path).node();
	if (config_node.empty())
		return default_value;

	T config_value;
	wcs_convert(config_node.value(), &config_value);
	return config_value;
}

template<typename T>
size_t config::get_number_list(const wchar_t *config_path, T *list_values) const
{
	if (_root_node == NULL)
		return 0;

	const pugi::xpath_node_set config_nodes = reinterpret_cast<const pugi::xml_document *>(_root_node)->select_nodes(config_path);
	const size_t config_node_count = config_nodes.size();
	if (list_values == NULL)
		return config_node_count;

	pugi::xpath_node_set::const_iterator iter;
	size_t i;
	for (iter = config_nodes.begin(), i = 0; iter != config_nodes.end(); ++iter, ++i)
		wcs_convert(iter->node().value(), &list_values[i]);

	return config_node_count;
}

template GDIPP_API int config::get_number(const wchar_t *, int) const;
template GDIPP_API unsigned int config::get_number(const wchar_t *, unsigned int) const;
template long config::get_number(const wchar_t *, long) const;
template double config::get_number(const wchar_t *, double) const;

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_config/config.h:
namespace gdipp
{

class GDIPP_API config
{
public:
	config(const config_file &config_file);
	config(const void *root_node);

	const wchar_t *get_string(const wchar_t *config_path, const wchar_t *default_value) const;
	size_t get_string_list(const wchar_t *config_path, const wchar_t **list_values) const;

	template<typename T>
	T get_number(const wchar_t *config_path, T default_value) const;
	template<typename T>
	size_t get_number_list(const wchar_t *config_path, T *list_values) const;

private:
	const void *_root_node;
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_config/config_file.cpp:
namespace gdipp
{

config_file::config_file(const wchar_t *filename)
	: _config_xml(NULL)
{
	// get config file path
	wchar_t config_path[MAX_PATH];
	if (!get_dir_file_path(NULL, filename, config_path))
		return;

	pugi::xml_document *config_xml_doc = new pugi::xml_document();
	_config_xml = config_xml_doc;

	config_xml_doc->load_file(config_path);
}

config_file::~config_file()
{
	if (_config_xml != NULL)
		delete _config_xml;
}

const void *config_file::get_config_xml() const
{
	return _config_xml;
}

bool config_file::empty() const
{
	if (_config_xml == NULL)
		return true;

	pugi::xml_document *config_xml_doc = reinterpret_cast<pugi::xml_document *>(_config_xml);
	return config_xml_doc->empty();
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_config/config_file.h:
namespace gdipp
{

class GDIPP_API config_file
{
public:
	config_file(const wchar_t *filename);
	~config_file();

	const void *get_config_xml() const;
	bool empty() const;

private:
	void *_config_xml;
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_config/constant_client.h:
namespace gdipp
{
namespace client_config
{

enum PIXEL_GEOMETRY_TYPE
{
	PIXEL_GEOMETRY_RGB,
	PIXEL_GEOMETRY_BGR
};

enum PAINTER_TYPE
{
	PAINTER_GDI = 10,
	PAINTER_D2D = 20
};

static const double GAMMA_RED = 1.0;
static const double GAMMA_GREEN = 1.0;
static const double GAMMA_BLUE = 1.0;
static const PAINTER_TYPE PAINTER = PAINTER_GDI;
static const PIXEL_GEOMETRY_TYPE PIXEL_GEOMETRY = PIXEL_GEOMETRY_RGB;
static const int SHADOW_OFFSET_X = 0;
static const int SHADOW_OFFSET_Y = 0;
static const unsigned char SHADOW_ALPHA = 0;

}
}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_config/constant_demo.h:
namespace gdipp
{
namespace demo_config
{

static const unsigned int CYCLES = 5000;
static const unsigned char THREADS = 1;
static const bool RANDOM_TEXT = false;

}
}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_config/constant_hook.h:
namespace gdipp
{
namespace hook_config
{

static const bool PROC_32_BIT = true;
static const bool PROC_64_BIT = true;

}
}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_config/constant_server.h:
namespace gdipp
{
namespace server_config
{

enum RENDERER_TYPE
{
	RENDERER_CLEARTYPE = 0,
	RENDERER_FREETYPE = 10,
	RENDERER_GETGLYPHOUTLINE = 20,
	RENDERER_DIRECTWRITE = 30,
	RENDERER_WIC = 31
};

static const unsigned char AUTO_HINTING = 1;
static const unsigned int CACHE_SIZE = 8;
static const bool EMBEDDED_BITMAP = false;
static const long EMBOLDEN = 0;
static const FT_LcdFilter LCD_FILTER = FT_LCD_FILTER_DEFAULT;
static const unsigned char HINTING = 1;
static const bool KERNING = false;
static const unsigned char RENDER_MODE_MONO = 0;
static const unsigned char RENDER_MODE_GRAY = 1;
static const unsigned char RENDER_MODE_SUBPIXEL = 1;
static const bool RENDER_MODE_ALIASED = false;
static const RENDERER_TYPE RENDERER = RENDERER_FREETYPE;

}
}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_config/exclude_config.cpp:
namespace gdipp
{

bool exclude_config::is_process_excluded(const config &cfg, const wchar_t *proc_name)
{
	if (proc_name == NULL)
		return false;

	const wchar_t *exclude_path = L"/gdipp/client/exclude/process/text()";
	size_t process_count = cfg.get_string_list(exclude_path, NULL);
	if (process_count == 0)
		return false;

	const wchar_t **processes = new const wchar_t *[process_count];
	process_count = cfg.get_string_list(exclude_path, processes);
	assert(process_count > 0);

	bool is_excluded = false;
	for (size_t i = 0; i < process_count; ++i)
	{
		const std::tr1::wregex proc_name_regex(processes[i],
			std::tr1::regex_constants::icase | std::tr1::regex_constants::nosubs | std::tr1::regex_constants::optimize);
		if (regex_match(proc_name, proc_name_regex))
		{
			is_excluded = true;
			break;
		}
	}

	delete[] processes;

	return is_excluded;
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_config/exclude_config.h:
namespace gdipp
{

class GDIPP_API exclude_config
{
public:
	static bool is_process_excluded(const config &cfg, const wchar_t *proc_name);
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_config/font_config_criteria.cpp:
namespace gdipp
{

font_config_criteria::font_config_criteria(const void *node)
	: _bold(-1),
	_italic(-1),
	_max_height(-1)
{
	if (node == NULL)
		return;

	const pugi::xml_node *node_ptr = reinterpret_cast<const pugi::xml_node *>(node);
	if (node_ptr->empty())
		return;

	pugi::xml_attribute attr;
	
	attr = node_ptr->attribute(L"bold");
	if (!attr.empty())
		wcs_convert(attr.value(), reinterpret_cast<short *>(&_bold));

	attr = node_ptr->attribute(L"italic");
	if (!attr.empty())
		wcs_convert(attr.value(), reinterpret_cast<short *>(&_italic));

	attr = node_ptr->attribute(L"max_height");
	if (!attr.empty())
		wcs_convert(attr.value(), &_max_height);

	attr = node_ptr->attribute(L"name");
	if (!attr.empty())
		_font_name = attr.value();
}

bool font_config_criteria::is_satisfied(bool bold, bool italic, LONG height, const wchar_t *font_name) const
{
	if (_bold >= 0 && (!_bold == bold))
		return false;

	if (_italic >= 0 && (!_italic == italic))
		return false;

	if (_max_height >= 0 && (_max_height < height))
		return false;

	if (!_font_name.empty())
	{
		const std::tr1::wregex font_name_regex(_font_name,
			std::tr1::regex_constants::icase | std::tr1::regex_constants::nosubs | std::tr1::regex_constants::optimize);
		return regex_match(font_name, font_name_regex);
	}

	return true;
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_config/font_config_criteria.h:
namespace gdipp
{

class font_config_criteria
{
public:
	font_config_criteria(const void *node);
	bool is_satisfied(bool bold, bool italic, LONG height, const wchar_t *font_name) const;

private:
	char _bold;
	char _italic;
	LONG _max_height;
	std::wstring _font_name;
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_config/proc_config_criteria.cpp:
namespace gdipp
{

proc_config_criteria::proc_config_criteria(const void *node)
{
	if (node == NULL)
		return;

	const pugi::xml_node *node_ptr = reinterpret_cast<const pugi::xml_node *>(node);
	if (node_ptr->empty())
		return;

	pugi::xml_attribute attr;
	
	attr = node_ptr->attribute(L"name");
	if (!attr.empty())
		_proc_name = attr.value();
}

bool proc_config_criteria::is_satisfied(const wchar_t *proc_name) const
{
	if (!_proc_name.empty())
	{
		const std::tr1::wregex font_name_regex(_proc_name,
			std::tr1::regex_constants::icase | std::tr1::regex_constants::nosubs | std::tr1::regex_constants::optimize);
		return regex_match(proc_name, font_name_regex);
	}

	return true;
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_config/proc_config_criteria.h:
namespace gdipp
{

class proc_config_criteria
{
public:
	proc_config_criteria(const void *node);
	bool is_satisfied(const wchar_t *proc_name) const;

private:
	std::wstring _proc_name;
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_config/render_config_cache.cpp:
namespace gdipp
{

render_config_cache::render_config_cache(const config_file &file)
{
	if (file.empty())
		return;

	const pugi::xml_document *config_xml_doc = reinterpret_cast<const pugi::xml_document *>(file.get_config_xml());
	const pugi::xpath_node_set render_font_nodes = config_xml_doc->select_nodes(L"/gdipp/server/render/font");
	for (pugi::xpath_node_set::const_iterator node_iter = render_font_nodes.begin(); node_iter != render_font_nodes.end(); ++node_iter)
	{
		const pugi::xml_node curr_node = node_iter->node();
		const config cfg(&curr_node);
		const font_config_criteria curr_criteria(&curr_node);
		render_config_static *curr_rcs = new render_config_static();
		curr_rcs->parse(cfg);
		_configs.push_back(std::pair<font_config_criteria, const render_config_static *>(curr_criteria, curr_rcs));			
	}

	_default_config = new render_config_static();
}

render_config_cache::~render_config_cache()
{
	delete _default_config;

	for (std::list<std::pair<font_config_criteria, const render_config_static *>>::const_iterator config_iter = _configs.begin();
		config_iter != _configs.end();
		++config_iter)
		delete config_iter->second;
}

const render_config_static *render_config_cache::get_font_render_config(bool bold, bool italic, LONG height, const wchar_t *font_name)
{
	const uint32_t trait = get_render_config_trait(bold, italic, height, font_name);
	std::map<uint32_t, const render_config_static *>::const_iterator config_iter = _cache.find(trait);
	if (config_iter == _cache.end())
	{
		const scoped_rw_lock lock_w(scoped_rw_lock::CONFIG_RENDER_CACHE, false);
		config_iter = _cache.find(trait);
		if (config_iter == _cache.end())
		{
			const render_config_static *rcs = find_font_render_config(bold, italic, height, font_name);
			if (rcs == NULL)
				rcs = _default_config;
			_cache.insert(std::pair<uint32_t, const render_config_static *>(trait, rcs));
			return rcs;
		}
	}
	
	return config_iter->second;
}

const render_config_static *render_config_cache::find_font_render_config(bool bold, bool italic, LONG height, const wchar_t *font_name) const
{
	for (std::list<std::pair<font_config_criteria, const render_config_static *>>::const_iterator config_iter = _configs.begin();
		config_iter != _configs.end();
		++config_iter)
	{
		if (config_iter->first.is_satisfied(bold, italic, height, font_name))
			return config_iter->second;
	}

	return NULL;
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_config/render_config_cache.h:
namespace gdipp
{

class GDIPP_API render_config_cache
{
public:
	render_config_cache(const config_file &file);
	~render_config_cache();
	const render_config_static *get_font_render_config(bool bold, bool italic, LONG height, const wchar_t *font_name);

private:
	// if the font does not exist in the cache, this function is called to find a render config that matches the criteria
	const render_config_static *find_font_render_config(bool bold, bool italic, LONG height, const wchar_t *font_name) const;

	const render_config_static *_default_config;
	std::map<uint32_t, const render_config_static *> _cache;
	std::list<std::pair<font_config_criteria, const render_config_static*>> _configs;
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_config/render_config_delta.cpp:
namespace gdipp
{

void render_config_delta::load(const config_file &file)
{
	assert(false);
}

void render_config_delta::parse(const void *root)
{
	if (root == NULL)
		return;

	const pugi::xml_node *root_node = reinterpret_cast<const pugi::xml_node *>(root);
	if (root_node->empty())
		return;

	// TODO:
	for (pugi::xml_node::iterator child_iter = root_node->begin(); child_iter != root_node->end(); ++child_iter)
	{
		
	}
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_config/render_config_delta.h:
namespace gdipp
{

class GDIPP_API render_config_delta
{
	friend class render_config_delta_cache;

public:
	void load(const config_file &file);

	std::wstring config_delta;

private:
	void parse(const void *root);
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_config/render_config_delta_cache.cpp:
namespace gdipp
{

render_config_delta_cache::render_config_delta_cache(const config_file &file)
{
	if (file.empty())
		return;

	const pugi::xml_document *config_xml_doc = reinterpret_cast<const pugi::xml_document *>(file.get_config_xml());
	const pugi::xpath_node_set font_render_font_nodes = config_xml_doc->select_nodes(L"/gdipp/server/render/font");
	for (pugi::xpath_node_set::const_iterator node_iter = font_render_font_nodes.begin(); node_iter != font_render_font_nodes.end(); ++node_iter)
	{
		const pugi::xml_node curr_node = node_iter->node();
		font_config_criteria curr_criteria(&curr_node);
		render_config_delta curr_config_delta;
		curr_config_delta.parse(&curr_node);
		_font_config_deltas.push_front(std::pair<font_config_criteria, render_config_delta>(curr_criteria, curr_config_delta));			
	}

	const pugi::xpath_node_set proc_render_font_nodes = config_xml_doc->select_nodes(L"/gdipp/server/render/process");
	for (pugi::xpath_node_set::const_iterator node_iter = proc_render_font_nodes.begin(); node_iter != proc_render_font_nodes.end(); ++node_iter)
	{
		const pugi::xml_node curr_node = node_iter->node();
		proc_config_criteria curr_criteria(&curr_node);
		render_config_delta curr_config_delta;
		curr_config_delta.parse(&curr_node);
		_proc_config_deltas.push_front(std::pair<proc_config_criteria, render_config_delta>(curr_criteria, curr_config_delta));			
	}
}

render_config_delta render_config_delta_cache::get_font_render_config_delta(bool bold, bool italic, LONG height, const wchar_t *font_name)
{
	const render_config_delta *rcd;

	const uint32_t trait = get_render_config_trait(bold, italic, height, font_name);
	std::map<uint32_t, const render_config_delta *>::const_iterator config_iter = _cache.find(trait);
	if (config_iter == _cache.end())
	{
		const scoped_rw_lock lock_w(scoped_rw_lock::CONFIG_RENDER_CONFIG_DELTA_CACHE, false);
		config_iter = _cache.find(trait);
		if (config_iter == _cache.end())
		{
			rcd = find_font_render_config_delta(bold, italic, height, font_name);
			_cache.insert(std::pair<uint32_t, const render_config_delta *>(trait, rcd));
		}
		else
		{
			rcd = config_iter->second;
		}
	}
	else
	{
		rcd = config_iter->second;
	}

	if (rcd == NULL)
		return render_config_delta();
	else
		return *rcd;
}

render_config_delta render_config_delta_cache::get_proc_render_config_delta(const wchar_t *proc_name)
{
	for (std::list<std::pair<proc_config_criteria, render_config_delta>>::const_iterator config_iter = _proc_config_deltas.begin();
		config_iter != _proc_config_deltas.end();
		++config_iter)
	{
		if (config_iter->first.is_satisfied(proc_name))
			return config_iter->second;
	}

	return render_config_delta();
}

const render_config_delta *render_config_delta_cache::find_font_render_config_delta(bool bold, bool italic, LONG height, const wchar_t *font_name) const
{
	for (std::list<std::pair<font_config_criteria, render_config_delta>>::const_iterator config_iter = _font_config_deltas.begin();
		config_iter != _font_config_deltas.end();
		++config_iter)
	{
		if (config_iter->first.is_satisfied(bold, italic, height, font_name))
			return &config_iter->second;
	}

	return NULL;
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_config/render_config_delta_cache.h:
namespace gdipp
{

class GDIPP_API render_config_delta_cache
{
public:
	render_config_delta_cache(const config_file &file);
	render_config_delta get_font_render_config_delta(bool bold, bool italic, LONG height, const wchar_t *font_name);
	render_config_delta get_proc_render_config_delta(const wchar_t *proc_name);

private:
	// if the font does not exist in the cache, this function is called to find a render config that matches the criteria
	const render_config_delta *find_font_render_config_delta(bool bold, bool italic, LONG height, const wchar_t *font_name) const;

	std::map<uint32_t, const render_config_delta *> _cache;
	std::list<std::pair<font_config_criteria, render_config_delta>> _font_config_deltas;
	std::list<std::pair<proc_config_criteria, render_config_delta>> _proc_config_deltas;
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_config/render_config_static.cpp:
namespace gdipp
{

render_config_static::render_mode_static::render_mode_static()
	: mono(server_config::RENDER_MODE_MONO),
	gray(server_config::RENDER_MODE_GRAY),
	subpixel(server_config::RENDER_MODE_SUBPIXEL),
	aliased(server_config::RENDER_MODE_ALIASED)
{
}

render_config_static::render_config_static()
	: auto_hinting(server_config::AUTO_HINTING),
	embedded_bitmap(server_config::EMBEDDED_BITMAP),
	embolden(server_config::EMBOLDEN),
	hinting(server_config::HINTING),
	kerning(server_config::KERNING),
	renderer(server_config::RENDERER)
{
}

void render_config_static::parse(const config &cfg)
{
	auto_hinting = cfg.get_number(L"auto_hinting/text()", static_cast<unsigned int>(auto_hinting));
	embedded_bitmap = (!!cfg.get_number(L"embedded_bitmap/text()", static_cast<int>(embedded_bitmap)));
	embolden = cfg.get_number(L"embolden/text()", embolden);
	hinting = cfg.get_number(L"hinting/text()", static_cast<unsigned int>(hinting));
	kerning = (!!cfg.get_number(L"kerning/text()", static_cast<int>(kerning)));
	render_mode.mono = cfg.get_number(L"render_mode/mono/text()", static_cast<unsigned int>(render_mode.mono));
	render_mode.gray = cfg.get_number(L"render_mode/gray/text()", static_cast<unsigned int>(render_mode.gray));
	render_mode.subpixel = cfg.get_number(L"render_mode/subpixel/text()", static_cast<unsigned int>(render_mode.subpixel));
	render_mode.aliased = (!!cfg.get_number(L"render_mode/aliased_text/text()", static_cast<int>(render_mode.aliased)));
	renderer = static_cast<server_config::RENDERER_TYPE>(cfg.get_number(L"renderer/text()", static_cast<int>(renderer)));
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_config/render_config_static.h:
namespace gdipp
{

class GDIPP_API render_config_static
{
public:
	struct GDIPP_API render_mode_static
	{
		render_mode_static();

		unsigned char mono;
		unsigned char gray;
		unsigned char subpixel;
		bool aliased;
	};

public:
	render_config_static();
	void parse(const config &cfg);

	unsigned char auto_hinting;
	bool embedded_bitmap;
	long embolden;
	unsigned char hinting;
	bool kerning;
	render_mode_static render_mode;
	server_config::RENDERER_TYPE renderer;
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_demo/demo_painter.cpp:
namespace gdipp
{

demo_painter::demo_painter()
	: _demo_fonts(NULL),
	_painted_cycles(0),
	_result_prepared(false),
	_result_font(NULL)
{
	srand(GetTickCount());

	_demo_font_count = config_instance.get_string_list(L"/gdipp/demo/fonts/font/text()", NULL);
	if (_demo_font_count > 0)
	{
		_demo_fonts = new const wchar_t *[_demo_font_count];
		_demo_font_count = config_instance.get_string_list(L"/gdipp/demo/fonts/font/text()", _demo_fonts);
		assert(_demo_font_count > 0);
	}

	_random_text = !!config_instance.get_number(L"/gdipp/demo/random_text/text()", static_cast<int>(demo_config::RANDOM_TEXT));
	_total_cycles = config_instance.get_number(L"/gdipp/demo/cycles/text()", demo_config::CYCLES);
}

demo_painter::~demo_painter()
{
	if (_demo_fonts != NULL)
		delete[] _demo_fonts;

	if (_result_font != NULL)
		DeleteObject(_result_font);
}

void demo_painter::paint_demo(CPaintDC &dc)
{
	BOOL b_ret;

	if (_demo_font_count == 0)
		return;

	if (_painted_cycles == 0)
		_start_time = GetTickCount();

	if (_painted_cycles < _total_cycles)
	{
		// randomize text metrics
		const LONG text_height = (rand() % 10) + 9;
		const LONG text_weight = (rand() % 8 + 1) * 100;
		const BYTE text_italic = rand() % 2;
		const wchar_t *font_name = _demo_fonts[rand() % _demo_font_count];

		const HFONT curr_dc_font = CreateFont(-text_height, 0, 0, 0, text_weight, text_italic, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, font_name);
		assert(curr_dc_font != NULL);
		dc.SelectFont(curr_dc_font);

		// randomize text color
		dc.SetTextColor(RGB(rand() % 256, rand() % 256, rand() % 256));

		// randomize text background
		const int bk_mode = rand() % 2 + 1;
		dc.SetBkMode(bk_mode);
		if (bk_mode == OPAQUE)
			dc.SetBkColor(RGB(rand() % 256, rand() % 256, rand() % 256));

		std::wstring paint_str;

		// if randomize text content, use random Unicode characters
		// otherwise use the font name
		if (_random_text)
		{
			const int max_text_len = 10;
			paint_str.resize(rand() % max_text_len + 1);

			for (size_t i = 0; i < paint_str.size(); ++i)
			{
				int chr;
				do
				{
					chr = rand();
				} while (iswcntrl(chr));

				paint_str[i] = chr;
			}
		}
		else
			paint_str = font_name;

		SIZE text_extent = {};
		b_ret = dc.GetTextExtent(paint_str.c_str(), static_cast<int>(paint_str.size()), &text_extent);
		assert(b_ret);

		// randomize text position
		const int x = rand() % (dc.m_ps.rcPaint.right - dc.m_ps.rcPaint.left - text_extent.cx);
		const int y = rand() % (dc.m_ps.rcPaint.bottom - dc.m_ps.rcPaint.top - text_extent.cy);

		b_ret = dc.ExtTextOut(x, y, 0, NULL, paint_str.c_str(), static_cast<UINT>(paint_str.size()), NULL);
		assert(b_ret);

		dc.GetCurrentFont().DeleteObject();

		_painted_cycles += 1;

		// show the rendered text count in the window title
		wchar_t new_title[GDIPP_DEMO_MAX_STR_LEN];
		wsprintf(new_title, TEXT("Paint - %u"), _painted_cycles);
		SetWindowText(dc.m_hWnd, new_title);

		// force redraw the client rect
		InvalidateRect(dc.m_hWnd, NULL, FALSE);
	}
	else
	{
		if (!_result_prepared)
		{
			const DWORD elapse_time = GetTickCount() - _start_time;
			swprintf(_result_str, GDIPP_DEMO_MAX_STR_LEN, L"%u milliseconds render time, %.2f ms per text run", elapse_time, static_cast<float>(elapse_time) / _painted_cycles);

			dc.FillRect(&dc.m_ps.rcPaint, COLOR_BTNFACE);

			_result_font = CreateFontW(-20, 0, 0, 0, FW_REGULAR, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, L"Tahoma");

			_result_prepared = true;
		}

		dc.SetTextColor(RGB(0x20, 0x80, 0x40));
		dc.SetBkColor(GetSysColor(COLOR_BTNFACE));
		dc.SetBkMode(OPAQUE);
		dc.SetTextAlign(TA_LEFT | TA_TOP);
		dc.SelectFont(_result_font);
		dc.ExtTextOut(10, 10, 0, NULL, _result_str, static_cast<UINT>(wcslen(_result_str)), NULL);

		ValidateRect(dc.m_hWnd, NULL);
	}
}

void demo_painter::stop_painting()
{
	_total_cycles = -1;
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_demo/demo_painter.h:
namespace gdipp
{

#define GDIPP_DEMO_MAX_STR_LEN 100

class demo_painter
{
public:
	demo_painter();
	~demo_painter();

	void paint_demo(CPaintDC &dc);
	void stop_painting();

private:
	size_t _demo_font_count;
	const wchar_t **_demo_fonts;
	bool _random_text;
	int _total_cycles;

	// multi-thread related
	std::vector<HANDLE> _start_render_events;
	std::vector<HANDLE> _complete_render_events;
	std::vector<HANDLE> _render_threads;

	// result text related
	bool _result_prepared;
	HFONT _result_font;
	wchar_t _result_str[GDIPP_DEMO_MAX_STR_LEN];

	int _painted_cycles;
	DWORD _start_time;
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_demo/global.cpp:
namespace gdipp
{

config_file config_file_instance(L"demo.conf");
config config_instance(config_file_instance);

HMODULE gdipp::h_client = NULL;
WCHAR client_path[MAX_PATH];
std::vector<HWND> paint_hwnd;

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_demo/global.h:
namespace gdipp
{

extern config_file config_file_instance;
extern config config_instance;

// client related
extern HMODULE h_client;
extern WCHAR client_path[MAX_PATH];
extern std::vector<HWND> paint_hwnd;

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_lib/debug.cpp:
namespace gdipp
{

const wchar_t *debug_file_name = L"C:\\gdipp_debug.log";

void debug_buffer(const void *ptr, unsigned int size)
{
	FILE *f;
	_wfopen_s(&f, debug_file_name, L"a+");

	if (f != NULL)
	{
		fwrite(ptr, 1, size, f);
		fclose(f);
	}
}

void debug_decimal(double num, bool new_line)
{
	FILE *f;
	_wfopen_s(&f, debug_file_name, L"a+");

	if (f != NULL)
	{
		if (new_line)
			fwprintf(f, L"%f\n", num);
		else
			fwprintf(f, L"%f, ", num);
		fclose(f);
	}
}

void debug_integer(size_t num, bool new_line)
{
	FILE *f;
	_wfopen_s(&f, debug_file_name, L"a+");

	if (f != NULL)
	{
		if (new_line)
			fwprintf(f, L"%u\n", num);
		else
			fwprintf(f, L"%u, ", num);
		fclose(f);
	}
}

void debug_string(const wchar_t *str, bool new_line)
{
	FILE *f;
	_wfopen_s(&f, debug_file_name, L"a+");

	if (f != NULL)
	{
		if (new_line)
			fwprintf(f, L"%s\n", str);
		else
			fwprintf(f, L"%s", str);
		fclose(f);
	}
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_lib/debug.h:
namespace gdipp
{

GDIPP_API void debug_buffer(const void *ptr, unsigned int size);
GDIPP_API void debug_decimal(double num, bool new_line = true);
GDIPP_API void debug_integer(size_t num, bool new_line = true);
GDIPP_API void debug_string(const wchar_t *str = L"", bool new_line = true);

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_lib/gdipp_lib.cpp:
namespace gdipp
{

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		register_minidump_module(hModule);
		break;
	}

	return TRUE;
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_lib/helper.cpp:
namespace gdipp
{

bool wstring_ci_less::operator()(const std::wstring &string1, const std::wstring &string2) const
{
	return (_wcsicmp(string1.c_str(), string2.c_str()) < 0);
}

BOOL get_dir_file_path(HMODULE h_module, const wchar_t *file_name, wchar_t *out_path)
{
	// append the file name after the module's resident directory name
	// if the module handle is NULL, use the current exe as the module

	DWORD dw_ret;
	BOOL b_ret;

	dw_ret = GetModuleFileNameW(h_module, out_path, MAX_PATH);
	if (dw_ret == 0)
		return FALSE;

	b_ret = PathRemoveFileSpecW(out_path);
	if (!b_ret)
		return FALSE;

	return PathAppendW(out_path, file_name);
}

void init_minidump()
{
	SetUnhandledExceptionFilter(minidump_filter);
}

void register_minidump_module(HMODULE h_module)
{
	h_minidump_modules.push_back(h_module);
}

char get_gdi_weight_class(unsigned short weight)
{
	
	// emulate GDI behavior:
	// weight 1 to 550 are rendered as Regular
	// 551 to 611 are Semibold
	// 612 to infinity are Bold

	// weight 0 is DONTCARE
	

	const long weight_class_max[] = {0, 550, 611};
	const char max_weight_class = sizeof(weight_class_max) / sizeof(long);

	for (char i = 0; i < max_weight_class; ++i)
	{
		if (weight <= weight_class_max[i])
			return i;
	}

	return max_weight_class;
}

unsigned long get_render_config_trait(char weight_class, bool italic, LONG height, const wchar_t *font_name)
{
	const size_t font_name_len = wcslen(font_name) + 1;
	const size_t trait_size = sizeof(weight_class) + sizeof(italic) + sizeof(height) + font_name_len * sizeof(wchar_t);
	BYTE *trait_data = new BYTE[trait_size];

	*reinterpret_cast<char *>(trait_data) = weight_class;
	*reinterpret_cast<bool *>(trait_data + sizeof(char)) = italic;
	*reinterpret_cast<LONG *>(trait_data + sizeof(char) + sizeof(bool)) = height;
	wcscpy_s(reinterpret_cast<wchar_t *>(trait_data + sizeof(char) + sizeof(bool) + sizeof(LONG)), font_name_len, font_name);

	unsigned long trait_id;
	MurmurHash3_x86_32(trait_data, static_cast<int>(trait_size), 0, &trait_id);
	delete[] trait_data;

	return trait_id;
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_lib/helper.h:
namespace gdipp
{

// convert a string to template value if possible
// helper function to convert raw config strings to values
template<typename T>
void wcs_convert(const wchar_t *str, T *converted)
{
	if (str != NULL)
		std::wistringstream(str) >> *converted;
}

struct GDIPP_API wstring_ci_less
{
	bool operator()(const std::wstring &string1, const std::wstring &string2) const;
};

GDIPP_API BOOL get_dir_file_path(HMODULE h_module, const wchar_t *file_name, wchar_t *out_path);

GDIPP_API void init_minidump();
GDIPP_API void register_minidump_module(HMODULE h_module);

GDIPP_API char get_gdi_weight_class(unsigned short weight);

// generate hash of traits for the specified font configuration
// returned integer is used as key of configuration map
GDIPP_API unsigned long get_render_config_trait(char weight_class, bool italic, LONG height, const wchar_t *font_name);

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_lib/lru.h:
namespace gdipp
{

template<typename T>
class lru_list
{
public:
	lru_list()
		: _capacity(1)
	{
	}

	explicit lru_list(unsigned int capacity)
		: _capacity(capacity)
	{
	}

	void resize(unsigned int new_capacity)
	{
		_capacity = new_capacity;
	}

	bool access(const T data, T *erased)
	{
		bool overflow = false;

		const scoped_rw_lock lock_w(scoped_rw_lock::LIB_LRU, false);

		_map_type::iterator data_iter = _data_map.find(data);
		if (data_iter == _data_map.end())
		{
			// data never accessed

			if (_data_map.size() == _capacity && _capacity > 0)
			{
				// list is full
				// erase and return the last accessed data
				erased = &_access_list.back();
				_access_list.pop_back();
				_data_map.erase(*erased);
				overflow = true;
			}

			// add the data to the most recent position
			_access_list.push_front(data);
			_data_map[data] = _access_list.begin();
		}
		else
		{
			// data accessed before
			// move it to the most recent position
			_list_iter_type node = data_iter->second;

			if (node != _access_list.begin())
				_access_list.splice(_access_list.begin(), _access_list, node);
		}

		return overflow;
	}

private:
	typedef typename std::list<T> _list_type;
	typedef typename _list_type::iterator _list_iter_type;
	typedef typename std::map<T, _list_iter_type> _map_type;

	_list_type _access_list;
	_map_type _data_map;
	unsigned int _capacity;
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_lib/minidump.cpp:
namespace gdipp
{

std::vector<HMODULE> h_minidump_modules;

BOOL WINAPI minidump_callback(IN PVOID CallbackParam,
	IN CONST PMINIDUMP_CALLBACK_INPUT CallbackInput,
	IN OUT PMINIDUMP_CALLBACK_OUTPUT CallbackOutput)
{
	switch (CallbackInput->CallbackType)
	{
	case IncludeModuleCallback:
		{
			for (std::vector<HMODULE>::const_iterator iter = h_minidump_modules.begin(); iter != h_minidump_modules.end(); ++iter)
			{
				if (*iter == reinterpret_cast<HMODULE>(CallbackInput->IncludeModule.BaseOfImage))
					return TRUE;
			}

			return FALSE;
		}
	case IncludeThreadCallback:
		{
			return (CallbackInput->IncludeThread.ThreadId == GetCurrentThreadId());
		}
	default:
		return TRUE;
	}
}

LONG WINAPI minidump_filter(EXCEPTION_POINTERS *ExceptionInfo)
{	if (h_minidump_modules.empty())
		return 0;

	BOOL b_ret;

	bool ex_in_module = false;
	for (std::vector<HMODULE>::const_iterator iter = h_minidump_modules.begin(); iter != h_minidump_modules.end(); ++iter)
	{
		MODULEINFO mod_info;
		b_ret = GetModuleInformation(GetCurrentProcess(), *iter, &mod_info, sizeof(MODULEINFO));
		if (!b_ret)
			return EXCEPTION_CONTINUE_SEARCH;

		// exception not from this module
		if (ExceptionInfo->ExceptionRecord->ExceptionAddress >= mod_info.lpBaseOfDll &&
			reinterpret_cast<size_t>(ExceptionInfo->ExceptionRecord->ExceptionAddress) <= reinterpret_cast<size_t>(mod_info.lpBaseOfDll) + mod_info.SizeOfImage)
		{
			ex_in_module = true;
			break;
		}
	}

	if (!ex_in_module)
		return EXCEPTION_CONTINUE_SEARCH;

	// path of the crash dump is
	// [gdipp_directory]\[dmp_dir_name]\[crash_process_name]\[crash_time].dmp

	const time_t curr_time = time(NULL);
	struct tm curr_tm;
	errno_t er_ret = localtime_s(&curr_tm, &curr_time);
	if (er_ret != 0)
		return EXCEPTION_CONTINUE_SEARCH;

	const wchar_t *dmp_dir_name = L"crash_dump\\";
	wchar_t dmp_file_path[MAX_PATH];
	b_ret = get_dir_file_path(h_minidump_modules[0], dmp_dir_name, dmp_file_path);
	assert(b_ret);
	const size_t dmp_dir_len = wcslen(dmp_file_path);
	assert(dmp_dir_len < MAX_PATH);

	b_ret = CreateDirectoryW(dmp_file_path, NULL);
	assert(b_ret || GetLastError() == ERROR_ALREADY_EXISTS);

	const DWORD exe_name_len = GetModuleBaseNameW(GetCurrentProcess(), NULL, dmp_file_path + dmp_dir_len, MAX_PATH);
	if (exe_name_len == 0)
		return EXCEPTION_CONTINUE_SEARCH;

	b_ret = CreateDirectoryW(dmp_file_path, NULL);
	assert(b_ret || GetLastError() == ERROR_ALREADY_EXISTS);

	wcsftime(dmp_file_path + dmp_dir_len + exe_name_len, MAX_PATH - dmp_dir_len - exe_name_len, L"\\%Y-%m-%d_%H-%M-%S.dmp", &curr_tm);

	// exception information is necessary for stack trace in the minidump
	MINIDUMP_EXCEPTION_INFORMATION ex_info = {GetCurrentThreadId(), ExceptionInfo, FALSE};

	const HANDLE dmp_file = CreateFileW(dmp_file_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (dmp_file != INVALID_HANDLE_VALUE)
	{
		MINIDUMP_CALLBACK_INFORMATION ci = {minidump_callback, NULL};
		const MINIDUMP_TYPE dump_type = static_cast<const MINIDUMP_TYPE>(MiniDumpWithIndirectlyReferencedMemory | MiniDumpScanMemory | MiniDumpWithDataSegs | MiniDumpWithHandleData);
		MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), dmp_file, dump_type, &ex_info, NULL, &ci);
		CloseHandle(dmp_file);
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_lib/minidump.h:
namespace gdipp
{

extern std::vector<HMODULE> h_minidump_modules;

BOOL WINAPI minidump_callback(IN PVOID CallbackParam,
	IN CONST PMINIDUMP_CALLBACK_INPUT CallbackInput,
	IN OUT PMINIDUMP_CALLBACK_OUTPUT CallbackOutput);

LONG WINAPI minidump_filter(EXCEPTION_POINTERS *ExceptionInfo);

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_lib/rpc.h:
namespace gdipp
{

struct font_link_node
{
	std::wstring font_family;
	double scaling;
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_lib/scoped_rw_lock.cpp:
namespace gdipp
{

std::vector<SRWLOCK> scoped_rw_lock::_srws;

void scoped_rw_lock::initialize()
{
	_srws.resize(LAST_MONITOR_LOCATION);
	for (int i = 0; i < LAST_MONITOR_LOCATION; ++i)
		InitializeSRWLock(&_srws[i]);
}

scoped_rw_lock::scoped_rw_lock(MONITOR_LOCATION cs_location, bool is_shared)
{
	_curr_srw = &_srws[cs_location];
	_is_shared = is_shared;

	if (is_shared)
		AcquireSRWLockShared(_curr_srw);
	else
		AcquireSRWLockExclusive(_curr_srw);
}

scoped_rw_lock::~scoped_rw_lock()
{
	if (_is_shared)
		ReleaseSRWLockShared(_curr_srw);
	else
		ReleaseSRWLockExclusive(_curr_srw);
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_lib/scoped_rw_lock.h:
namespace gdipp
{

class GDIPP_API scoped_rw_lock
{
public:
	enum MONITOR_LOCATION
	{
		CLIENT_COM_HOOK,
		CLIENT_GAMMA,
		CONFIG_RENDER_CACHE,
		CONFIG_RENDER_CONFIG_DELTA_CACHE,
		GLOBAL_DEBUG,
		LIB_LRU,
		SERVER_DC_POOL,
		SERVER_FONT_MGR,
		SERVER_FREETYPE,
		SERVER_GLYPH_CACHE,
		SERVER_GLYPH_RUN_CACHE,

		LAST_MONITOR_LOCATION
	};

public:
	static void initialize();

	explicit scoped_rw_lock(MONITOR_LOCATION srw_location, bool is_shared);
	~scoped_rw_lock();

private:
	static std::vector<SRWLOCK> _srws;

	SRWLOCK *_curr_srw;
	bool _is_shared;
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_server/dc_pool.cpp:
namespace gdipp
{

dc_pool::~dc_pool()
{
	// TODO: change to blockingly wait until _busy.empty() is true
	assert(_busy.empty());

	BOOL b_ret;

	for (std::list<HDC>::const_iterator free_iter = _free.begin(); free_iter != _free.end(); ++free_iter)
	{
		b_ret = DeleteDC(*free_iter);
		assert(b_ret);
	}
}

HDC dc_pool::claim()
{
	// acquire a resource from the pool
	// if no resource exists, create one by calling create() of the template class
	// otherwise, remove one from the free resource set and add to busy set

	const scoped_rw_lock lock_w(scoped_rw_lock::SERVER_DC_POOL, false);

	HDC hdc;

	if (_free.empty())
	{
		hdc = CreateCompatibleDC(NULL);
	}
	else
	{
		hdc = _free.front();
		_free.pop_front();
	}
	_busy.insert(hdc);

	return hdc;
}

bool dc_pool::free(HDC hdc)
{
	// return claimed resource back to the pool

	const scoped_rw_lock lock_w(scoped_rw_lock::SERVER_DC_POOL, false);

	std::set<HDC>::const_iterator busy_iter = _busy.find(hdc);
	if (busy_iter == _busy.end())
		return false;

	_free.push_back(*busy_iter);
	_busy.erase(busy_iter);

	return true;
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_server/dc_pool.h:
namespace gdipp
{

class dc_pool
{
	// pool for managing costly and reusable HDCs
	// all operations are thread-safe

public:
	~dc_pool();
	HDC claim();
	bool free(HDC hdc);

private:
	// free HDCs are ready to be claimed
	// busy HDCs are claimed and being used
	std::list<HDC> _free;
	std::set<HDC> _busy;
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_server/font_link.cpp:
namespace gdipp
{

#define MAX_VALUE_NAME 1024

font_link::font_link()
{
	// read font linking information from registry, and store in std::map

	LONG l_ret;

	const wchar_t *Fonts = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Fonts";
	const wchar_t *FontLink = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontLink\\SystemLink";

	HKEY key_ft;
	l_ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, Fonts, 0, KEY_QUERY_VALUE, &key_ft);
	if (l_ret != ERROR_SUCCESS)
		return;

	HKEY key_fl;
	l_ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, FontLink, 0, KEY_QUERY_VALUE, &key_fl);
	if (l_ret != ERROR_SUCCESS)
	{
		l_ret = RegCloseKey(key_ft);
		return;
	}

	DWORD value_count;
	DWORD max_data_len;
	wchar_t value_name[MAX_VALUE_NAME];
	BYTE *value_data;

	// font file name -> font face name mapping
	std::map<std::wstring, std::wstring, wstring_ci_less> fonts_table;

	// get font_file_name -> font_face mapping from the "Fonts" registry key

	l_ret = RegQueryInfoKeyW(key_ft, NULL, NULL, NULL, NULL, NULL, NULL, &value_count, NULL, &max_data_len, NULL, NULL);
	assert(l_ret == ERROR_SUCCESS);

	// no font installed
	if (value_count == 0)
		return;

	// max_data_len is in BYTE
	value_data = static_cast<BYTE *>(HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, max_data_len));
	assert(value_data != NULL);

	for (DWORD i = 0; i < value_count; ++i)
	{
		DWORD name_len = MAX_VALUE_NAME;
		DWORD data_len = max_data_len;

		l_ret = RegEnumValueW(key_ft, i, value_name, &name_len, NULL, NULL, value_data, &data_len);
		assert(l_ret == ERROR_SUCCESS);

		std::wstring curr_face = value_name;
		std::wstring font_file = reinterpret_cast<wchar_t *>(value_data);
		curr_face = curr_face.substr(0, curr_face.find('(') - 1);
		fonts_table[font_file] = curr_face;
	}

	// get font_face -> font_file_name mapping from the "SystemLink" registry key
	// complete the font linking by composing the two mappings

	l_ret = RegQueryInfoKey(key_fl, NULL, NULL, NULL, NULL, NULL, NULL, &value_count, NULL, &max_data_len, NULL, NULL);
	assert(l_ret == ERROR_SUCCESS);

	// no font link information
	if (value_count == 0)
		return;

	value_data = static_cast<BYTE *>(HeapReAlloc(GetProcessHeap(), 0, value_data, max_data_len));
	assert(value_data != NULL);

	for (DWORD i = 0; i < value_count; ++i)
	{
		DWORD name_len = MAX_VALUE_NAME;
		DWORD data_len = max_data_len;

		l_ret = RegEnumValueW(key_fl, i, value_name, &name_len, NULL, NULL, value_data, &data_len);
		assert(l_ret == ERROR_SUCCESS);

		_link_table[value_name] = std::vector<font_link_node>();
		size_t line_start = 0;

		std::set<std::wstring, wstring_ci_less> curr_font_family_pool;

		while (line_start < data_len - sizeof(wchar_t))
		{
			font_link_node new_link;
			new_link.scaling = 1.0;

			wchar_t *curr_font = reinterpret_cast<wchar_t *>(value_data + line_start);

			// including the trailing '\0'
			line_start += (wcslen(curr_font) + 1) * sizeof(wchar_t);

			std::vector<wchar_t *> properties;
			wchar_t *curr_comma = curr_font - 1;
			while (curr_comma != NULL)
			{
				wchar_t *next_comma = wcschr(curr_comma + 1, L',');

				if (next_comma != NULL)
				{
					*next_comma = L'\0';
					properties.push_back(next_comma + 1);
				}

				curr_comma = next_comma;
			}

			// font family starts with alphabetic character

			size_t scaling_prop = properties.size();
			if (properties.empty() || !isalpha(*properties[0]))
			{
				// this is not a ttc file
				// lookup the Fonts table
				std::map<std::wstring, std::wstring, wstring_ci_less>::const_iterator iter = fonts_table.find(curr_font);
				if (iter != fonts_table.end())
					new_link.font_family = iter->second;

				scaling_prop = 0;
			}
			else if (isalpha(*properties[0]))
			{
				// this is a ttc file
				// use the specified font face
				if (fonts_table.find(curr_font) != fonts_table.end())
				{
					// trust the face name
					new_link.font_family = properties[0];
				}

				scaling_prop = 1;
			}

			if (scaling_prop + 2 == properties.size())
			{
				// scaling factors are provided
				// use only if both two factors are specified

				int factor1, factor2;
				std::wstringstream ss;

				ss << properties[scaling_prop];
				ss >> factor1;

				ss.clear();
				ss.str(L"");

				ss << properties[scaling_prop + 1];
				ss >> factor2;

				new_link.scaling = (factor1 / 128.0) * (96.0 / factor2);
			}

			if (!new_link.font_family.empty() && curr_font_family_pool.find(new_link.font_family) == curr_font_family_pool.end())
			{
				_link_table[value_name].push_back(new_link);
				curr_font_family_pool.insert(new_link.font_family);
			}
		}
	}

	HeapFree(GetProcessHeap(), 0, value_data);

	l_ret = RegCloseKey(key_ft);
	l_ret = RegCloseKey(key_fl);
}

const font_link_node *font_link::lookup_link(const wchar_t *font_name, size_t index) const
{
	const link_map::const_iterator iter = _link_table.find(font_name);

	if (iter == _link_table.end())
		return NULL;
	else
	{
		if (index < iter->second.size())
			return &iter->second[index];
		else
			return NULL;
	}
}

size_t font_link::get_link_count(const wchar_t *font_name) const
{
	const link_map::const_iterator iter = _link_table.find(font_name);

	if (iter == _link_table.end())
		return 0;
	else
		return iter->second.size();
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_server/font_link.h:
namespace gdipp
{


// only the constructor changes internal state
// all public functions are read-only
// therefore it is thread-safe

class font_link
{
public:
	font_link();

	const font_link_node *lookup_link(const wchar_t *font_name, size_t index) const;
	size_t get_link_count(const wchar_t *font_name) const;

private:
	typedef std::map<std::wstring, std::vector<font_link_node>, wstring_ci_less> link_map;

	link_map _link_table;
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_server/font_mgr.cpp:
namespace gdipp
{

DWORD font_mgr::get_font_size(HDC font_holder, DWORD *table_header)
{
	*table_header = TTCF_TABLE_TAG;

	
	// try to get font file size with ttcf tag first
	// if succeeds, the font face is part of a TTC file
	// otherwise, the font face is a standalone TrueType font file
	
	DWORD font_size = GetFontData(font_holder, *table_header, 0, NULL, 0);
	if (font_size == GDI_ERROR)
	{
		*table_header = 0;
		font_size = GetFontData(font_holder, *table_header, 0, NULL, 0);
		assert(font_size != GDI_ERROR);
	}

	return font_size;
}

ULONG font_mgr::get_ttc_face_index(HDC font_holder, DWORD ttc_file_size)
{
	// get the index of the current face in its TTC file
	// by comparing its start offset retrieved from GetFontData and from the TTC header

	// pre-condition: the font file contains TTC header

	DWORD read_size;

	// start offset of the current face
	DWORD face_start = GetFontData(font_holder, 0, 0, NULL, 0);
	assert(face_start != GDI_ERROR);
	face_start = ttc_file_size - face_start;

	DWORD read_offset = sizeof(DWORD) + sizeof(FIXED);
	ULONG face_count;
	DWORD buffer_len = sizeof(face_count);

	// number of face records in the TTC header
	read_size = GetFontData(font_holder, TTCF_TABLE_TAG, read_offset, &face_count, buffer_len);
	assert(read_size == buffer_len);

	// TrueType font data uses big-endian, while mainstream Windows uses little-endian platforms
	face_count = SWAPLONG(face_count);
	read_offset += buffer_len;

	for (ULONG i = 0; i < face_count; i++)
	{
		// start offset of the current record
		DWORD curr_start;
		buffer_len = sizeof(curr_start);
		read_size = GetFontData(font_holder, TTCF_TABLE_TAG, read_offset, &curr_start, buffer_len);
		assert(read_size == buffer_len);
		curr_start = SWAPLONG(curr_start);

		if (curr_start == face_start)
			return i;

		read_offset += buffer_len;
	}

	return ULONG_MAX;
}

font_mgr::font_mgr()
{
	_font_holder_tls_index = TlsAlloc();
	assert(_font_holder_tls_index != TLS_OUT_OF_INDEXES);
}

font_mgr::~font_mgr()
{
	for (std::map<std::wstring, _font_entry>::const_iterator iter = _font_registry.begin(); iter != _font_registry.end(); ++iter)
		DeleteObject(iter->second.font_handle);

	TlsFree(_font_holder_tls_index);
}

void *font_mgr::register_font(HDC font_holder, const LOGFONTW *log_font, BYTE **outline_metrics_buf, unsigned long *outline_metrics_size)
{
	// create a font with supplied LOGFONT and retrieve related information

	bool b_ret;

	const HFONT hfont = CreateFontIndirectW(log_font);
	if (hfont == NULL)
		return NULL;

	SelectObject(font_holder, hfont);

	*outline_metrics_size = get_dc_outline_metrics(font_holder, outline_metrics_buf);
	if (*outline_metrics_size == 0)
	{
		DeleteObject(hfont);
		return NULL;
	}

	const OUTLINETEXTMETRICW *outline_metrics = reinterpret_cast<const OUTLINETEXTMETRICW *>(*outline_metrics_buf);
	const std::wstring font_face = metric_face_name(outline_metrics);
	std::map<std::wstring, _font_entry>::iterator font_iter = _font_registry.find(font_face);
	if (font_iter == _font_registry.end())
	{
		const scoped_rw_lock lock_w(scoped_rw_lock::SERVER_FONT_MGR, false);
		font_iter = _font_registry.find(font_face);
		if (font_iter == _font_registry.end())
		{
			os2_metrics os2;
			b_ret = os2.init(font_holder);
			if (!b_ret)
			{
				DeleteObject(hfont);
				return NULL;
			}

			DWORD table_header;
			DWORD font_size = get_font_size(font_holder, &table_header);
			if (font_size == GDI_ERROR)
			{
				DeleteObject(hfont);
				return NULL;
			}

			DWORD face_index = 0;
			if (table_header != 0)
			{
				face_index = get_ttc_face_index(font_holder, font_size);
				if (face_index == ULONG_MAX)
				{
					DeleteObject(hfont);
					return NULL;
				}
			}

			const std::pair<std::map<std::wstring, _font_entry>::iterator, bool> insert_ret = _font_registry.insert(std::pair<std::wstring, _font_entry>(font_face, _font_entry()));
			assert(insert_ret.second);
			font_iter = insert_ret.first;

			font_iter->second.font_handle = hfont;
			font_iter->second.os2 = os2;
			font_iter->second.face_index = face_index;
			font_iter->second.table_header = table_header;

			font_iter->second.stream.size = font_size;
			// need the table header to retrieve font data (see stream_io())
			font_iter->second.stream.descriptor.value = table_header;
			font_iter->second.stream.read = font_mgr::stream_io;
			font_iter->second.stream.close = font_mgr::stream_close;

			return &font_iter->second;
		}
	}

	// font has been created before
	DeleteObject(hfont);
	return &font_iter->second;
}

HFONT font_mgr::select_font(void *font_id, HDC hdc) const
{
	const _font_entry *curr_font = reinterpret_cast<const _font_entry *>(font_id);
	return reinterpret_cast<HFONT>(SelectObject(hdc, curr_font->font_handle));
}

ULONG font_mgr::lookup_face_index(void *font_id) const
{
	const _font_entry *curr_font = reinterpret_cast<const _font_entry *>(font_id);
	return curr_font->face_index;
}

const os2_metrics *font_mgr::lookup_os2_metrics(void *font_id) const
{
	const _font_entry *curr_font = reinterpret_cast<const _font_entry *>(font_id);
	return &curr_font->os2;
}

FT_Stream font_mgr::lookup_stream(void *font_id) const
{
	_font_entry *curr_font = reinterpret_cast<_font_entry *>(font_id);
	return &curr_font->stream;
}

HDC font_mgr::get_thread_font_holder() const
{
	return reinterpret_cast<HDC>(TlsGetValue(_font_holder_tls_index));
}

BOOL font_mgr::set_thread_font_holder(HDC font_holder) const
{
	return TlsSetValue(_font_holder_tls_index, font_holder);
}

unsigned long font_mgr::get_dc_outline_metrics(HDC hdc, BYTE **outline_metrics_buf)
{
	// get outline metrics of the DC, which also include the text metrics

	unsigned long outline_metrics_size = GetOutlineTextMetricsW(hdc, 0, NULL);
	if (outline_metrics_size == 0)
		return outline_metrics_size;

	*outline_metrics_buf = new BYTE[outline_metrics_size];
	outline_metrics_size = GetOutlineTextMetricsW(hdc, outline_metrics_size, reinterpret_cast<OUTLINETEXTMETRICW *>(*outline_metrics_buf));
	assert(outline_metrics_size != 0);

	return outline_metrics_size;
}

unsigned long font_mgr::stream_io(FT_Stream stream, unsigned long offset, unsigned char *buffer, unsigned long count)
{
	// callback function, called when freetype requests font data

	// count == 0 means seek operation
	if (count == 0)
		return 0;

	const DWORD read_size = GetFontData(font_mgr_instance.get_thread_font_holder(), stream->descriptor.value, offset, buffer, count);
	assert(read_size != GDI_ERROR);
	assert(read_size == count);

	return read_size;
}

void font_mgr::stream_close(FT_Stream stream)
{
	// GetFontData() needs no close
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_server/font_mgr.h:
namespace gdipp
{

#define buf_family_name(metric_buf) (reinterpret_cast<const wchar_t *>(metric_buf + reinterpret_cast<const UINT>((reinterpret_cast<const OUTLINETEXTMETRICW *>(metric_buf)->otmpFamilyName))))
#define buf_face_name(metric_buf) (reinterpret_cast<const wchar_t *>(metric_buf + reinterpret_cast<const UINT>((reinterpret_cast<const OUTLINETEXTMETRICW *>(metric_buf)->otmpFaceName))))
#define buf_style_name(metric_buf) (reinterpret_cast<const wchar_t *>(metric_buf + reinterpret_cast<const UINT>((reinterpret_cast<const OUTLINETEXTMETRICW *>(metric_buf)->otmpStyleName))))
#define metric_family_name(outline_metric) (reinterpret_cast<const wchar_t *>(reinterpret_cast<const BYTE *>(outline_metric) + reinterpret_cast<const UINT>(outline_metric->otmpFamilyName)))
#define metric_face_name(outline_metric) (reinterpret_cast<const wchar_t *>(reinterpret_cast<const BYTE *>(outline_metric) + reinterpret_cast<const UINT>(outline_metric->otmpFaceName)))
#define metric_style_name(outline_metric) (reinterpret_cast<const wchar_t *>(reinterpret_cast<const BYTE *>(outline_metric) + reinterpret_cast<const UINT>(outline_metric->otmpStyleName)))

class font_mgr
{
public:
	static DWORD get_font_size(HDC font_holder, DWORD *table_header);
	static ULONG get_ttc_face_index(HDC font_holder, DWORD ttc_file_size);

	font_mgr();
	~font_mgr();

	void *register_font(HDC font_holder, const LOGFONTW *log_font, BYTE **outline_metrics_buf, unsigned long *outline_metrics_size);
	HFONT select_font(void *font_id, HDC hdc) const;

	ULONG lookup_face_index(void *font_id) const;
	const os2_metrics *lookup_os2_metrics(void *font_id) const;
	FT_Stream lookup_stream(void *font_id) const;

	HDC get_thread_font_holder() const;
	BOOL set_thread_font_holder(HDC font_holder) const;

private:
	struct _font_entry
	{
		// all fields are font-specific and thread-safe invariants

		HFONT font_handle;
		os2_metrics os2;
		FT_StreamRec stream;

		// used to retrieve font data from GetFontData
		DWORD face_index;
		DWORD table_header;
	};

	static unsigned long get_dc_outline_metrics(HDC hdc, BYTE **outline_metrics_buf);
	static unsigned long stream_io(FT_Stream stream, unsigned long offset, unsigned char *buffer, unsigned long count);
	static void stream_close(FT_Stream stream);

	std::map<std::wstring, _font_entry> _font_registry;
	DWORD _font_holder_tls_index;
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_server/freetype.cpp:
namespace gdipp
{

FT_Library ft_lib;
FTC_Manager ft_cache_man;
FTC_ImageCache ft_glyph_cache;
FT_Glyph empty_outline_glyph;

void initialize_freetype()
{
	FT_Error ft_error;

	ft_error = FT_Init_FreeType(&ft_lib);
	assert(ft_error == 0);

	FT_LcdFilter lcd_filter = static_cast<FT_LcdFilter>(config_instance.get_number(L"/gdipp/server/freetype_lcd_filter/text()", static_cast<int>(server_config::LCD_FILTER)));
	ft_error = FT_Library_SetLcdFilter(ft_lib, lcd_filter);
	assert(ft_error == 0);

	unsigned int b = server_cache_size >> 2;
	ft_error = FTC_Manager_New(ft_lib,
		1 >> b,
		1 >> (b + 1),
		1 >> (b + 18),
		face_requester,
		NULL,
		&ft_cache_man);
	assert(ft_error == 0);

	ft_error = FTC_ImageCache_New(ft_cache_man, &ft_glyph_cache);
	assert(ft_error == 0);

	empty_outline_glyph = make_empty_outline_glyph();
}

void destroy_freetype()
{
	FT_Error ft_error;

	FTC_Manager_Done(ft_cache_man);

	ft_error = FT_Done_FreeType(ft_lib);
	assert(ft_error == 0);
}

FT_Error face_requester(FTC_FaceID face_id, FT_Library library, FT_Pointer request_data, FT_Face *aface)
{
	FT_Open_Args args = {};
	args.flags = FT_OPEN_STREAM;
	args.stream = font_mgr_instance.lookup_stream(face_id);

	return FT_Open_Face(library, &args, font_mgr_instance.lookup_face_index(face_id), aface);
}

int freetype_get_kern(const FTC_Scaler scaler, WORD left_glyph, WORD right_glyph)
{
	FT_Error ft_error;

	FT_Size size;
	ft_error = FTC_Manager_LookupSize(ft_cache_man, scaler, &size);
	assert(ft_error == 0);

	FT_Vector delta;
	ft_error = FT_Get_Kerning(size->face, left_glyph, right_glyph, FT_KERNING_DEFAULT, &delta);
	assert(ft_error == 0);

	return int_from_26dot6(delta.x);
}

FT_Glyph make_empty_outline_glyph()
{
	FT_Glyph empty_glyph;

	FT_Error ft_error;

	FT_GlyphSlotRec glyph_slot = {};
	glyph_slot.library = ft_lib;
	glyph_slot.format = FT_GLYPH_FORMAT_OUTLINE;

	ft_error = FT_Get_Glyph(&glyph_slot, &empty_glyph);
	if (ft_error != 0)
		return NULL;

	return empty_glyph;
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_server/freetype.h:
namespace gdipp
{

extern FT_Library ft_lib;
extern FTC_Manager ft_cache_man;
extern FTC_ImageCache ft_glyph_cache;
extern FT_Glyph empty_outline_glyph;

void initialize_freetype();
void destroy_freetype();
FT_Error face_requester(FTC_FaceID face_id, FT_Library library, FT_Pointer request_data, FT_Face *aface);
int freetype_get_kern(const FTC_Scaler scaler, WORD left_glyph, WORD right_glyph);
FT_Glyph make_empty_outline_glyph();

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_server/ft_renderer.cpp:
namespace gdipp
{

ft_renderer::ft_renderer(rpc_session *render_session)
	: renderer(render_session)
{
}

FT_F26Dot6 ft_renderer::get_embolden_diff(char font_weight_class, char text_weight_class)
{
	// the embolden weight is based on the difference between demanded weight and the regular weight

	const FT_F26Dot6 embolden_values[] = {-32, -16, 0, 16, 32};
	const char embolden_class_count = sizeof(embolden_values) / sizeof(FT_F26Dot6);
	const char regular_embolden_class = (embolden_class_count - 1) / 2;

	char embolden_class = text_weight_class - font_weight_class + regular_embolden_class;

	if (embolden_class < 0)
		embolden_class = 0;
	else if (embolden_class >= embolden_class_count)
		embolden_class = embolden_class_count - 1;

	return embolden_values[embolden_class];
}

void ft_renderer::get_font_width_height(const OUTLINETEXTMETRICW *outline_metrics, FT_Short xAvgCharWidth, FT_UInt &font_width, FT_UInt &font_height)
{
	
	// while the height in FreeType scaler has the same meaning as the height value in LOGFONT structure, the width is different
	// what we know is, when the width in LOGFONT is the xAvgCharWidth (from the OS/2 table), the corresponding FreeType scaler width is the height
	// therefore we need conversion when LOGFONT width is not 0
	// simple calculation yields freetype_width = logfont_width * em_square / xAvgCharWidth
	// note that the tmAveCharWidth field in TEXTMETRIC is the actual LOGFONT width, which is never 0
	

	assert(outline_metrics != NULL);

	font_height = outline_metrics->otmTextMetrics.tmHeight - outline_metrics->otmTextMetrics.tmInternalLeading;

	if (xAvgCharWidth == 0)
		font_width = font_height * outline_metrics->otmTextMetrics.tmDigitizedAspectX / outline_metrics->otmTextMetrics.tmDigitizedAspectY;
	else
	{
		// compare the xAvgCharWidth against the current average char width
		font_width = outline_metrics->otmTextMetrics.tmAveCharWidth * outline_metrics->otmEMSquare / xAvgCharWidth;
	}
}

FT_ULong ft_renderer::make_load_flags(const render_config_static *render_config, FT_Render_Mode render_mode)
{
	FT_ULong load_flags = FT_LOAD_CROP_BITMAP | (render_config->embedded_bitmap ? 0 : FT_LOAD_NO_BITMAP);

	if (render_config->hinting == 0)
		load_flags |= FT_LOAD_NO_HINTING;
	else
	{
		switch (render_config->hinting)
		{
		case 1:
			load_flags |= FT_LOAD_TARGET_LIGHT;
			break;
		case 3:
			load_flags |= FT_LOAD_TARGET_MONO;
			break;
		default:
			{
				if (render_mode == FT_RENDER_MODE_LCD)
					load_flags |= FT_LOAD_TARGET_LCD;
				else
					load_flags |= FT_LOAD_TARGET_NORMAL;
				break;
			}
		}

		switch (render_config->auto_hinting)
		{
		case 0:
			load_flags |= FT_LOAD_NO_AUTOHINT;
			break;
		case 2:
			load_flags |= FT_LOAD_FORCE_AUTOHINT;
			break;
		default:
			load_flags |= FT_LOAD_DEFAULT;
			break;
		}
	}

	return load_flags;
}

void ft_renderer::oblique_outline(const FT_Outline *outline, double slant_adv)
{
	// advance of slant on x-axis
	FT_Matrix oblique_mat = {float_to_16dot16(1), float_to_16dot16(slant_adv), 0, float_to_16dot16(1)};
	FT_Outline_Transform(outline, &oblique_mat);
}

bool ft_renderer::generate_outline_glyph(FT_Glyph *glyph,
	WORD glyph_index,
	const FTC_Scaler scaler,
	FT_F26Dot6 embolden,
	FT_ULong load_flags,
	bool is_italic) const
{
	FT_Error ft_error;

	FT_Glyph cached_glyph;

	{
		// the FreeType function seems not thread-safe
		const scoped_rw_lock lock_w(scoped_rw_lock::SERVER_FREETYPE, false);
		ft_error = FTC_ImageCache_LookupScaler(ft_glyph_cache, scaler, load_flags, glyph_index, &cached_glyph, NULL);
		if (ft_error != 0)
			return NULL;
	}

	// some fonts are embedded with pre-rendered glyph bitmap
	// in that case, use original ExtTextOutW
	if (cached_glyph->format != FT_GLYPH_FORMAT_OUTLINE)
		return NULL;

	// if italic style is demanded, and the font has italic glyph, do oblique transformation
	const OUTLINETEXTMETRICW *outline_metrics = reinterpret_cast<const OUTLINETEXTMETRICW *>(_session->outline_metrics_buf);
	const bool is_oblique = ((outline_metrics->otmTextMetrics.tmItalic != 0) && !is_italic);
	const bool need_embolden = (embolden != 0);
	const bool need_glyph_copy = (is_oblique || need_embolden);

	if (need_glyph_copy)
	{
		FT_Glyph_Copy(cached_glyph, glyph);
		FT_Outline *glyph_outline = &(reinterpret_cast<FT_OutlineGlyph>(*glyph)->outline);

		// it seems faster if oblique first, and then embolden
		if (is_oblique)
			oblique_outline(glyph_outline, 0.3);

		if (need_embolden)
		{
			ft_error = FT_Outline_Embolden(glyph_outline, embolden);
			assert(ft_error == 0);
		}
	}
	else
		*glyph = cached_glyph;

	return need_glyph_copy;
}

const FT_Glyph ft_renderer::generate_bitmap_glyph(WORD glyph_index,
	const FTC_Scaler scaler,
	FT_Render_Mode render_mode,
	FT_F26Dot6 embolden,
	FT_ULong load_flags,
	bool is_italic,
	bool request_outline,
	uint128_t render_trait) const
{
	FT_Error ft_error;
	FT_Glyph glyph;

	if (request_outline)
	{
		generate_outline_glyph(&glyph, glyph_index, scaler, embolden, load_flags, is_italic);
		return glyph;
	}

	const glyph_cache::char_id_type char_id = glyph_cache::get_char_id(render_trait, glyph_index, true);
	glyph = glyph_cache_instance.lookup_glyph(char_id);
	if (glyph == NULL)
	{
		// no cached glyph, or outline glyph is requested, generate outline
		const bool is_local_glyph = generate_outline_glyph(&glyph, glyph_index, scaler, embolden, load_flags, is_italic);

		// outline -> bitmap conversion
		{
			// the FreeType function seems not thread-safe
			const scoped_rw_lock lock_w(scoped_rw_lock::SERVER_FREETYPE, false);
			ft_error = FT_Glyph_To_Bitmap(&glyph, render_mode, NULL, is_local_glyph);
			if (ft_error != 0)
				return NULL;
		}

		glyph_cache_instance.store_glyph(char_id, glyph);
	}

	return glyph;
}

bool ft_renderer::generate_glyph_run(bool is_glyph_index, LPCWSTR lpString, UINT c, glyph_run *new_glyph_run, bool request_outline)
{
	const OUTLINETEXTMETRICW *curr_outline_metrics = reinterpret_cast<const OUTLINETEXTMETRICW *>(_session->outline_metrics_buf);
	const render_config_static *curr_render_config = _session->render_config;
	uint128_t curr_render_trait = _session->render_trait;
	const wchar_t *curr_font_face = metric_face_name(curr_outline_metrics);
	const os2_metrics *curr_os2 = font_mgr_instance.lookup_os2_metrics(_session->font_id);
	const wchar_t *session_font_family = metric_family_name(curr_outline_metrics);

	FTC_ScalerRec scaler = {};
	scaler.face_id = _session->font_id;
	scaler.pixel = 1;
	get_font_width_height(curr_outline_metrics, (_session->log_font.lfWidth == 0 ? 0 : curr_os2->get_xAvgCharWidth()), scaler.height, scaler.width);

	FT_F26Dot6 curr_embolden = 0;
	if (_session->log_font.lfWeight != FW_DONTCARE)
	{
		// embolden if some weight is demanded
		curr_embolden = curr_render_config->embolden + get_embolden_diff(curr_os2->get_weight_class(), static_cast<char>(_session->log_font.lfWeight));
	}

	FT_ULong curr_load_flags = make_load_flags(curr_render_config, _session->render_mode);

	if (is_glyph_index)
	{
		// directly render glyph indices with the current DC font

		for (UINT i = 0; i < c; ++i)
		{
			const FT_Glyph new_glyph = generate_bitmap_glyph(lpString[i],
				&scaler,
				_session->render_mode,
				curr_embolden,
				curr_load_flags,
				curr_os2->is_italic(),
				request_outline,
				curr_render_trait);
			RECT ctrl_box = {}, black_box = {};

			if (new_glyph == NULL)
			{
				if (request_outline)
					return false;
			}
			else if (curr_render_config->kerning && i > 0 && !request_outline)
			{
				ctrl_box.left = freetype_get_kern(&scaler, lpString[i-1], lpString[i]);
				ctrl_box.right = ctrl_box.left;
			}

			new_glyph_run->glyphs.push_back(new_glyph);
			new_glyph_run->ctrl_boxes.push_back(ctrl_box);
			new_glyph_run->black_boxes.push_back(black_box);
		}
	}
	else
	{
		FT_Render_Mode curr_render_mode = _session->render_mode;

		UINT rendered_count = 0;
		int font_link_index = 0;
		std::wstring final_string(lpString, c);
		std::vector<unsigned short> glyph_indices(c);

		new_glyph_run->glyphs.resize(c);
		new_glyph_run->ctrl_boxes.resize(c);
		new_glyph_run->black_boxes.resize(c);

		while (true)
		{
			GetGlyphIndices(_curr_font_holder, final_string.data(), c, &glyph_indices[0], GGI_MARK_NONEXISTING_GLYPHS);

			std::vector<FT_Glyph>::iterator glyph_iter;
			std::vector<RECT>::iterator ctrl_iter, black_iter;
			UINT i;
			for (glyph_iter = new_glyph_run->glyphs.begin(), ctrl_iter = new_glyph_run->ctrl_boxes.begin(), black_iter = new_glyph_run->black_boxes.begin(), i = 0;
				i < c; i++, glyph_iter++, ctrl_iter++, black_iter++)
			{
				if (final_string[i] == L'\0')
					continue;

				// do not render control characters, even the corresponding glyphs exist in font
				if (iswcntrl(final_string[i]) && !request_outline)
					*glyph_iter = NULL;
				else if (glyph_indices[i] != 0xffff)
				{
					*glyph_iter = generate_bitmap_glyph(glyph_indices[i],
						&scaler,
						curr_render_mode,
						curr_embolden,
						curr_load_flags, 
						curr_os2->is_italic(),
						request_outline,
						curr_render_trait);

					if (*glyph_iter == NULL)
					{
						if (request_outline)
							return false;
					}
					else if (curr_render_config->kerning && i > 0 && !request_outline)
					{
						ctrl_iter->left = freetype_get_kern(&scaler, glyph_indices[i-1], glyph_indices[i]);
						ctrl_iter->right = ctrl_iter->left;
					}
				}
				else
					continue;
					
				final_string[i] = L'\0';
				rendered_count += 1;
			}

			if (rendered_count >= c)
			{
				assert(rendered_count == c);
				break;
			}

			// font linking

			const font_link_node *curr_link = font_link_instance.lookup_link(session_font_family, font_link_index);
			if (curr_link == NULL)
				return false;
			font_link_index += 1;
			
			LOGFONTW linked_log_font = _session->log_font;
			
			// this reset is essential to make GetGlyphIndices work correctly
			// for example, lfOutPrecision might be OUT_PS_ONLY_PRECIS for Myriad Pro
			// if create HFONT of Microsoft YaHei with such lfOutPrecision, GetGlyphIndices always fails
			
			linked_log_font.lfOutPrecision = OUT_DEFAULT_PRECIS;
			wcsncpy_s(linked_log_font.lfFaceName, curr_link->font_family.c_str(), LF_FACESIZE);

			BYTE *curr_outline_metrics_buf;
			unsigned long curr_outline_metrics_size;
			scaler.face_id = font_mgr_instance.register_font(_curr_font_holder, &linked_log_font, &curr_outline_metrics_buf, &curr_outline_metrics_size);
			assert(scaler.face_id != NULL);

			// reload metrics for the linked font

			const OUTLINETEXTMETRICW *curr_outline_metrics = reinterpret_cast<const OUTLINETEXTMETRICW *>(curr_outline_metrics_buf);
			curr_font_face = metric_face_name(curr_outline_metrics);

			if (curr_link->scaling != 1.0)
			{
				// apply font linking scaling factor
				scaler.width = static_cast<FT_UInt>(scaler.width * curr_link->scaling);
				scaler.height = static_cast<FT_UInt>(scaler.height * curr_link->scaling);
			}

			curr_os2 = font_mgr_instance.lookup_os2_metrics(scaler.face_id);
			const char font_weight_class = curr_os2->get_weight_class();
			const LONG point_size = (linked_log_font.lfHeight > 0 ? linked_log_font.lfHeight : -MulDiv(linked_log_font.lfHeight, 72, curr_outline_metrics->otmTextMetrics.tmDigitizedAspectY));

			curr_render_config = font_render_config_cache_instance.get_font_render_config(!!font_weight_class,
				curr_os2->is_italic(),
				point_size,
				curr_font_face);

			delete[] curr_outline_metrics_buf;

			if (!get_render_mode(curr_render_config->render_mode, _session->bits_per_pixel, _session->log_font.lfQuality, &curr_render_mode))
				return false;

			curr_render_trait = generate_render_trait(&linked_log_font, curr_render_mode);

			curr_embolden = 0;
			if (linked_log_font.lfWeight != FW_DONTCARE)
				curr_embolden = curr_render_config->embolden + get_embolden_diff(font_weight_class, static_cast<char>(linked_log_font.lfWeight));

			curr_load_flags = make_load_flags(curr_render_config, _session->render_mode);
		}

		dc_pool_instance.free(_curr_font_holder);
	}

	return true;
}

bool ft_renderer::render(bool is_glyph_index, LPCWSTR lpString, UINT c, glyph_run *new_glyph_run)
{
	bool b_ret;

	if (is_glyph_index)
	{
		_curr_font_holder = _session->font_holder;
	}
	else
	{
		// font link is possible
		// we need an extra DC to hold linked font and not affect the session font holder
		_curr_font_holder = dc_pool_instance.claim();
		assert(_curr_font_holder != NULL);
		font_mgr_instance.select_font(_session->font_id, _curr_font_holder);
	}
	font_mgr_instance.set_thread_font_holder(_curr_font_holder);

	b_ret = generate_glyph_run(is_glyph_index, lpString, c, new_glyph_run, false);

	if (!is_glyph_index)
		dc_pool_instance.free(_curr_font_holder);

	if (!b_ret)
		return false;

	POINT pen_pos = {};

	std::vector<FT_Glyph>::iterator glyph_iter;
	std::vector<RECT>::iterator ctrl_iter, black_iter;
	for (glyph_iter = new_glyph_run->glyphs.begin(), ctrl_iter = new_glyph_run->ctrl_boxes.begin(), black_iter = new_glyph_run->black_boxes.begin();
		glyph_iter != new_glyph_run->glyphs.end(); ++glyph_iter, ++ctrl_iter, ++black_iter)
	{
		FT_Int glyph_left = 0, glyph_width = 0;
		FT_Vector glyph_advance = {};

		const FT_BitmapGlyph bmp_glyph = reinterpret_cast<FT_BitmapGlyph>(*glyph_iter);
		if (bmp_glyph != NULL)
		{
			glyph_left = bmp_glyph->left;
			glyph_width = get_glyph_bmp_width(bmp_glyph->bitmap);
			glyph_advance = bmp_glyph->root.advance;
		}

		ctrl_iter->left += pen_pos.x;
		ctrl_iter->top += pen_pos.y;
		black_iter->left = ctrl_iter->left + glyph_left;
		black_iter->top = ctrl_iter->top;

		pen_pos.x += int_from_16dot16(glyph_advance.x);
		pen_pos.y += int_from_16dot16(glyph_advance.y);

		ctrl_iter->right += pen_pos.x;
		ctrl_iter->bottom += pen_pos.y;
		black_iter->right = black_iter->left + glyph_width;
		black_iter->bottom = ctrl_iter->bottom;
	}

	return true;
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_server/ft_renderer.h:
namespace gdipp
{

class ft_renderer : public renderer
{
public:
	explicit ft_renderer(rpc_session *render_session);

private:
	static FT_F26Dot6 get_embolden_diff(char font_weight_class, char text_weight_class);
	static void get_font_width_height(const OUTLINETEXTMETRICW *outline_metrics, FT_Short xAvgCharWidth, FT_UInt &font_width, FT_UInt &font_height);
	static FT_ULong make_load_flags(const render_config_static *render_config, FT_Render_Mode render_mode);
	static void oblique_outline(const FT_Outline *outline, double slant_adv);

	bool generate_outline_glyph(FT_Glyph *glyph,
		WORD glyph_index,
		const FTC_Scaler scaler,
		FT_F26Dot6 embolden,
		FT_ULong load_flags,
		bool is_italic) const;
	const FT_Glyph generate_bitmap_glyph(WORD glyph_index,
		const FTC_Scaler scaler,
		FT_Render_Mode render_mode,
		FT_F26Dot6 embolden,
		FT_ULong load_flags,
		bool is_italic,
		bool request_outline,
		uint128_t render_trait) const;
	bool generate_glyph_run(bool is_glyph_index, LPCWSTR lpString, UINT c, glyph_run *new_glyph_run, bool request_outline);

	bool render(bool is_glyph_index, LPCWSTR lpString, UINT c, glyph_run *new_glyph_run);

	HDC _curr_font_holder;
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_server/gdipp_server.cpp:
namespace gdipp
{

#define SVC_NAME L"gdipp_svc"

SERVICE_STATUS svc_status = {};
SERVICE_STATUS_HANDLE h_svc_status = NULL;

HANDLE h_svc_events, h_wait_cleanup, h_rpc_thread;

std::map<ULONG, HANDLE> h_user_tokens;
std::map<ULONG, PROCESS_INFORMATION> pi_hooks_32, pi_hooks_64;

BOOL hook_proc(HANDLE h_user_token, char *hook_env_str, const wchar_t *gdipp_hook_name, PROCESS_INFORMATION &pi)
{
	wchar_t gdipp_hook_path[MAX_PATH];

	if (!get_dir_file_path(NULL, gdipp_hook_name, gdipp_hook_path))
		return FALSE;

	STARTUPINFOW si = {sizeof(STARTUPINFO)};

	return CreateProcessAsUserW(h_user_token, gdipp_hook_path, NULL, NULL, NULL, TRUE, NULL, hook_env_str, NULL, &si, &pi);
}

BOOL start_hook(ULONG session_id)
{
	// make the event handle inheritable
	SECURITY_ATTRIBUTES inheritable_sa = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
	BOOL b_ret, hook_success = TRUE;
	HANDLE h_user_token;

	b_ret = WTSQueryUserToken(session_id, &h_user_token);
	if (!b_ret)
	{
		hook_success = FALSE;
		goto post_hook;
	}

	// use the linked token if exists
	// needed in UAC-enabled scenarios and Run As Administrator
	TOKEN_LINKED_TOKEN linked_token;
	DWORD token_info_len;
	b_ret = GetTokenInformation(h_user_token, TokenLinkedToken, &linked_token, sizeof(TOKEN_LINKED_TOKEN), &token_info_len);
	if (b_ret)
	{
		CloseHandle(h_user_token);
		h_user_token = linked_token.LinkedToken;
	}
	
	char hook_env_str[64];
	sprintf_s(hook_env_str, "gdipp_svc_proc_id=%d%c", GetCurrentProcessId(), 0);

	if (!!config_instance.get_number(L"/gdipp/hook/include/proc_32_bit/text()", static_cast<int>(gdipp::hook_config::PROC_32_BIT)))
	{
		const wchar_t *gdipp_hook_name_32 = L"gdipp_hook_32.exe";
		PROCESS_INFORMATION pi;

		if (hook_proc(h_user_token, hook_env_str, gdipp_hook_name_32, pi))
			pi_hooks_32[session_id] = pi;
		else
			hook_success = FALSE;
	}

	if (!!config_instance.get_number(L"/gdipp/hook/include/proc_64_bit/text()", static_cast<int>(gdipp::hook_config::PROC_64_BIT)))
	{
		const wchar_t *gdipp_hook_name_64 = L"gdipp_hook_64.exe";
		PROCESS_INFORMATION pi;

		if (hook_proc(h_user_token, hook_env_str, gdipp_hook_name_64, pi))
			pi_hooks_64[session_id] = pi;
		else
			hook_success = FALSE;
	}

post_hook:
	if (hook_success)
	{
		h_user_tokens[session_id] = h_user_token;
	}
	else
	{
		if (h_user_token)
			CloseHandle(h_user_token);
	}

	return b_ret;
}

void stop_hook(ULONG session_id)
{
	std::map<ULONG, PROCESS_INFORMATION>::const_iterator pi_iter_32, pi_iter_64;
	HANDLE h_hook_processes[2] = {};

	pi_iter_32 = pi_hooks_32.find(session_id);
	if (pi_iter_32 != pi_hooks_32.end())
		h_hook_processes[0] = pi_iter_32->second.hProcess;

	pi_iter_64 = pi_hooks_64.find(session_id);
	if (pi_iter_64 != pi_hooks_64.end())
		h_hook_processes[1] = pi_iter_64->second.hProcess;

	// notify and wait hook subprocesses to exit
	WaitForMultipleObjects(2, h_hook_processes, TRUE, INFINITE);

	// clean up

	if (pi_iter_32 != pi_hooks_32.end())
	{
		CloseHandle(pi_iter_32->second.hThread);
		CloseHandle(pi_iter_32->second.hProcess);
		pi_hooks_32.erase(pi_iter_32);
	}

	if (pi_iter_64 != pi_hooks_64.end())
	{
		CloseHandle(pi_iter_64->second.hThread);
		CloseHandle(pi_iter_64->second.hProcess);
		pi_hooks_64.erase(pi_iter_64);
	}

	CloseHandle(h_user_tokens[session_id]);
	h_user_tokens.erase(session_id);
}

void set_svc_status(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint)
{
	static DWORD dwCheckPoint = 1;

	// fill in the SERVICE_STATUS structure
	svc_status.dwCurrentState = dwCurrentState;
	svc_status.dwWin32ExitCode = dwWin32ExitCode;
	svc_status.dwWaitHint = dwWaitHint;

	if (dwCurrentState == SERVICE_RUNNING)
		svc_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SESSIONCHANGE;
	else
		svc_status.dwControlsAccepted = 0;

	if (dwCurrentState == SERVICE_RUNNING || dwCurrentState == SERVICE_STOPPED)
		svc_status.dwCheckPoint = 0;
	else
		svc_status.dwCheckPoint = ++dwCheckPoint;

	// report the status of the service to the SCM (Service Control Manager)
	SetServiceStatus(h_svc_status, &svc_status);
}

DWORD WINAPI svc_ctrl_handler(DWORD dwCtrl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext)
{
	BOOL b_ret;

	// handle the requested control code
	switch (dwCtrl)
	{
	case SERVICE_CONTROL_STOP:
		set_svc_status(SERVICE_STOP_PENDING, NO_ERROR, 0);

		b_ret = SetEvent(h_svc_events);
		assert(b_ret);

		return NO_ERROR;
	case SERVICE_CONTROL_INTERROGATE:
		return NO_ERROR;
	case SERVICE_CONTROL_SESSIONCHANGE:
		if (dwEventType == WTS_SESSION_LOGON)
		{
			b_ret = start_hook(reinterpret_cast<WTSSESSION_NOTIFICATION *>(lpEventData)->dwSessionId);

			if (b_ret)
				return NO_ERROR;
			else
				return GetLastError();
		}
		else if (dwEventType == WTS_SESSION_LOGOFF)
		{
			stop_hook(reinterpret_cast<WTSSESSION_NOTIFICATION *>(lpEventData)->dwSessionId);

			return NO_ERROR;
		}
		else
			return ERROR_CALL_NOT_IMPLEMENTED;
	default:
		return ERROR_CALL_NOT_IMPLEMENTED;
	}
}

VOID CALLBACK exit_cleanup(PVOID lpParameter, BOOLEAN TimerOrWaitFired)
{
	BOOL b_ret;

	b_ret = UnregisterWait(h_wait_cleanup);
	assert(b_ret || GetLastError() == ERROR_IO_PENDING);

	b_ret = stop_gdipp_rpc_server();
	if (b_ret)
	{
		const DWORD wait_ret = WaitForSingleObject(h_rpc_thread, INFINITE);
		assert(wait_ret == WAIT_OBJECT_0);
	}

	set_svc_status(SERVICE_STOPPED, NO_ERROR, 0);
}

void svc_init()
{
	h_svc_events = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (h_svc_events == NULL)
	{
		set_svc_status(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}

	// clean up when event is set
	if (!RegisterWaitForSingleObject(&h_wait_cleanup, h_svc_events, exit_cleanup, NULL, INFINITE, WT_EXECUTEDEFAULT | WT_EXECUTEONLYONCE))
	{
		set_svc_status(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}

	// report running status when initialization is complete
	set_svc_status(SERVICE_RUNNING, NO_ERROR, 0);

	// initialize RPC for font service
	h_rpc_thread = CreateThread(NULL, 0, start_gdipp_rpc_server, NULL, 0, NULL);
	if (h_rpc_thread == NULL)
	{
		set_svc_status(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}

	
	// service process and its child processes run in session 0
	// some functions in gdipp may require interactive session (session ID > 0)
	// use CreateProcessAsUser to create process in the active user's session
	
	const DWORD active_session_id = WTSGetActiveConsoleSessionId();
	if (active_session_id != 0xFFFFFFFF)
		start_hook(active_session_id);
}

VOID WINAPI svc_main(DWORD dwArgc, LPTSTR *lpszArgv)
{
	// register the handler function for the service
	h_svc_status = RegisterServiceCtrlHandlerExW(SVC_NAME, svc_ctrl_handler, NULL);
	if (h_svc_status == NULL)
		return;

	// these SERVICE_STATUS members remain as set here
	svc_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	svc_status.dwWin32ExitCode = NO_ERROR;

	// report initial status to the SCM
	set_svc_status(SERVICE_START_PENDING, NO_ERROR, 3000);

	svc_init();
}

}

// #define svc_debug

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow)
{
#ifdef svc_debug
	Sleep(5000);
#endif  // svc_debug

	SERVICE_TABLE_ENTRY dispatch_table[] =
	{
		{ SVC_NAME, gdipp::svc_main },
		{ NULL, NULL },
	};

	if (!StartServiceCtrlDispatcherW(dispatch_table))
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_server/ggo_renderer.cpp:
namespace gdipp
{

ggo_renderer::ggo_renderer(rpc_session *render_session)
	: renderer(render_session)
{
}

bool ggo_renderer::render(bool is_glyph_index, LPCWSTR lpString, UINT c, glyph_run *new_glyph_run)
{
	bool b_ret;

	// identity matrix
	memset(&_matrix, 0, sizeof(MAT2));
	_matrix.eM11.value = 1;
	_matrix.eM22.value = 1;

	
	// GetGlyphOutline is capable of returning cubic B¨¦zier curves
	// although it generally require less points to define a curve with cubic rather than quadratic B¨¦zier curves,
	// TrueType fonts internally store curves with quadratic B¨¦zier curves
	// GetGlyphOutline has to do conversion, which takes time, and generates more points
	// therefore, quadratic B¨¦zier curves are more favored
	
	_ggo_format = GGO_NATIVE;
	if (is_glyph_index)
		_ggo_format |= GGO_GLYPH_INDEX;

	if (_session->render_config->hinting == 0)
		_ggo_format |= GGO_UNHINTED;

	POINT pen_pos = {};

	for (UINT i = 0; i < c; ++i)
	{
		GLYPHMETRICS glyph_metrics = {};
		FT_Glyph new_glyph;

		// we do not care about non-printable characters
		// solution for Windows Vista/7 Date glitch
		if (is_glyph_index || !iswcntrl(lpString[i]))
		{
			const glyph_cache::char_id_type char_id = glyph_cache::get_char_id(_session->render_trait, lpString[i], is_glyph_index);
			new_glyph = glyph_cache_instance.lookup_glyph(char_id);
			if (new_glyph == NULL)
			{
				new_glyph = outline_to_bitmap(lpString[i], glyph_metrics);
				glyph_cache_instance.store_glyph(char_id, new_glyph);
			}
			else
			{
				b_ret = get_glyph_metrics(lpString[i], glyph_metrics);
				if (!b_ret)
					return b_ret;
			}
		}

		FT_Int glyph_left = 0, glyph_width = 0;

		if (new_glyph != NULL)
		{
			const FT_BitmapGlyph bmp_glyph = reinterpret_cast<FT_BitmapGlyph>(new_glyph);
			glyph_left = bmp_glyph->left;
			glyph_width = get_glyph_bmp_width(bmp_glyph->bitmap);
		}

		RECT ctrl_box, black_box;
		ctrl_box.left = pen_pos.x;
		ctrl_box.top = pen_pos.y;
		black_box.left = ctrl_box.left + glyph_left;
		black_box.top = ctrl_box.top;

		pen_pos.x += glyph_metrics.gmCellIncX;
		pen_pos.y += glyph_metrics.gmCellIncY;

		ctrl_box.right = pen_pos.x;
		ctrl_box.bottom = pen_pos.y;
		black_box.right = black_box.left + glyph_width;
		black_box.bottom = ctrl_box.bottom;

		new_glyph_run->glyphs.push_back(new_glyph);
		new_glyph_run->ctrl_boxes.push_back(ctrl_box);
		new_glyph_run->black_boxes.push_back(black_box);
	}

	return true;
}

void ggo_renderer::outline_ggo_to_ft(DWORD ggo_outline_buf_len, const BYTE *ggo_outline_buf, std::vector<FT_Vector> &curve_points, std::vector<char> &curve_tags, std::vector<short> &contour_indices)
{
	// parse outline coutours
	DWORD header_off = 0;
	do
	{
		const BYTE *header_ptr = ggo_outline_buf + header_off;
		const TTPOLYGONHEADER *header = reinterpret_cast<const TTPOLYGONHEADER *>(header_ptr);

		// FreeType uses 26.6 format, while Windows gives logical units
		const FT_Vector start_point = {fixed_to_26dot6(header->pfxStart.x), fixed_to_26dot6(header->pfxStart.y)};

		DWORD curve_off = sizeof(TTPOLYGONHEADER);
		while (curve_off < header->cb)
		{
			// the starting point of each curve is the last point of the previous curve or the starting point of the contour
			if (curve_off == sizeof(TTPOLYGONHEADER))
			{
				curve_points.push_back(start_point);
				// the first point is on the curve
				curve_tags.push_back(FT_CURVE_TAG_ON);
			}

			const TTPOLYCURVE *curve = reinterpret_cast<const TTPOLYCURVE *>(header_ptr + curve_off);
			char curve_tag;
			switch (curve->wType)
			{
			case TT_PRIM_LINE:
				curve_tag = FT_CURVE_TAG_ON;
				break;
			case TT_PRIM_QSPLINE:
				curve_tag = FT_CURVE_TAG_CONIC;
				break;
			case TT_PRIM_CSPLINE:
				curve_tag = FT_CURVE_TAG_CUBIC;
				break;
			}

			for (int j = 0; j < curve->cpfx; ++j)
			{
				const FT_Vector curr_point = {fixed_to_26dot6(curve->apfx[j].x), fixed_to_26dot6(curve->apfx[j].y)};
				curve_points.push_back(curr_point);
				curve_tags.push_back(curve_tag);
			}
			// the last point is on the curve
			curve_tags[curve_tags.size() - 1] = FT_CURVE_TAG_ON;

			curve_off += sizeof(TTPOLYCURVE) + (curve->cpfx - 1) * sizeof(POINTFX);
		}

		contour_indices.push_back(static_cast<short>(curve_points.size() - 1));
		header_off += header->cb;
	} while (header_off < ggo_outline_buf_len);

	assert(curve_points.size() <= FT_OUTLINE_POINTS_MAX);
}

bool ggo_renderer::get_glyph_metrics(wchar_t ch, GLYPHMETRICS &glyph_metrics) const
{
	DWORD outline_buf_len = GetGlyphOutline(_session->font_holder, ch, (_ggo_format | GGO_METRICS), &glyph_metrics, 0, NULL, &_matrix);
	return (outline_buf_len != GDI_ERROR);
}

const FT_Glyph ggo_renderer::outline_to_bitmap(wchar_t ch, GLYPHMETRICS &glyph_metrics) const
{
	bool b_ret;
	FT_Error ft_error;

	FT_OutlineGlyphRec outline_glyph = {*empty_outline_glyph, {}};
	outline_glyph.root.format = FT_GLYPH_FORMAT_OUTLINE;

	DWORD outline_buf_len = GetGlyphOutline(_session->font_holder, ch, _ggo_format, &glyph_metrics, 0, NULL, &_matrix);
	assert(outline_buf_len != GDI_ERROR);

	if (outline_buf_len == 0)
	{
		// the glyph outline of this character is empty (e.g. space)
		b_ret = get_glyph_metrics(ch, glyph_metrics);
		assert(b_ret);

		return NULL;
	}
	else
	{
		BYTE *outline_buf = new BYTE[outline_buf_len];
		outline_buf_len = GetGlyphOutline(_session->font_holder, ch, _ggo_format, &glyph_metrics, outline_buf_len, outline_buf, &_matrix);
		assert(outline_buf_len != GDI_ERROR);

		std::vector<FT_Vector> curve_points;
		std::vector<char> curve_tags;
		std::vector<short> contour_indices;
		outline_ggo_to_ft(outline_buf_len, outline_buf, curve_points, curve_tags, contour_indices);

		delete[] outline_buf;

		outline_glyph.outline.n_contours = static_cast<short>(contour_indices.size());
		outline_glyph.outline.n_points = static_cast<short>(curve_points.size());
		outline_glyph.outline.points = &curve_points[0];
		outline_glyph.outline.tags = &curve_tags[0];
		outline_glyph.outline.contours = &contour_indices[0];
		outline_glyph.outline.flags = FT_OUTLINE_NONE;

		
		// once in possess of FT_Outline, there are several way to get FT_Bitmap

		// 1. FT_Outline_Render: could pass a callback span function to directly draw scanlines to DC
		//    unfortunately it only output 8-bit bitmap
		// 2. FT_Outline_Get_Bitmap: merely a wrapper of FT_Outline_Render
		// 3. FT_Glyph_To_Bitmap: first conglyph_indicesuct FT_OutlineGlyph from FT_Outline, then render glyph to get FT_Bitmap
		//    when conglyph_indicesucting FreeType glyph, the private clazz field must be provided
		//    support 24-bit bitmap

		// we use method 3
		

		if (_session->render_config->embolden != 0)
		{
			ft_error = FT_Outline_Embolden(&outline_glyph.outline, _session->render_config->embolden);
			assert(ft_error == 0);
		}

		// convert outline to bitmap
		FT_Glyph generic_glyph = reinterpret_cast<FT_Glyph>(&outline_glyph);

		{
			// the FreeType function seems not thread-safe
			const scoped_rw_lock lock_w(scoped_rw_lock::SERVER_FREETYPE, false);
			ft_error = FT_Glyph_To_Bitmap(&generic_glyph, _session->render_mode, NULL, false);
			if (ft_error != 0)
				return NULL;
		}

		return generic_glyph;
	}
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_server/ggo_renderer.h:
namespace gdipp
{

class ggo_renderer : public renderer
{
public:
	explicit ggo_renderer(rpc_session *render_session);

	bool render(bool is_glyph_index, LPCWSTR lpString, UINT c, glyph_run *new_glyph_run);

private:
	static void outline_ggo_to_ft(DWORD ggo_outline_buf_len, const BYTE *ggo_outline_buf, std::vector<FT_Vector> &curve_points, std::vector<char> &curve_tags, std::vector<short> &contour_indices);

	bool get_glyph_metrics(wchar_t ch, GLYPHMETRICS &glyph_metrics) const;
	const FT_Glyph outline_to_bitmap(wchar_t ch, GLYPHMETRICS &glyph_metrics) const;

	static FT_Glyph _empty_outline_glyph;

	UINT _ggo_format;
	MAT2 _matrix;
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_server/global.cpp:
namespace gdipp
{

config_file config_file_instance(L"server.conf");
config config_instance(config_file_instance);
dc_pool dc_pool_instance;
font_link font_link_instance;
font_mgr font_mgr_instance;
render_config_cache font_render_config_cache_instance(config_file_instance);
glyph_cache glyph_cache_instance;
unsigned int server_cache_size;
//sqlite3 *index_db_instance;

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_server/global.h:
namespace gdipp
{

extern config_file config_file_instance;
extern config config_instance;
extern dc_pool dc_pool_instance;
extern font_link font_link_instance;
extern font_mgr font_mgr_instance;
extern render_config_cache font_render_config_cache_instance;
extern glyph_cache glyph_cache_instance;
extern unsigned int server_cache_size;
//extern sqlite3 *index_db_instance;

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_server/glyph_cache.cpp:
namespace gdipp
{

glyph_cache::string_id_type glyph_cache::get_string_id(const wchar_t *string, unsigned int count, bool is_glyph_index)
{
	string_id_type string_id;
#ifdef _M_X64
	MurmurHash3_x64_128(string, count * sizeof(wchar_t), is_glyph_index, &string_id);
#else
	MurmurHash3_x86_128(string, count * sizeof(wchar_t), is_glyph_index, &string_id);
#endif // _M_X64

	return string_id;
}

glyph_cache::char_id_type glyph_cache::get_char_id(uint128_t render_trait, FT_UInt index, bool is_glyph_index)
{
	
	// character ID:
	// * low 64 bits: low 64 bits of render_trait
	// * high 64 bits:
	// high								                low
	// |             31             |       1        |  32   |
	// | render_trait (65 - 96 bit) | is_glyph_index | index |
	
	char_id_type char_id = render_trait;
	char_id.second = (char_id.second << 33) | (static_cast<uint64_t>(is_glyph_index) << 32) | index;
	return char_id;
}

glyph_cache::~glyph_cache()
{
	for (std::map<char_id_type, INIT_ONCE>::iterator glyph_iter = _glyph_store.begin(); glyph_iter != _glyph_store.end(); ++glyph_iter)
	{
		BOOL pending;
		FT_Glyph glyph;
		InitOnceBeginInitialize(&glyph_iter->second, INIT_ONCE_CHECK_ONLY, &pending, reinterpret_cast<void **>(&glyph));
		assert(!pending);
		FT_Done_Glyph(glyph);
	}

	for (std::map<string_id_type, trait_to_run_map>::iterator str_iter = _glyph_run_store.begin(); str_iter != _glyph_run_store.end(); ++str_iter)
		erase_glyph_run_cache_string(str_iter);
}

void glyph_cache::initialize()
{
	_glyph_run_lru.resize(min(1 << server_cache_size, 16777216));
}

const FT_Glyph glyph_cache::lookup_glyph(char_id_type char_id)
{
	std::map<char_id_type, INIT_ONCE>::iterator glyph_iter;
	
	{
		const scoped_rw_lock lock_w(scoped_rw_lock::SERVER_GLYPH_CACHE, false);

		glyph_iter = _glyph_store.find(char_id);
		if (glyph_iter == _glyph_store.end())
		{
			const std::pair<std::map<char_id_type, INIT_ONCE>::iterator, bool> insert_ret = _glyph_store.insert(std::pair<char_id_type, INIT_ONCE>(char_id, INIT_ONCE()));
			assert(insert_ret.second);
			glyph_iter = insert_ret.first;
			InitOnceInitialize(&glyph_iter->second);
		}
	}

	FT_Glyph glyph = NULL;
	BOOL pending;
	InitOnceBeginInitialize(&glyph_iter->second, 0, &pending, reinterpret_cast<void **>(&glyph));
	assert((glyph == NULL) == pending);

	return glyph;
}

bool glyph_cache::store_glyph(char_id_type char_id, const FT_Glyph glyph)
{
	std::map<char_id_type, INIT_ONCE>::iterator glyph_iter;

	{
		const scoped_rw_lock lock_w(scoped_rw_lock::SERVER_GLYPH_CACHE, false);

		glyph_iter = _glyph_store.find(char_id);
	}

	InitOnceComplete(&glyph_iter->second, (glyph == NULL ? INIT_ONCE_INIT_FAILED : 0), glyph);
	return glyph != NULL;
}

const glyph_run *glyph_cache::lookup_glyph_run(string_id_type string_id, uint128_t render_trait)
{
	trait_to_run_map::iterator trait_iter;

	{
		const scoped_rw_lock lock_w(scoped_rw_lock::SERVER_GLYPH_RUN_CACHE, false);

		std::map<uint128_t, trait_to_run_map>::iterator str_iter = _glyph_run_store.find(string_id);
		if (str_iter == _glyph_run_store.end())
		{
			const std::pair<std::map<string_id_type, trait_to_run_map>::iterator, bool> str_insert_ret = _glyph_run_store.insert(std::pair<string_id_type, trait_to_run_map>(string_id, trait_to_run_map()));
			assert(str_insert_ret.second);
			str_iter = str_insert_ret.first;
			trait_iter = str_iter->second.end();
		}
		else
		{
			trait_iter = str_iter->second.find(render_trait);
		}

		if (trait_iter == str_iter->second.end())
		{
			const std::pair<trait_to_run_map::iterator, bool> trait_insert_ret = str_iter->second.insert(std::pair<uint128_t, INIT_ONCE>(render_trait, INIT_ONCE()));
			assert(trait_insert_ret.second);
			trait_iter = trait_insert_ret.first;
			InitOnceInitialize(&trait_iter->second);
		}
	}

	glyph_run *a_glyph_run = NULL;
	BOOL pending;
	InitOnceBeginInitialize(&trait_iter->second, 0, &pending, reinterpret_cast<void **>(&a_glyph_run));
	assert((a_glyph_run == NULL) == pending);

	return a_glyph_run;
}

bool glyph_cache::store_glyph_run(string_id_type string_id, uint128_t render_trait, glyph_run *a_glyph_run)
{
	trait_to_run_map::iterator trait_iter;

	{
		bool b_ret;
		string_id_type erased_str;
		std::map<string_id_type, trait_to_run_map>::iterator str_iter;

		const scoped_rw_lock lock_w(scoped_rw_lock::SERVER_GLYPH_RUN_CACHE, false);

		b_ret = _glyph_run_lru.access(string_id, &erased_str);
		if (b_ret)
		{
			// the string is evicted from LRU cache
			// erase all cached glyph run that is under the evicted string ID

			str_iter = _glyph_run_store.find(erased_str);
			assert(str_iter != _glyph_run_store.end());
			erase_glyph_run_cache_string(str_iter);
			_glyph_run_store.erase(str_iter);
		}

		str_iter = _glyph_run_store.find(string_id);
		assert(str_iter != _glyph_run_store.end());
		trait_iter = str_iter->second.find(render_trait);
	}

	InitOnceComplete(&trait_iter->second, (a_glyph_run == NULL ? INIT_ONCE_INIT_FAILED : 0), a_glyph_run);
	return a_glyph_run != NULL;
}

void glyph_cache::erase_glyph_run_cache_string(std::map<string_id_type, trait_to_run_map>::iterator str_iter)
{
	for (trait_to_run_map::iterator trait_iter = str_iter->second.begin(); trait_iter != str_iter->second.end(); ++trait_iter)
	{
		BOOL pending;
		glyph_run *a_glyph_run;
		InitOnceBeginInitialize(&trait_iter->second, INIT_ONCE_CHECK_ONLY, &pending, reinterpret_cast<void **>(&a_glyph_run));
		assert(!pending);
		delete a_glyph_run;
	}
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_server/glyph_cache.h:
namespace gdipp
{

class glyph_cache
{
public:
	typedef uint128_t string_id_type;
	typedef uint128_t char_id_type;
	typedef std::pair<string_id_type, uint128_t> glyph_run_id_type;

	static string_id_type get_string_id(const wchar_t *string, unsigned int count, bool is_glyph_index);
	static char_id_type get_char_id(uint128_t render_trait, FT_UInt index, bool is_glyph_index);

	~glyph_cache();

	void initialize();

	const FT_Glyph lookup_glyph(char_id_type char_id);
	bool store_glyph(char_id_type char_id, const FT_Glyph glyph);
	const glyph_run *lookup_glyph_run(string_id_type string_id, uint128_t render_trait);
	bool store_glyph_run(string_id_type string_id, uint128_t render_trait, glyph_run *a_glyph_run);

private:
	// std::map from render trait to glyph run
	typedef std::map<uint128_t, INIT_ONCE> trait_to_run_map;

	void erase_glyph_run_cache_string(std::map<string_id_type, trait_to_run_map>::iterator str_iter);

	// std::map from character ID (including character index and render trait) to its glyph
	std::map<char_id_type, INIT_ONCE> _glyph_store;
	// std::map from string ID to glyph run
	// use hierarchical design so that when LRU string is evicted, all associated glyph runs are erased
	std::map<string_id_type, trait_to_run_map> _glyph_run_store;

	// least recently used glyph runs, indexed by string ID
	lru_list<string_id_type> _glyph_run_lru;
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_server/glyph_run.h:
namespace gdipp
{

class glyph_run
{
public:
	// information for a glyph run, minimum units in the glyph run cache

	// glyph data pointers
	// different glyph runs could share same glyph, therefore each glyph is the minimum units in the glyph cache
	std::vector<FT_Glyph> glyphs;

	
	// the bounding boxes are dependent to specific glyph run
	// control box is the formal positioning according to the glyph's advance std::vector
	// black box, on the other hand, is the actual positioning, with glyph's bearing and bitmap width concerned
	// the left border of the first glyph's control box always starts at 0, while the black box varies
	
	std::vector<RECT> ctrl_boxes;
	std::vector<RECT> black_boxes;
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_server/helper.cpp:
namespace gdipp
{

FIXED fixed_from_26dot6(signed long x)
{
	signed long y = (x << 10);
	return *(reinterpret_cast<FIXED *>(&y));
}

signed long fixed_to_26dot6(const FIXED &x)
{
	return *(reinterpret_cast<const signed long *>(&x)) >> 10;
}

signed long float_to_16dot16(double x)
{
	return static_cast<FT_Pos>(x * 65536);
}

LONG int_from_16dot16(signed long x)
{
	const LONG ret = (x >> 16);

	if (ret == 0 && x > 0)
		return 1;
	else
		return ret;
}

LONG int_from_26dot6(signed long x)
{
	const LONG ret = (x >> 6);

	if (ret == 0 && x > 0)
		return 1;
	else
		return ret;
}

DWORD create_tls_index()
{
	DWORD new_tls_index = TlsAlloc();
	assert(new_tls_index != TLS_OUT_OF_INDEXES);

	return new_tls_index;
}

BOOL free_tls_index(DWORD tls_index)
{
	return TlsFree(tls_index);
}

BYTE division_by_255(short number, short numerator)
{
	// there are many approaches to approximate number * numerator / 255
	// it is a trade-off between efficiency and accuracy

	const int t = number * numerator;
	return (((t + 255) >> 8) + t) >> 8;
}

uint128_t generate_render_trait(const LOGFONTW *logfont, int render_mode)
{
	// the LOGFONTW structure and render mode are the minimal set that uniquely determine font metrics used by any renderer

	// exclude the bytes after the face name, which may contain junk data
	const int lf_metric_size = sizeof(LOGFONTW) - sizeof(logfont->lfFaceName);
	const int lf_facename_size = static_cast<const int>((wcslen(logfont->lfFaceName) * sizeof(wchar_t)));
	const int lf_total_size = lf_metric_size + lf_facename_size;

	uint128_t render_trait;
#ifdef _M_X64
	MurmurHash3_x64_128(logfont, lf_total_size, render_mode, &render_trait);
#else
	MurmurHash3_x86_128(logfont, lf_total_size, render_mode, &render_trait);
#endif
	return render_trait;
}

POINT get_baseline(UINT alignment, int x, int y, int width, int ascent, int descent)
{
	POINT baseline = {x, y};

	switch ((TA_LEFT | TA_RIGHT | TA_CENTER) & alignment)
	{
	case TA_LEFT:
		break;
	case TA_RIGHT:
		baseline.x -= width;
		break;
	case TA_CENTER:
		baseline.x -= width / 2;
		break;
	}

	switch ((TA_TOP | TA_BOTTOM | TA_BASELINE) & alignment)
	{
	case TA_TOP:
		baseline.y += ascent;
		break;
	case TA_BOTTOM:
		baseline.y -= descent;
		break;
	case TA_BASELINE:
		break;
	}

	return baseline;
}

int get_bmp_pitch(int width, WORD bpp)
{
#define FT_PAD_FLOOR( x, n )  ( (x) & ~((n)-1) )
#define FT_PAD_ROUND( x, n )  FT_PAD_FLOOR( (x) + ((n)/2), n )
#define FT_PAD_CEIL( x, n )   FT_PAD_FLOOR( (x) + ((n)-1), n )

	return FT_PAD_CEIL(static_cast<int>(ceil(static_cast<double>(width * bpp) / 8)), sizeof(LONG));
}

bool get_dc_bmp_header(HDC hdc, BITMAPINFOHEADER &dc_bmp_header)
{
	dc_bmp_header.biSize = sizeof(BITMAPINFOHEADER);

	const HBITMAP dc_bitmap = static_cast<const HBITMAP>(GetCurrentObject(hdc, OBJ_BITMAP));
	if (dc_bitmap == NULL)
	{
		// currently no selected bitmap
		// use DC capability

		dc_bmp_header.biWidth = GetDeviceCaps(hdc, HORZRES);
		dc_bmp_header.biHeight = GetDeviceCaps(hdc, VERTRES);
		dc_bmp_header.biPlanes = GetDeviceCaps(hdc, PLANES);
		dc_bmp_header.biBitCount = GetDeviceCaps(hdc, BITSPIXEL);

		return false;
	}
	else
	{
		// do not return the color table
		dc_bmp_header.biBitCount = 0;
		const int i_ret = GetDIBits(hdc, dc_bitmap, 0, 0, NULL, reinterpret_cast<LPBITMAPINFO>(&dc_bmp_header), DIB_RGB_COLORS);
		assert(i_ret != 0);

		return true;
	}
}

OUTLINETEXTMETRICW *get_dc_metrics(HDC hdc, std::vector<BYTE> &metric_buf)
{
	// get outline metrics of the DC, which also include the text metrics

	UINT metric_size = GetOutlineTextMetricsW(hdc, 0, NULL);
	if (metric_size == 0)
		return NULL;

	metric_buf.resize(metric_size);
	OUTLINETEXTMETRICW *outline_metrics = reinterpret_cast<OUTLINETEXTMETRICW *>(&metric_buf[0]);
	metric_size = GetOutlineTextMetricsW(hdc, metric_size, outline_metrics);
	assert(metric_size != 0);

	return outline_metrics;
}

int get_glyph_bmp_width(const FT_Bitmap &bitmap)
{
	if (bitmap.pixel_mode == FT_PIXEL_MODE_LCD)
		return bitmap.width / 3;
	else
		return bitmap.width;
}


LOGFONTW get_log_font(HDC hdc)
{
	HFONT h_font = reinterpret_cast<HFONT>(GetCurrentObject(hdc, OBJ_FONT));
	assert(h_font != NULL);

	LOGFONTW font_attr;
	GetObject(h_font, sizeof(LOGFONTW), &font_attr);

	return font_attr;
}

bool get_render_mode(const render_config_static::render_mode_static &render_mode_conf, WORD dc_bmp_bpp, BYTE font_quality, FT_Render_Mode *render_mode)
{
	// return true if successfully find an appropriate render mode
	// otherwise return false

	if (render_mode_conf.mono == 2)
	{
		*render_mode = FT_RENDER_MODE_MONO;
		return true;
	}

	if (render_mode_conf.gray == 2)
	{
		*render_mode = FT_RENDER_MODE_NORMAL;
		return true;
	}

	if (render_mode_conf.subpixel == 2)
	{
		*render_mode = FT_RENDER_MODE_LCD;
		return true;
	}

	if (!render_mode_conf.aliased && font_quality == NONANTIALIASED_QUALITY)
		return false;

	if (render_mode_conf.mono == 1 && dc_bmp_bpp == 1)
	{
		*render_mode = FT_RENDER_MODE_MONO;
		return true;
	}

	if (render_mode_conf.gray == 1 && dc_bmp_bpp == 8)
	{
		*render_mode = FT_RENDER_MODE_NORMAL;
		return true;
	}

	// we do not support 16 bpp currently

	if (render_mode_conf.subpixel == 1 && dc_bmp_bpp >= 24)
	{
		*render_mode = FT_RENDER_MODE_LCD;
		return true;
	}

	return false;
}

bool operator<(const LOGFONTW &lf1, const LOGFONTW &lf2)
{
	return memcmp(&lf1, &lf2, sizeof(LOGFONTW)) < 0;
}

bool mb_to_wc(const char *multi_byte_str, int count, std::wstring &wide_char_str)
{
	int wc_str_len = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, multi_byte_str, count, NULL, 0);
	if (wc_str_len == 0)
		return false;

	wide_char_str.resize(wc_str_len);
	wc_str_len = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, multi_byte_str, count, &wide_char_str[0], wc_str_len);
	if (wc_str_len == 0)
		return false;

	return true;
}

BOOL paint_background(HDC hdc, const RECT *bg_rect, COLORREF bg_color)
{
	int i_ret;

	if (bg_color == CLR_INVALID)
		return FALSE;

	const HBRUSH bg_brush = CreateSolidBrush(bg_color);
	if (bg_brush == NULL)
		return FALSE;

	i_ret = FillRect(hdc, bg_rect, bg_brush);
	if (i_ret == 0)
		return FALSE;

	DeleteObject(bg_brush);
	return TRUE;
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_server/helper.h:
namespace gdipp
{

const double pi = acos(-1.0);

// convert 26.6 fixed float type to 16.16 fixed point
FIXED fixed_from_26dot6(signed long x);

// convert 16.16 fixed point to 26.6 format
signed long fixed_to_26dot6(const FIXED &x);

// convert floating point to 16.16 format
signed long float_to_16dot16(double x);

// convert 16.16 fixed float type to integer
LONG int_from_16dot16(signed long x);

// convert 26.6 fixed float type to integer
LONG int_from_26dot6(signed long x);

DWORD create_tls_index();
BOOL free_tls_index(DWORD tls_index);

// high-performance division method to approximate number * numerator / 255
//BYTE division_by_255(short number, short numerator);

uint128_t generate_render_trait(const LOGFONTW *logfont, int render_mode);

// apply alignment on the reference point and use it to calculate the baseline
POINT get_baseline(UINT alignment, int x, int y, int width, int ascent, int descent);

// for given bitmap width and bit count, compute the bitmap pitch
int get_bmp_pitch(int width, WORD bpp);

// retrieve BITMAPINFOHEADER from the selected bitmap of the given DC
bool get_dc_bmp_header(HDC hdc, BITMAPINFOHEADER &dc_dc_bmp_header);

// get outline metrics of the DC
OUTLINETEXTMETRICW *get_dc_metrics(HDC hdc, std::vector<BYTE> &metric_buf);

int get_glyph_bmp_width(const FT_Bitmap &bitmap);

//LONG get_glyph_run_width(const glyph_run *a_glyph_run, bool is_control_width);

LOGFONTW get_log_font(HDC hdc);

// return true and fill the corresponding FT_Glyph_To_Bitmap render mode if find an appropriate render mode
// otherwise, return false
bool get_render_mode(const render_config_static::render_mode_static &render_mode_conf, WORD dc_bmp_bpp, BYTE font_quality, FT_Render_Mode *render_mode);

bool operator<(const LOGFONTW &lf1, const LOGFONTW &lf2);

//const FT_Glyph make_empty_outline_glyph();

//bool mb_to_wc(const char *multi_byte_str, int count, std::wstring &wide_char_str);

BOOL paint_background(HDC hdc, const RECT *bg_rect, COLORREF bg_color);

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_server/os2_metrics.cpp:
namespace gdipp
{

#define OS2_TABLE_TAG mmioFOURCC('O', 'S', '/', '2')

// little-endian <-> big-endian
#define SWAPWORD(x) MAKEWORD(HIBYTE(x), LOBYTE(x))
#define SWAPLONG(x) MAKELONG(SWAPWORD(HIWORD(x)), SWAPWORD(LOWORD(x)))

bool os2_metrics::init(HDC hdc)
{
	// retrieve needed fields from the OS/2 table

	DWORD font_data_size;

	font_data_size = GetFontData(hdc, OS2_TABLE_TAG, offsetof(TT_OS2, xAvgCharWidth), &_xAvgCharWidth, sizeof(_xAvgCharWidth));
	if (font_data_size == GDI_ERROR)
		return false;

	font_data_size = GetFontData(hdc, OS2_TABLE_TAG, offsetof(TT_OS2, usWeightClass), &_usWeightClass, sizeof(_usWeightClass));
	if (font_data_size == GDI_ERROR)
		return false;

	font_data_size = GetFontData(hdc, OS2_TABLE_TAG, offsetof(TT_OS2, usWidthClass), &_usWidthClass, sizeof(_usWidthClass));
	if (font_data_size == GDI_ERROR)
		return false;

	font_data_size = GetFontData(hdc, OS2_TABLE_TAG, offsetof(TT_OS2, fsSelection), &_fsSelection, sizeof(_fsSelection));
	if (font_data_size == GDI_ERROR)
		return false;

	_xAvgCharWidth = SWAPWORD(_xAvgCharWidth);
	_usWeightClass = SWAPWORD(_usWeightClass);
	_usWidthClass = SWAPWORD(_usWidthClass);
	_fsSelection = SWAPWORD(_fsSelection);

	return true;
}

bool os2_metrics::init(void *font_id)
{
	// retrieve needed fields from the OS/2 table

	DWORD font_data_size;

	const HDC font_holder = dc_pool_instance.claim();
	assert(font_holder != NULL);
	font_mgr_instance.select_font(font_id, font_holder);

	font_data_size = GetFontData(font_holder, OS2_TABLE_TAG, offsetof(TT_OS2, xAvgCharWidth), reinterpret_cast<byte *>(&_xAvgCharWidth), sizeof(_xAvgCharWidth));
	if (font_data_size == GDI_ERROR)
		goto failed_init_os2_metrics;

	font_data_size = GetFontData(font_holder, OS2_TABLE_TAG, offsetof(TT_OS2, usWeightClass), reinterpret_cast<byte *>(&_usWeightClass), sizeof(_usWeightClass));
	if (font_data_size == GDI_ERROR)
		goto failed_init_os2_metrics;

	font_data_size = GetFontData(font_holder, OS2_TABLE_TAG, offsetof(TT_OS2, usWidthClass), reinterpret_cast<byte *>(&_usWidthClass), sizeof(_usWidthClass));
	if (font_data_size == GDI_ERROR)
		goto failed_init_os2_metrics;

	font_data_size = GetFontData(font_holder, OS2_TABLE_TAG, offsetof(TT_OS2, fsSelection), reinterpret_cast<byte *>(&_fsSelection), sizeof(_fsSelection));
	if (font_data_size == GDI_ERROR)
		goto failed_init_os2_metrics;

	_xAvgCharWidth = SWAPWORD(_xAvgCharWidth);
	_usWeightClass = SWAPWORD(_usWeightClass);
	_usWidthClass = SWAPWORD(_usWidthClass);
	_fsSelection = SWAPWORD(_fsSelection);

	return true;

failed_init_os2_metrics:
	dc_pool_instance.free(font_holder);
	return false;
}

FT_Short os2_metrics::get_xAvgCharWidth() const
{
	return _xAvgCharWidth;
}

char os2_metrics::get_weight_class() const
{
	return get_gdi_weight_class(_usWeightClass);
}

FT_UShort os2_metrics::get_usWidthClass() const
{
	return _usWidthClass;
}

bool os2_metrics::is_italic() const
{
	return (_fsSelection & 1);
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_server/os2_metrics.h:
namespace gdipp
{

class os2_metrics
{
public:
	bool init(HDC hdc);
	bool init(void *font_id);

	FT_Short get_xAvgCharWidth() const;
	char get_weight_class() const;
	FT_UShort get_usWidthClass() const;
	bool is_italic() const;

private:
	FT_Short _xAvgCharWidth;
	FT_UShort _usWeightClass;
	FT_UShort _usWidthClass;
	FT_UShort _fsSelection;
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_server/renderer.cpp:
namespace gdipp
{

renderer::renderer(rpc_session *render_session)
	: _session(render_session)
{
}

renderer::~renderer()
{
}

bool renderer::render(bool is_glyph_index, LPCWSTR lpString, UINT c, glyph_run *new_glyph_run)
{
	return true;
}

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_server/renderer.h:
namespace gdipp
{

class renderer
{
public:
	explicit renderer(rpc_session *render_session);
	virtual ~renderer();
	virtual bool render(bool is_glyph_index, LPCWSTR lpString, UINT c, glyph_run *new_glyph_run);

protected:
	rpc_session *_session;
};

}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_server/rpc_server.cpp:
namespace gdipp
{

HANDLE process_heap = GetProcessHeap();




DWORD WINAPI start_gdipp_rpc_server(LPVOID lpParameter)
{
	if (process_heap == NULL)
		return 1;

	//bool b_ret;
	RPC_STATUS rpc_status;

	scoped_rw_lock::initialize();
	server_cache_size = min(config_instance.get_number(L"/gdipp/server/cache_size/text()", server_config::CACHE_SIZE), 24);
	glyph_cache_instance.initialize();
	initialize_freetype();

	//b_ret = rpc_index_initialize();
	//if (!b_ret)
	//	return 1;

	rpc_status = RpcServerUseProtseqEpW(reinterpret_cast<RPC_WSTR>(L"ncalrpc"), RPC_C_PROTSEQ_MAX_REQS_DEFAULT, reinterpret_cast<RPC_WSTR>(L"gdipp"), NULL);
	if (rpc_status != RPC_S_OK)
		return 1;

	rpc_status = RpcServerRegisterIf(gdipp_rpc_v1_0_s_ifspec, NULL, NULL);
	if (rpc_status != RPC_S_OK)
		return 1;

	rpc_status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, TRUE);
	if (rpc_status != RPC_S_OK)
		return 1;

	rpc_status = RpcMgmtWaitServerListen();
	if (rpc_status != RPC_S_OK)
		return 1;

	return 0;
}

bool stop_gdipp_rpc_server()
{
	//bool b_ret;
	RPC_STATUS rpc_status;

	rpc_status = RpcMgmtStopServerListening(NULL);
	if (rpc_status != RPC_S_OK)
		return false;

	//b_ret = rpc_index_shutdown();
	//assert(b_ret);

	destroy_freetype();

	return true;
}

}

void __RPC_FAR *__RPC_USER MIDL_user_allocate(size_t size)
{
	return HeapAlloc(gdipp::process_heap, HEAP_GENERATE_EXCEPTIONS, size);
}

void __RPC_USER MIDL_user_free(void __RPC_FAR *ptr)
{
	HeapFree(gdipp::process_heap, 0, ptr);
}

/* [fault_status][comm_status] */ error_status_t gdipp_rpc_begin_session( 
	/* [in] */ handle_t h_gdipp_rpc,
	/* [size_is][in] */ const byte *logfont_buf,
	/* [in] */ unsigned long logfont_size,
	/* [in] */ unsigned short bits_per_pixel,
	/* [out] */ GDIPP_RPC_SESSION_HANDLE *h_session)
{
	if (logfont_size != sizeof(LOGFONTW))
		return RPC_S_INVALID_ARG;

	const HDC session_font_holder = gdipp::dc_pool_instance.claim();
	assert(session_font_holder != NULL);

	// register font with given LOGFONT structure
	const LOGFONTW *logfont = reinterpret_cast<const LOGFONTW *>(logfont_buf);
	BYTE *outline_metrics_buf;
	unsigned long outline_metrics_size;

	void *session_font_id = gdipp::font_mgr_instance.register_font(session_font_holder, logfont, &outline_metrics_buf, &outline_metrics_size);
	if (session_font_id == NULL)
	{
		gdipp::dc_pool_instance.free(session_font_holder);
		return RPC_S_INVALID_ARG;
	}

	const OUTLINETEXTMETRICW *outline_metrics = reinterpret_cast<const OUTLINETEXTMETRICW *>(outline_metrics_buf);
	// generate config trait and retrieve font-specific config
	const LONG point_size = (logfont->lfHeight > 0 ? logfont->lfHeight : -MulDiv(logfont->lfHeight, 72, outline_metrics->otmTextMetrics.tmDigitizedAspectY));
	const char weight_class = gdipp::get_gdi_weight_class(static_cast<unsigned short>(outline_metrics->otmTextMetrics.tmWeight));
	const gdipp::render_config_static *session_render_config = gdipp::font_render_config_cache_instance.get_font_render_config(!!weight_class,
		!!outline_metrics->otmTextMetrics.tmItalic,
		point_size,
		metric_face_name(outline_metrics));
	if (session_render_config->renderer == gdipp::server_config::RENDERER_CLEARTYPE)
	{
		gdipp::dc_pool_instance.free(session_font_holder);
		return RPC_S_OK;
	}

	FT_Render_Mode session_render_mode;
	if (!gdipp::get_render_mode(session_render_config->render_mode, bits_per_pixel, logfont->lfQuality, &session_render_mode))
	{
		gdipp::dc_pool_instance.free(session_font_holder);
		return RPC_S_INVALID_ARG;
	}

	gdipp::rpc_session *new_session = reinterpret_cast<gdipp::rpc_session *>(MIDL_user_allocate(sizeof(gdipp::rpc_session)));

	new_session->bits_per_pixel = bits_per_pixel;
	new_session->font_holder = session_font_holder;
	new_session->font_id = session_font_id;
	new_session->log_font = *reinterpret_cast<const LOGFONTW *>(logfont_buf);
	new_session->outline_metrics_buf = outline_metrics_buf;
	new_session->outline_metrics_size = outline_metrics_size;
	new_session->render_config = session_render_config;
	new_session->render_mode = session_render_mode;
	new_session->render_trait = gdipp::generate_render_trait(logfont, new_session->render_mode);

	// create session renderer
	switch (session_render_config->renderer)
	{
	case gdipp::server_config::RENDERER_DIRECTWRITE:
		//break;
	case gdipp::server_config::RENDERER_FREETYPE:
		new_session->renderer = new gdipp::ft_renderer(new_session);
		break;
	case gdipp::server_config::RENDERER_GETGLYPHOUTLINE:
		new_session->renderer = new gdipp::ggo_renderer(new_session);
		break;
	case gdipp::server_config::RENDERER_WIC:
		break;
	default:
		break;
	}

	*h_session = reinterpret_cast<GDIPP_RPC_SESSION_HANDLE>(new_session);
	return RPC_S_OK;
}

/* [fault_status][comm_status] */ error_status_t gdipp_rpc_get_font_size( 
	/* [in] */ handle_t h_gdipp_rpc,
	/* [context_handle_noserialize][in] */ GDIPP_RPC_SESSION_HANDLE h_session,
	/* [in] */ unsigned long table,
	/* [in] */ unsigned long offset,
	/* [out] */ unsigned long *font_size)
{
	const gdipp::rpc_session *curr_session = reinterpret_cast<const gdipp::rpc_session *>(h_session);
	*font_size = GetFontData(curr_session->font_holder, table, offset, NULL, 0);

	return RPC_S_OK;
}

/* [fault_status][comm_status] */ error_status_t gdipp_rpc_get_font_data( 
	/* [in] */ handle_t h_gdipp_rpc,
	/* [context_handle_noserialize][in] */ GDIPP_RPC_SESSION_HANDLE h_session,
	/* [in] */ unsigned long table,
	/* [in] */ unsigned long offset,
	/* [size_is][out] */ byte *data_buf,
	/* [in] */ unsigned long buf_size)
{
	const gdipp::rpc_session *curr_session = reinterpret_cast<const gdipp::rpc_session *>(h_session);

	// TODO: output pointer is not allocated with MIDL_user_allocate
	// TODO: return value not returned
	GetFontData(curr_session->font_holder, table, offset, data_buf, buf_size);

	return RPC_S_OK;
}

/* [fault_status][comm_status] */ error_status_t gdipp_rpc_get_font_metrics_size( 
	/* [in] */ handle_t h_gdipp_rpc,
	/* [context_handle_noserialize][in] */ GDIPP_RPC_SESSION_HANDLE h_session,
	/* [out] */ unsigned long *metrics_size)
{
	const gdipp::rpc_session *curr_session = reinterpret_cast<const gdipp::rpc_session *>(h_session);
	*metrics_size = curr_session->outline_metrics_size;

	return RPC_S_OK;
}

/* [fault_status][comm_status] */ error_status_t gdipp_rpc_get_font_metrics_data( 
	/* [in] */ handle_t h_gdipp_rpc,
	/* [context_handle_noserialize][in] */ GDIPP_RPC_SESSION_HANDLE h_session,
	/* [size_is][out] */ byte *metrics_buf,
	/* [in] */ unsigned long buf_size)
{
	const gdipp::rpc_session *curr_session = reinterpret_cast<const gdipp::rpc_session *>(h_session);
	const DWORD copy_size = min(curr_session->outline_metrics_size, buf_size);
	CopyMemory(metrics_buf, curr_session->outline_metrics_buf, copy_size);

	return RPC_S_OK;
}

/* [fault_status][comm_status] */ error_status_t gdipp_rpc_get_glyph_indices( 
	/* [in] */ handle_t h_gdipp_rpc,
	/* [context_handle_noserialize][in] */ GDIPP_RPC_SESSION_HANDLE h_session,
	/* [size_is][string][in] */ const wchar_t *str,
	/* [in] */ int count,
	/* [size_is][out] */ unsigned short *gi)
{
	const gdipp::rpc_session *curr_session = reinterpret_cast<const gdipp::rpc_session *>(h_session);

	// TODO: output pointer is not allocated with MIDL_user_allocate
	// TODO: return value not returned
	GetGlyphIndices(curr_session->font_holder, str, count, gi, GGI_MARK_NONEXISTING_GLYPHS);

	return RPC_S_OK;
}

/* [fault_status][comm_status] */ error_status_t gdipp_rpc_make_bitmap_glyph_run( 
	/* [in] */ handle_t h_gdipp_rpc,
	/* [context_handle_noserialize][in] */ GDIPP_RPC_SESSION_HANDLE h_session,
	/* [string][in] */ const wchar_t *string,
	/* [in] */ unsigned int count,
	/* [in] */ boolean is_glyph_index,
	/* [out] */ gdipp_rpc_bitmap_glyph_run *glyph_run_ptr)
{
	if (count == 0)
		return RPC_S_INVALID_ARG;

	const gdipp::rpc_session *curr_session = reinterpret_cast<const gdipp::rpc_session *>(h_session);
	bool b_ret;

	// generate unique identifier for the string
	const gdipp::glyph_cache::string_id_type string_id = gdipp::glyph_cache::get_string_id(string, count, !!is_glyph_index);

	// check if a glyph run cached for the same rendering environment and string
	const gdipp::glyph_run *glyph_run = gdipp::glyph_cache_instance.lookup_glyph_run(string_id, curr_session->render_trait);
	if (!glyph_run)
	{
		// no cached glyph run. render new glyph run
		gdipp::glyph_run *new_glyph_run = new gdipp::glyph_run();
		b_ret = curr_session->renderer->render(!!is_glyph_index, string, count, new_glyph_run);
		if (!b_ret)
			return RPC_S_OUT_OF_MEMORY;

		// and cache it
		gdipp::glyph_cache_instance.store_glyph_run(string_id, curr_session->render_trait, new_glyph_run);
		glyph_run = new_glyph_run;
	}

	// convert internal glyph run to RPC exchangable format

	// allocate space for glyph run
	glyph_run_ptr->count = static_cast<UINT>(glyph_run->glyphs.size());
	glyph_run_ptr->glyphs = reinterpret_cast<gdipp_rpc_bitmap_glyph *>(MIDL_user_allocate(sizeof(gdipp_rpc_bitmap_glyph) * glyph_run_ptr->count));
	glyph_run_ptr->ctrl_boxes = reinterpret_cast<RECT *>(MIDL_user_allocate(sizeof(RECT) * glyph_run_ptr->count));
	glyph_run_ptr->black_boxes = reinterpret_cast<RECT *>(MIDL_user_allocate(sizeof(RECT) * glyph_run_ptr->count));
	glyph_run_ptr->render_mode = curr_session->render_mode;

	for (unsigned int i = 0; i < glyph_run_ptr->count; ++i)
	{
		glyph_run_ptr->ctrl_boxes[i] = glyph_run->ctrl_boxes[i];
		glyph_run_ptr->black_boxes[i] = glyph_run->black_boxes[i];

		if (glyph_run->glyphs[i] == NULL)
		{
			glyph_run_ptr->glyphs[i].buffer = NULL;
			continue;
		}

		const FT_BitmapGlyph bmp_glyph = reinterpret_cast<const FT_BitmapGlyph>(glyph_run->glyphs[i]);
		glyph_run_ptr->glyphs[i].left = bmp_glyph->left;
		glyph_run_ptr->glyphs[i].top = bmp_glyph->top;
		glyph_run_ptr->glyphs[i].rows = bmp_glyph->bitmap.rows;
		glyph_run_ptr->glyphs[i].width = bmp_glyph->bitmap.width;
		glyph_run_ptr->glyphs[i].pitch = bmp_glyph->bitmap.pitch;
		const int buffer_size = bmp_glyph->bitmap.rows * abs(bmp_glyph->bitmap.pitch);
		glyph_run_ptr->glyphs[i].buffer = reinterpret_cast<byte *>(MIDL_user_allocate(buffer_size));
		memcpy(glyph_run_ptr->glyphs[i].buffer, bmp_glyph->bitmap.buffer, buffer_size);
	}

	return RPC_S_OK;
}

/* [fault_status][comm_status] */ error_status_t gdipp_rpc_make_outline_glyph_run( 
	/* [in] */ handle_t h_gdipp_rpc,
	/* [context_handle_noserialize][in] */ GDIPP_RPC_SESSION_HANDLE h_session,
	/* [string][in] */ const wchar_t *string,
	/* [in] */ unsigned int count,
	/* [in] */ boolean is_glyph_index,
	/* [out] */ gdipp_rpc_outline_glyph_run *glyph_run_ptr)
{
	return ERROR_CALL_NOT_IMPLEMENTED;
}

error_status_t gdipp_rpc_end_session( 
    /* [in] */ handle_t h_gdipp_rpc,
    /* [out][in] */ GDIPP_RPC_SESSION_HANDLE *h_session)
{
	const gdipp::rpc_session *curr_session = reinterpret_cast<const gdipp::rpc_session *>(*h_session);
	if (curr_session == NULL)
		return RPC_S_INVALID_ARG;

	delete[] curr_session->outline_metrics_buf;
	delete curr_session->renderer;
	gdipp::dc_pool_instance.free(curr_session->font_holder);
	MIDL_user_free(*h_session);

	*h_session = NULL;
	return RPC_S_OK;
}

void __RPC_USER GDIPP_RPC_SESSION_HANDLE_rundown(GDIPP_RPC_SESSION_HANDLE h_session)
{
	error_status_t e = gdipp_rpc_end_session(NULL, &h_session);
	assert(e == 0);
}

// --------------------------------------------------------
// Users/virgilming/ReGDI/gdipp_server/rpc_server.h:
namespace gdipp
{

class renderer;

// actual session handle structure
struct rpc_session
{
	unsigned short bits_per_pixel;
	HDC font_holder;
	void *font_id;
	
	// LOGFONT is not directly mapped to a font
	// instead, it is just a hint of how to create a font
	// font links may affect the mapping result
	// therefore, LOGFONT is part of session information
	
	LOGFONTW log_font;
	BYTE *outline_metrics_buf;
	unsigned long outline_metrics_size;
	const render_config_static *render_config;
	FT_Render_Mode render_mode;
	uint128_t render_trait;
	renderer *renderer;
};

DWORD WINAPI start_gdipp_rpc_server(LPVOID lpParameter);
bool stop_gdipp_rpc_server();

}