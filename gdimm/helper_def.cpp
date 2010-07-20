#include "stdafx.h"
#include "helper_def.h"
#include "helper_func.h"
#include "gdimm.h"

bool dc_context::init(HDC hdc)
{
	if (!get_dc_bmp_header(hdc, bmp_header))
		return false;

	outline_metrics = get_dc_metrics(hdc, _metric_buf);
	if (outline_metrics == NULL)
		return false;

	const gdimm_font_trait font_trait = {metric_face_name(outline_metrics),
		get_gdi_weight_class((unsigned short) outline_metrics->otmTextMetrics.tmWeight),
		!!outline_metrics->otmTextMetrics.tmItalic};
	setting_cache = setting_cache_instance.lookup(font_trait);

	log_font = get_log_font(hdc);

	if (!get_render_mode(setting_cache, bmp_header.biBitCount, log_font.lfQuality, render_mode))
		return false;

	this->hdc = hdc;

	return true;
}