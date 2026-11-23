"""Bilingual i18n helper (Vietnamese / English) and local preference storage for KidGate Tray UI."""

from __future__ import annotations

import json
import os
from pathlib import Path

TRAY_STRINGS: dict[str, dict[str, str]] = {
    "en": {
        "connecting": "KidGate: Connecting...",
        "status_tooltip": "KidGate ({state}) — {mins} min left today",
        "online": "Online",
        "offline": "Offline",
        "menu_today": "What I used today & Audit Log",
        "menu_request_time": "Request more time (+15 min)",
        "menu_language": "Language: English (switch to Tiếng Việt)",
        "req_dialog_title": "Request More Time",
        "req_dialog_prompt": "Why do you need +15 extra minutes? (e.g., finishing homework)",
        "req_sent_title": "Time Request",
        "req_sent_ok": "Your request for +15 minutes was sent to your parent.",
        "req_sent_offline": "You are offline. Your request was saved and will be sent when back online.",
        "err_title": "Error",
        "err_send": "Could not send request: {err}",
        "offline_title": "Offline",
        "err_load_today": "Could not load today's summary: {err}",
        "win_title": "KidGate — What I Used Today & Audit Log",
        "win_header": "KidGate — What I Used Today",
        "win_sub": "Apps used, main domains visited, blocked items, and parent rule changes.",
        "sec_date": "Date: {date}",
        "sec_apps": "=== APPS I USED TODAY ===",
        "sec_apps_empty": "  (No app usage recorded yet today)",
        "sec_sites": "=== WEBSITES VISITED (MAIN DOMAIN ONLY) ===",
        "sec_sites_empty": "  (No website visits recorded yet today)",
        "sec_blocked": "=== BLOCKED ITEMS TODAY ===",
        "sec_blocked_empty": "  (Nothing blocked today)",
        "sec_audit": "=== PARENT RULE CHANGES (READ-ONLY AUDIT LOG) ===",
        "sec_audit_empty": "  (No rule changes recorded)",
        "unit_min": "min",
        "unit_visits": "visits",
        "lang_switched_title": "Language Updated",
        "lang_switched_msg": "Tray UI language switched to English.",
    },
    "vi": {
        "connecting": "KidGate: Đang kết nối...",
        "status_tooltip": "KidGate ({state}) — còn {mins} phút hôm nay",
        "online": "Trực tuyến",
        "offline": "Ngoại tuyến",
        "menu_today": "Hôm nay em đã dùng gì & Nhật ký",
        "menu_request_time": "Xin thêm thời gian (+15 phút)",
        "menu_language": "Ngôn ngữ: Tiếng Việt (chuyển sang English)",
        "req_dialog_title": "Xin thêm thời gian",
        "req_dialog_prompt": "Lý do cần thêm 15 phút? (ví dụ: làm nốt bài tập)",
        "req_sent_title": "Yêu cầu thêm giờ",
        "req_sent_ok": "Đã gửi yêu cầu xin thêm 15 phút tới phụ huynh.",
        "req_sent_offline": "Đang ngoại tuyến. Yêu cầu đã được lưu và sẽ gửi khi có mạng.",
        "err_title": "Lỗi",
        "err_send": "Không thể gửi yêu cầu: {err}",
        "offline_title": "Ngoại tuyến",
        "err_load_today": "Không thể tải thống kê hôm nay: {err}",
        "win_title": "KidGate — Hôm nay em đã dùng gì & Nhật ký",
        "win_header": "KidGate — Hôm nay em đã dùng gì",
        "win_sub": "Ứng dụng đã dùng, tên miền chính, mục đã chặn và lịch sử thay đổi quy tắc.",
        "sec_date": "Ngày: {date}",
        "sec_apps": "=== ỨNG DỤNG ĐÃ DÙNG HÔM NAY ===",
        "sec_apps_empty": "  (Chưa có dữ liệu ứng dụng hôm nay)",
        "sec_sites": "=== TRANG WEB ĐÃ TRUY CẬP (CHỈ TÊN MIỀN CHÍNH) ===",
        "sec_sites_empty": "  (Chưa có lượt truy cập web hôm nay)",
        "sec_blocked": "=== MỤC ĐÃ TẠM CHẶN HÔM NAY ===",
        "sec_blocked_empty": "  (Hôm nay không có mục nào bị chặn)",
        "sec_audit": "=== LỊCH SỬ THAY ĐỔI QUY TẮC (CHỈ ĐỌC) ===",
        "sec_audit_empty": "  (Chưa có thay đổi quy tắc nào)",
        "unit_min": "phút",
        "unit_visits": "lượt",
        "lang_switched_title": "Đã đổi ngôn ngữ",
        "lang_switched_msg": "Giao diện khay hệ thống đã chuyển sang Tiếng Việt.",
    },
}


def get_prefs_path() -> Path:
    """Return per-user writable path for Tray UI preferences."""
    base = os.environ.get("LOCALAPPDATA")
    if base:
        return Path(base) / "KidGate" / "tray_prefs.json"
    return Path.home() / ".kidgate" / "tray_prefs.json"


def load_tray_language(prefs_path: Path | None = None) -> str:
    path = prefs_path or get_prefs_path()
    try:
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            lang = str(data.get("language", "en")).lower()
            if lang in TRAY_STRINGS:
                return lang
    except Exception:
        pass
    return "en"


def save_tray_language(lang: str, prefs_path: Path | None = None) -> None:
    if lang not in TRAY_STRINGS:
        return
    path = prefs_path or get_prefs_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"language": lang}, indent=2), encoding="utf-8")
    except Exception:
        pass


def tray_t(lang: str, key: str, **kwargs: object) -> str:
    table = TRAY_STRINGS.get(lang, TRAY_STRINGS["en"])
    template = table.get(key, TRAY_STRINGS["en"].get(key, key))
    return template.format(**kwargs) if kwargs else template
