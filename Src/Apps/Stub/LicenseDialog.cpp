#include "LicenseRuntime.h"
#include "LicenseDialog.h"
#include "PeVmCrypto.h"
#include <windows.h>
#include <commctrl.h>
#include <algorithm>
#include <cstring>
#include <exception>
#include <string_view>
#include <vector>

namespace pevm::activation {
bool UseChineseLicenseUi() { return PRIMARYLANGID(GetThreadUILanguage()) == LANG_CHINESE; }
namespace {
constexpr int KIntro = 3110, KMachineLabel = 3111, KLicenseLabel = 3112, KHeading = 3113, KRemember = 3114;
constexpr UINT KRefreshAppearance = WM_APP + 43;
constexpr UINT_PTR KCopyFeedbackTimer = 1;
struct DialogState {
    const LicensePolicy& Policy;
    const std::filesystem::path& Wrapper;
    const std::string& InitialReason;
    bool Chinese;
    std::string Result;
    std::exception_ptr Error;
    std::wstring Machine;
    HWND HotButton{};
    bool StatusError{}, InputError{}, HighContrast{};
    COLORREF Background{}, Ink{}, Muted{}, Accent{}, Border{}, Soft{}, ErrorInk{}, ErrorBackground{};
    HBRUSH BackgroundBrush{}, SoftBrush{}, StatusBrush{};
    HFONT HeadingFont{}, LabelFont{}, MachineFont{};
    ~DialogState() {
        for (const auto Brush : {BackgroundBrush, SoftBrush, StatusBrush}) if (Brush) DeleteObject(Brush);
        for (const auto Font : {HeadingFont, LabelFont, MachineFont}) if (Font) DeleteObject(Font);
    }
};

RECT Units(HWND Window, int X, int Y, int Width, int Height) {
    RECT Area{X, Y, X + Width, Y + Height};
    MapDialogRect(Window, &Area);
    return Area;
}
int Pixels(HWND Window, int Value) { return MulDiv(Value, static_cast<int>(GetDpiForWindow(Window)), 96); }

void Rounded(HDC Dc, const RECT& Area, COLORREF Fill, COLORREF Stroke, int Radius) {
    SelectObject(Dc, GetStockObject(DC_BRUSH)); SetDCBrushColor(Dc, Fill);
    SelectObject(Dc, GetStockObject(DC_PEN)); SetDCPenColor(Dc, Stroke);
    RoundRect(Dc, Area.left, Area.top, Area.right, Area.bottom, Radius, Radius);
}

void SetStatus(HWND Window, DialogState& State, const wchar_t* Text, bool Error = false, bool InputError = false) {
    State.StatusError = Error; State.InputError = InputError;
    if (State.StatusBrush) DeleteObject(State.StatusBrush);
    State.StatusBrush = CreateSolidBrush(Error ? State.ErrorBackground : State.Soft);
    SetDlgItemTextW(Window, KLicenseReason, Text);
    InvalidateRect(Window, nullptr, TRUE);
    InvalidateRect(GetDlgItem(Window, KLicenseReason), nullptr, TRUE);
}

void RefreshAppearance(HWND Window, DialogState& State) {
    HIGHCONTRASTW Contrast{sizeof(Contrast)};
    State.HighContrast = SystemParametersInfoW(SPI_GETHIGHCONTRAST, sizeof(Contrast), &Contrast, 0) &&
        (Contrast.dwFlags & HCF_HIGHCONTRASTON) != 0;
    State.Background = State.HighContrast ? GetSysColor(COLOR_WINDOW) : RGB(255, 255, 255);
    State.Ink = State.HighContrast ? GetSysColor(COLOR_WINDOWTEXT) : RGB(26, 38, 56);
    State.Muted = State.HighContrast ? State.Ink : RGB(92, 105, 123);
    State.Accent = State.HighContrast ? GetSysColor(COLOR_HIGHLIGHT) : RGB(37, 99, 235);
    State.Border = State.HighContrast ? State.Ink : RGB(214, 222, 233);
    State.Soft = State.HighContrast ? State.Background : RGB(245, 248, 252);
    State.ErrorInk = State.HighContrast ? State.Ink : RGB(172, 42, 47);
    State.ErrorBackground = State.HighContrast ? State.Background : RGB(255, 242, 242);
    for (const auto Brush : {State.BackgroundBrush, State.SoftBrush, State.StatusBrush}) if (Brush) DeleteObject(Brush);
    State.BackgroundBrush = CreateSolidBrush(State.Background);
    State.SoftBrush = CreateSolidBrush(State.Soft);
    State.StatusBrush = CreateSolidBrush(State.StatusError ? State.ErrorBackground : State.Soft);

    LOGFONTW Base{};
    auto Font = reinterpret_cast<HFONT>(SendMessageW(Window, WM_GETFONT, 0, 0));
    if (!Font) Font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
    GetObjectW(Font, sizeof(Base), &Base);
    const auto ReplaceFont = [&](HFONT& Old, const LOGFONTW& Description, std::initializer_list<int> Controls) {
        const auto New = CreateFontIndirectW(&Description);
        if (!New) return;
        for (const auto Id : Controls) SendDlgItemMessageW(Window, Id, WM_SETFONT, reinterpret_cast<WPARAM>(New), TRUE);
        if (Old) DeleteObject(Old);
        Old = New;
    };
    auto Heading = Base; Heading.lfHeight = MulDiv(Base.lfHeight, 17, 10); Heading.lfWeight = FW_SEMIBOLD;
    ReplaceFont(State.HeadingFont, Heading, {KHeading});
    auto Label = Base; Label.lfWeight = FW_SEMIBOLD;
    ReplaceFont(State.LabelFont, Label, {KMachineLabel, KLicenseLabel, IDOK});
    auto Machine = Base; wcscpy_s(Machine.lfFaceName, L"Consolas");
    ReplaceFont(State.MachineFont, Machine, {KMachineInput});
    RedrawWindow(Window, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
}

// Keep native buttons/edit controls for accessibility, selection and keyboard handling.
LRESULT CALLBACK ControlProc(HWND Window, UINT Message, WPARAM WParam, LPARAM LParam,
                             UINT_PTR, DWORD_PTR Reference) {
    auto& State = *reinterpret_cast<DialogState*>(Reference);
    const auto Id = GetDlgCtrlID(Window);
    const bool Button = Id == IDOK || Id == IDCANCEL || Id == KCopyMachine || Id == KPasteLicense;
    if (Button && Message == WM_GETDLGCODE)
        return DLGC_BUTTON | (Id == IDOK ? DLGC_DEFPUSHBUTTON : DLGC_UNDEFPUSHBUTTON);
    if (Button && Message == BM_SETSTYLE) {
        // The dialog manager changes the default button on focus moves. Retain owner drawing.
        if (LParam) InvalidateRect(Window, nullptr, TRUE);
        return 0;
    }
    if (Button && Message == WM_MOUSEMOVE && State.HotButton != Window) {
        State.HotButton = Window;
        TRACKMOUSEEVENT Track{sizeof(Track), TME_LEAVE, Window, 0}; TrackMouseEvent(&Track);
        InvalidateRect(Window, nullptr, FALSE);
    }
    if (Button && Message == WM_MOUSELEAVE) {
        if (State.HotButton == Window) State.HotButton = nullptr;
        InvalidateRect(Window, nullptr, FALSE);
    }
    if (!Button && Message == WM_KEYDOWN && WParam == 'A' && GetKeyState(VK_CONTROL) < 0) {
        SendMessageW(Window, EM_SETSEL, 0, -1); return 0;
    }
    if (Id == KLicenseInput && Message == WM_PASTE) {
        SendMessageW(GetParent(Window), WM_COMMAND, KPasteLicense, reinterpret_cast<LPARAM>(Window)); return 0;
    }
    if (Message == WM_SETFOCUS || Message == WM_KILLFOCUS)
        InvalidateRect(GetParent(Window), nullptr, FALSE);
    if (Message == WM_NCDESTROY) RemoveWindowSubclass(Window, ControlProc, 1);
    return DefSubclassProc(Window, Message, WParam, LParam);
}

void DrawStatus(const DRAWITEMSTRUCT& Item, DialogState& State) {
    const auto Saved = SaveDC(Item.hDC);
    FillRect(Item.hDC, &Item.rcItem, State.StatusBrush);
    SelectObject(Item.hDC, reinterpret_cast<HFONT>(SendMessageW(Item.hwndItem, WM_GETFONT, 0, 0)));
    SetBkMode(Item.hDC, TRANSPARENT); SetTextColor(Item.hDC, State.StatusError ? State.ErrorInk : State.Muted);
    wchar_t Text[512]{}; GetWindowTextW(Item.hwndItem, Text, 512);
    auto Area = Item.rcItem;
    DrawTextW(Item.hDC, Text, -1, &Area, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX);
    const auto Height = Area.bottom - Area.top;
    Area = Item.rcItem; Area.top += std::max(0L, (Area.bottom - Area.top - Height) / 2);
    DrawTextW(Item.hDC, Text, -1, &Area, DT_WORDBREAK | DT_NOPREFIX);
    RestoreDC(Item.hDC, Saved);
}

void DrawButton(const DRAWITEMSTRUCT& Item, DialogState& State) {
    const auto Saved = SaveDC(Item.hDC);
    const bool Primary = Item.CtlID == IDOK, Disabled = (Item.itemState & ODS_DISABLED) != 0;
    const bool Pressed = (Item.itemState & ODS_SELECTED) != 0, Hot = State.HotButton == Item.hwndItem;
    auto Fill = Primary && !Disabled ? State.Accent : State.Background;
    if (!State.HighContrast && !Disabled && (Pressed || Hot))
        Fill = Primary ? (Pressed ? RGB(29, 63, 161) : RGB(29, 78, 216)) : RGB(237, 243, 254);
    if (Disabled) Fill = State.Soft;
    const auto Foreground = Disabled ? (State.HighContrast ? GetSysColor(COLOR_GRAYTEXT) : State.Muted) :
        Primary ? (State.HighContrast ? GetSysColor(COLOR_HIGHLIGHTTEXT) : RGB(255, 255, 255)) : State.Ink;
    auto Area = Item.rcItem;
    FillRect(Item.hDC, &Area, (Item.CtlID == IDOK || Item.CtlID == IDCANCEL) ? State.SoftBrush : State.BackgroundBrush);
    Rounded(Item.hDC, Area, Fill, Primary && !Disabled ? Fill : State.Border, Pixels(Item.hwndItem, 8));
    SelectObject(Item.hDC, reinterpret_cast<HFONT>(SendMessageW(Item.hwndItem, WM_GETFONT, 0, 0)));
    SetBkMode(Item.hDC, TRANSPARENT); SetTextColor(Item.hDC, Foreground);
    wchar_t Text[128]{}; GetWindowTextW(Item.hwndItem, Text, 128);
    if (Pressed) OffsetRect(&Area, 0, Pixels(Item.hwndItem, 1));
    DrawTextW(Item.hDC, Text, -1, &Area, DT_CENTER | DT_VCENTER | DT_SINGLELINE |
        ((Item.itemState & ODS_NOACCEL) ? DT_HIDEPREFIX : 0));
    if ((Item.itemState & ODS_FOCUS) && !(Item.itemState & ODS_NOFOCUSRECT)) {
        InflateRect(&Area, -Pixels(Item.hwndItem, 4), -Pixels(Item.hwndItem, 4));
        SetTextColor(Item.hDC, Foreground); SetBkColor(Item.hDC, Fill); DrawFocusRect(Item.hDC, &Area);
    }
    RestoreDC(Item.hDC, Saved);
}

void PaintDialog(HWND Window, HDC Dc, DialogState& State) {
    const auto Saved = SaveDC(Dc);
    RECT Client{}; GetClientRect(Window, &Client); FillRect(Dc, &Client, State.BackgroundBrush);
    auto Footer = Units(Window, 0, 240, 384, 42); FillRect(Dc, &Footer, State.SoftBrush);
    SetDCPenColor(Dc, State.Border); SelectObject(Dc, GetStockObject(DC_PEN));
    MoveToEx(Dc, 0, Footer.top, nullptr); LineTo(Dc, Client.right, Footer.top);
    for (const auto Id : {KMachineInput, KLicenseInput}) {
        const auto Area = Id == KMachineInput ? Units(Window, 24, 79, 336, 24) : Units(Window, 24, 137, 336, 27);
        const auto Border = Id == KLicenseInput && State.InputError ? State.ErrorInk :
            GetFocus() == GetDlgItem(Window, Id) ? State.Accent : State.Border;
        Rounded(Dc, Area, State.Background, Border, Pixels(Window, 8));
    }
    auto Status = Units(Window, 24, 196, 336, 32);
    const auto StatusFill = State.StatusError ? State.ErrorBackground : State.Soft;
    Rounded(Dc, Status, StatusFill, State.HighContrast ? State.Border : StatusFill, Pixels(Window, 8));
    auto Mark = Units(Window, 29, 196, 10, 32);
    SetTextColor(Dc, State.StatusError ? State.ErrorInk : State.Accent); SetBkMode(Dc, TRANSPARENT);
    SelectObject(Dc, State.LabelFont);
    DrawTextW(Dc, State.StatusError ? L"!" : L"i", 1, &Mark, DT_CENTER | DT_SINGLELINE | DT_VCENTER);

    // Small key emblem, drawn locally without an icon font or external assets.
    auto Icon = Units(Window, 24, 13, 27, 29);
    Rounded(Dc, Icon, State.Soft, State.Soft, Pixels(Window, 12));
    const auto Pen = CreatePen(PS_SOLID, Pixels(Window, 2), State.HighContrast ? State.Ink : State.Accent);
    const auto OldPen = SelectObject(Dc, Pen); SelectObject(Dc, GetStockObject(HOLLOW_BRUSH));
    const int Left = Icon.left + Pixels(Window, 9), Ring = Pixels(Window, 10), Top = (Icon.top + Icon.bottom - Ring) / 2;
    Ellipse(Dc, Left, Top, Left + Ring, Top + Ring);
    MoveToEx(Dc, Left + Ring - Pixels(Window, 1), Top + Ring / 2, nullptr);
    LineTo(Dc, Icon.right - Pixels(Window, 8), Top + Ring / 2);
    LineTo(Dc, Icon.right - Pixels(Window, 8), Top + Ring / 2 + Pixels(Window, 5));
    SelectObject(Dc, OldPen); DeleteObject(Pen);
    RestoreDC(Dc, Saved);
}

struct Clipboard {
    bool Open{};
    explicit Clipboard(HWND Owner) {
        for (int Attempt = 0; Attempt < 4; ++Attempt) {
            if (OpenClipboard(Owner)) { Open = true; break; }
            if (Attempt < 3) Sleep(5);
        }
    }
    ~Clipboard() { if (Open) CloseClipboard(); }
};
bool CopyMachine(HWND Window, std::wstring_view Text) {
    const auto Memory = GlobalAlloc(GMEM_MOVEABLE, (Text.size() + 1) * sizeof(wchar_t));
    if (!Memory) return false;
    const auto Data = static_cast<wchar_t*>(GlobalLock(Memory));
    if (!Data) { GlobalFree(Memory); return false; }
    std::memcpy(Data, Text.data(), Text.size() * sizeof(wchar_t)); Data[Text.size()] = 0;
    GlobalUnlock(Memory);
    Clipboard Clip(Window);
    if (Clip.Open && EmptyClipboard() && SetClipboardData(CF_UNICODETEXT, Memory)) return true;
    GlobalFree(Memory); return false;
}

bool ReadClipboard(HWND Window, std::wstring& Text, std::string& Reason) {
    Clipboard Clip(Window);
    if (!Clip.Open) { Reason = "clipboard busy"; return false; }
    const auto Memory = GetClipboardData(CF_UNICODETEXT);
    if (!Memory) { Reason = "clipboard text missing"; return false; }
    const auto Data = static_cast<const wchar_t*>(GlobalLock(Memory));
    if (!Data) { Reason = "clipboard text missing"; return false; }
    struct Unlock { HANDLE Memory; ~Unlock() { GlobalUnlock(Memory); } } Lock{Memory};
    const auto Capacity = GlobalSize(Memory) / sizeof(wchar_t);
    const auto Limit = std::min(Capacity, license::KMaximumTextBytes + 1);
    std::size_t Length{};
    while (Length < Limit && Data[Length]) ++Length;
    if (Length > license::KMaximumTextBytes) { Reason = "license too long"; return false; }
    if (Length == Capacity || !Length) { Reason = "clipboard text missing"; return false; }
    Text.assign(Data, Length);
    return true;
}

const wchar_t* Explain(const std::string& Reason, bool Chinese) {
    if (Reason == "license upgrade required") return Chinese
        ? L"此程序需要新版卡密，请联系签发方重新签发。原卡密仍可用于旧版程序。"
        : L"This app requires a new license. Ask your issuer to reissue it; the existing license still works with older apps.";
    if (Reason == "license required" || Reason.empty()) return Chinese
        ? L"请输入签发给本机的完整卡密。" : L"Enter the complete license issued for this device.";
    if (Reason == "license expired") return Chinese ? L"卡密已过期，请输入续期后的卡密。" : L"This license has expired. Enter a renewed license.";
    if (Reason == "license machine mismatch") return Chinese ? L"此卡密不适用于本机，请核对机器码。" : L"This license belongs to another device. Check the machine ID.";
    if (Reason == "license product mismatch" || Reason == "license signing key mismatch") return Chinese
        ? L"此卡密不适用于当前产品，请核对签发信息。" : L"This license belongs to a different product or issuer.";
    if (Reason.find("clock") != std::string::npos || Reason == "invalid license time") return Chinese
        ? L"卡密时间无效，请检查系统时间或联系签发方。" : L"License time is invalid. Check the system clock or contact the issuer.";
    if (Reason.find("saved license") != std::string::npos) return Chinese
        ? L"已保存的卡密不可用，请重新输入。" : L"The saved license is unavailable. Enter your license again.";
    if (Reason.find("long") != std::string::npos) return Chinese
        ? L"卡密过长，最多允许 4096 个 ASCII 字符。" : L"License is too long. The limit is 4096 ASCII characters.";
    if (Reason.find("ASCII") != std::string::npos) return Chinese
        ? L"卡密只能包含 ASCII 字符，请直接粘贴完整卡密。" : L"License must contain ASCII characters only. Paste the complete license.";
    if (Reason == "clipboard busy") return Chinese
        ? L"剪贴板暂时被占用，请稍后重试。" : L"The clipboard is busy. Please try again.";
    if (Reason == "clipboard text missing") return Chinese
        ? L"剪贴板中没有文字，请先复制完整卡密。" : L"No text on the clipboard. Copy your complete license first.";
    return Chinese ? L"卡密格式或签名无效，请核对后重新输入。" : L"Invalid license format or signature. Check it and try again.";
}

// Build a standard dialog in memory so wrapper resource merging cannot replace it.
class Template {
public:
    std::vector<WORD> Data;
    void Word(WORD Value) { Data.push_back(Value); }
    void Dword(DWORD Value) { Word(LOWORD(Value)); Word(HIWORD(Value)); }
    void Text(const wchar_t* Value) { do { Word(static_cast<WORD>(*Value)); } while (*Value++); }
    void Align() { if (Data.size() & 1) Word(0); }
    void Item(DWORD Style, short X, short Y, short W, short H, WORD Id, WORD Class, const wchar_t* Caption) {
        Align(); Dword(WS_CHILD | WS_VISIBLE | Style); Dword(0);
        Word(X); Word(Y); Word(W); Word(H); Word(Id);
        Word(0xffff); Word(Class); Text(Caption); Word(0);
    }
    explicit Template(bool Chinese) {
        Dword(WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_MODALFRAME | DS_SETFONT | DS_CENTER);
        Dword(0); Word(13); Word(0); Word(0); Word(384); Word(282);
        Word(0); Word(0); Text(L"License activation");
        Word(9); Text(Chinese ? L"Microsoft YaHei UI" : L"Segoe UI");
        Item(SS_NOPREFIX, 62, 10, 298, 25, KHeading, 0x82, L"");
        Item(SS_NOPREFIX | SS_PATHELLIPSIS, 62, 37, 298, 14, KIntro, 0x82, L"");
        Item(0, 24, 60, 230, 14, KMachineLabel, 0x82, L"");
        Item(WS_TABSTOP | ES_READONLY | ES_AUTOHSCROLL, 32, 84, 320, 15, KMachineInput, 0x81, L"");
        Item(WS_TABSTOP | BS_OWNERDRAW, 274, 53, 86, 23, KCopyMachine, 0x80, L"");
        Item(0, 24, 118, 230, 14, KLicenseLabel, 0x82, L"");
        Item(WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL, 32, 143, 320, 16, KLicenseInput, 0x81, L"");
        Item(WS_TABSTOP | BS_OWNERDRAW, 274, 110, 86, 23, KPasteLicense, 0x80, L"");
        Item(WS_TABSTOP | BS_AUTOCHECKBOX, 24, 171, 240, 15, KShowLicense, 0x80, L"");
        Item(SS_OWNERDRAW, 42, 199, 308, 26, KLicenseReason, 0x82, L"");
        Item(SS_NOPREFIX, 24, 248, 154, 28, KRemember, 0x82, L"");
        Item(WS_TABSTOP | BS_OWNERDRAW, 182, 248, 66, 26, IDCANCEL, 0x80, L"");
        Item(WS_TABSTOP | BS_OWNERDRAW, 256, 248, 104, 26, IDOK, 0x80, L"");
    }
};

INT_PTR CALLBACK DialogProc(HWND Window, UINT Message, WPARAM WParam, LPARAM LParam) noexcept {
    auto* State = reinterpret_cast<DialogState*>(GetWindowLongPtrW(Window, DWLP_USER));
    try {
        if (Message == WM_INITDIALOG) {
            State = reinterpret_cast<DialogState*>(LParam);
            SetWindowLongPtrW(Window, DWLP_USER, reinterpret_cast<LONG_PTR>(State));
            const auto Title = (State->Chinese ? L"卡密验证 — " : L"License activation — ") + State->Wrapper.filename().wstring();
            SetWindowTextW(Window, Title.c_str());
            SetDlgItemTextW(Window, KHeading, State->Chinese ? L"激活程序" : L"Activate your app");
            SetDlgItemTextW(Window, KIntro, State->Wrapper.filename().c_str());
            SetDlgItemTextW(Window, KMachineLabel, State->Chinese ? L"本机机器码(&M)" : L"Machine ID (&M)");
            const auto Machine = crypto::Hex(license::MachineId());
            State->Machine.assign(Machine.begin(), Machine.end());
            SetDlgItemTextW(Window, KMachineInput, State->Machine.c_str());
            SetDlgItemTextW(Window, KCopyMachine, State->Chinese ? L"复制机器码(&C)" : L"&Copy ID");
            SetDlgItemTextW(Window, KLicenseLabel, State->Chinese ? L"输入卡密(&L)" : L"License key (&L)");
            SetDlgItemTextW(Window, KPasteLicense, State->Chinese ? L"粘贴卡密(&P)" : L"&Paste key");
            SetDlgItemTextW(Window, KShowLicense, State->Chinese ? L"显示卡密(&S)" : L"&Show license key");
            SetDlgItemTextW(Window, KRemember, State->Chinese ? L"验证成功后自动记住卡密\n供当前 Windows 用户使用"
                : L"Remembered automatically\nfor this Windows user");
            SetDlgItemTextW(Window, IDOK, State->Chinese ? L"验证并启动" : L"Verify and start");
            SetDlgItemTextW(Window, IDCANCEL, State->Chinese ? L"取消" : L"Cancel");
            RefreshAppearance(Window, *State);
            SetStatus(Window, *State, Explain(State->InitialReason, State->Chinese),
                !State->InitialReason.empty() && State->InitialReason != "license required");
            SendDlgItemMessageW(Window, KLicenseInput, EM_SETLIMITTEXT, license::KMaximumTextBytes + 1, 0);
            SendDlgItemMessageW(Window, KLicenseInput, EM_SETPASSWORDCHAR, 0x25cf, 0);
            for (const auto Id : {KMachineInput, KLicenseInput, KCopyMachine, KPasteLicense, IDCANCEL, IDOK})
                if (!SetWindowSubclass(GetDlgItem(Window, Id), ControlProc, 1, reinterpret_cast<DWORD_PTR>(State)))
                    throw std::runtime_error("cannot initialize license dialog controls");
            SendMessageW(Window, DM_SETDEFID, IDOK, 0);
            EnableWindow(GetDlgItem(Window, IDOK), FALSE);
            SetFocus(GetDlgItem(Window, KLicenseInput));
            return FALSE;
        }
        if (!State) return FALSE;
        if (Message == WM_CLOSE || (Message == WM_COMMAND && LOWORD(WParam) == IDCANCEL)) {
            EndDialog(Window, IDCANCEL); return TRUE;
        }
        if (Message == WM_DPICHANGED || Message == WM_SETTINGCHANGE || Message == WM_SYSCOLORCHANGE || Message == WM_THEMECHANGED) {
            // Let the dialog manager scale its layout and base font before rebuilding derived fonts.
            PostMessageW(Window, KRefreshAppearance, 0, 0); return FALSE;
        }
        if (Message == KRefreshAppearance) { RefreshAppearance(Window, *State); return TRUE; }
        if (Message == WM_ERASEBKGND) { return TRUE; }
        if (Message == WM_PAINT) {
            PAINTSTRUCT Paint{}; const auto Dc = BeginPaint(Window, &Paint);
            PaintDialog(Window, Dc, *State); EndPaint(Window, &Paint); return TRUE;
        }
        if (Message == WM_LBUTTONDOWN) {
            const POINT Point{static_cast<short>(LOWORD(LParam)), static_cast<short>(HIWORD(LParam))};
            for (const auto Id : {KMachineInput, KLicenseInput}) {
                const auto Area = Id == KMachineInput ? Units(Window, 24, 79, 336, 24) : Units(Window, 24, 137, 336, 27);
                if (PtInRect(&Area, Point)) { SetFocus(GetDlgItem(Window, Id)); return TRUE; }
            }
        }
        if (Message == WM_DRAWITEM) {
            const auto& Item = *reinterpret_cast<const DRAWITEMSTRUCT*>(LParam);
            if (Item.CtlType == ODT_BUTTON) { DrawButton(Item, *State); return TRUE; }
            if (Item.CtlType == ODT_STATIC && Item.CtlID == KLicenseReason) { DrawStatus(Item, *State); return TRUE; }
        }
        if (Message == WM_CTLCOLORDLG || Message == WM_CTLCOLORSTATIC || Message == WM_CTLCOLOREDIT || Message == WM_CTLCOLORBTN) {
            const auto Dc = reinterpret_cast<HDC>(WParam);
            const auto Id = GetDlgCtrlID(reinterpret_cast<HWND>(LParam));
            auto Foreground = State->Ink, Background = State->Background;
            auto Brush = State->BackgroundBrush;
            if (Id == KIntro || Id == KRemember) Foreground = State->Muted;
            if (Id == KRemember) { Background = State->Soft; Brush = State->SoftBrush; }
            if (Id == KLicenseReason) {
                Foreground = State->StatusError ? State->ErrorInk : State->Muted;
                Background = State->StatusError ? State->ErrorBackground : State->Soft; Brush = State->StatusBrush;
            }
            SetTextColor(Dc, Foreground); SetBkColor(Dc, Background);
            return reinterpret_cast<INT_PTR>(Brush);
        }
        if (Message == WM_TIMER && WParam == KCopyFeedbackTimer) {
            KillTimer(Window, KCopyFeedbackTimer);
            SetDlgItemTextW(Window, KCopyMachine, State->Chinese ? L"复制机器码(&C)" : L"&Copy ID");
            return TRUE;
        }
        if (Message != WM_COMMAND) return FALSE;
        if (LOWORD(WParam) == KCopyMachine) {
            if (CopyMachine(Window, State->Machine)) {
                SetDlgItemTextW(Window, KCopyMachine, State->Chinese ? L"已复制" : L"Copied");
                SetTimer(Window, KCopyFeedbackTimer, 2000, nullptr);
            } else SetStatus(Window, *State, Explain("clipboard busy", State->Chinese), true);
            return TRUE;
        }
        if (LOWORD(WParam) == KPasteLicense) {
            std::wstring Text; std::string Reason;
            if (!ReadClipboard(Window, Text, Reason)) {
                SetStatus(Window, *State, Explain(Reason, State->Chinese), true); return TRUE;
            }
            if (std::any_of(Text.begin(), Text.end(), [](wchar_t C) { return C > 127; })) {
                SetStatus(Window, *State, Explain("license must be ASCII", State->Chinese), true); return TRUE;
            }
            // Trim only boundary whitespace; internal characters still reach the real verifier.
            const auto Start = Text.find_first_not_of(L" \t\r\n");
            Text = Start == std::wstring::npos ? L"" : Text.substr(Start, Text.find_last_not_of(L" \t\r\n") - Start + 1);
            const auto Input = GetDlgItem(Window, KLicenseInput);
            if (reinterpret_cast<HWND>(LParam) == Input) {
                // Ctrl+V replaces the selection; the dedicated button replaces the whole key.
                DWORD Begin{}, End{};
                SendMessageW(Input, EM_GETSEL, reinterpret_cast<WPARAM>(&Begin), reinterpret_cast<LPARAM>(&End));
                const auto Existing = GetWindowTextLengthW(Input);
                if (static_cast<std::size_t>(Existing) - (End - Begin) + Text.size() > license::KMaximumTextBytes) {
                    SetStatus(Window, *State, Explain("license too long", State->Chinese), true); return TRUE;
                }
            } else SendMessageW(Input, EM_SETSEL, 0, -1);
            SendMessageW(Input, EM_REPLACESEL, TRUE, reinterpret_cast<LPARAM>(Text.c_str())); SetFocus(Input);
            return TRUE;
        }
        if (LOWORD(WParam) == KLicenseInput && HIWORD(WParam) == EN_CHANGE) {
            const bool HasText = GetWindowTextLengthW(GetDlgItem(Window, KLicenseInput)) != 0;
            EnableWindow(GetDlgItem(Window, IDOK), HasText);
            SetStatus(Window, *State, State->Chinese
                ? L"粘贴完整卡密，然后点击“验证并启动”。" : L"Paste the complete license, then choose Verify and start.");
            return TRUE;
        }
        if (LOWORD(WParam) == KShowLicense && HIWORD(WParam) == BN_CLICKED) {
            SendDlgItemMessageW(Window, KLicenseInput, EM_SETPASSWORDCHAR,
                IsDlgButtonChecked(Window, KShowLicense) == BST_CHECKED ? 0 : 0x25cf, 0);
            InvalidateRect(GetDlgItem(Window, KLicenseInput), nullptr, TRUE);
            return TRUE;
        }
        if (LOWORD(WParam) != IDOK) return FALSE;
        const auto Input = GetDlgItem(Window, KLicenseInput);
        const auto Length = GetWindowTextLengthW(Input);
        std::string Reason, Text;
        if (Length > static_cast<int>(license::KMaximumTextBytes)) Reason = "license too long";
        else {
            std::vector<wchar_t> Buffer(static_cast<std::size_t>(Length) + 1);
            const auto Read = GetWindowTextW(Input, Buffer.data(), static_cast<int>(Buffer.size()));
            for (int I = 0; I < Read; ++I) {
                if (Buffer[I] > 127) { Reason = "license must be ASCII"; break; }
                Text.push_back(static_cast<char>(Buffer[I]));
            }
            if (Reason.empty() && Text.find_first_not_of(" \t\r\n") == std::string::npos) Reason = "license required";
            if (Reason.empty() && TryVerifyLicense(State->Policy, Text, Reason)) {
                State->Result = license::FormatLicense(license::ParseLicense(Text));
                SetWindowTextW(Input, L"");
                EndDialog(Window, IDOK); return TRUE;
            }
        }
        SetStatus(Window, *State, Explain(Reason, State->Chinese), true, true);
        SetFocus(Input);
        SendMessageW(Input, EM_SETSEL, 0, -1);
        return TRUE;
    } catch (...) {
        if (State) State->Error = std::current_exception();
        EndDialog(Window, -2);
        return TRUE;
    }
}
} // namespace

std::string PromptForLicense(const LicensePolicy& Policy, const std::filesystem::path& Wrapper,
                             const std::string& InitialReason) {
    // Restore the caller's DPI context before executing the protected application.
    const auto Previous = SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    struct DpiGuard { DPI_AWARENESS_CONTEXT Previous; ~DpiGuard() {
        if (Previous) SetThreadDpiAwarenessContext(Previous);
    } } Guard{Previous};
    DialogState State{Policy, Wrapper, InitialReason, UseChineseLicenseUi(), {}, {}};
    Template Layout(State.Chinese);
    const auto Result = DialogBoxIndirectParamW(GetModuleHandleW(nullptr),
        reinterpret_cast<const DLGTEMPLATE*>(Layout.Data.data()), nullptr, DialogProc, reinterpret_cast<LPARAM>(&State));
    if (State.Error) std::rethrow_exception(State.Error);
    if (Result == IDCANCEL) throw Cancelled();
    if (Result != IDOK || State.Result.empty()) throw std::runtime_error("cannot open license dialog");
    return State.Result;
}
} // namespace pevm::activation
