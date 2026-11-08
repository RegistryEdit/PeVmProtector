#include "LicenseRuntime.h"
#include "LicenseDialog.h"
#include "PeVmCrypto.h"
#include <windows.h>
#include <exception>
#include <vector>

namespace pevm::activation {
bool UseChineseLicenseUi() { return PRIMARYLANGID(GetThreadUILanguage()) == LANG_CHINESE; }
namespace {
constexpr int KIntro = 3110, KMachineLabel = 3111, KLicenseLabel = 3112;
struct DialogState {
    const LicensePolicy& Policy;
    const std::filesystem::path& Wrapper;
    const std::string& InitialReason;
    bool Chinese;
    std::string Result;
    std::exception_ptr Error;
};

const wchar_t* Explain(const std::string& Reason, bool Chinese) {
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
        Dword(0); Word(10); Word(0); Word(0); Word(360); Word(216);
        Word(0); Word(0); Text(L"License activation");
        Word(9); Text(Chinese ? L"Microsoft YaHei UI" : L"Segoe UI");
        Item(0, 14, 12, 332, 30, KIntro, 0x82, L"");
        Item(0, 14, 47, 332, 12, KMachineLabel, 0x82, L"");
        Item(WS_BORDER | WS_TABSTOP | ES_READONLY | ES_AUTOHSCROLL, 14, 61, 332, 17, KMachineInput, 0x81, L"");
        Item(0, 14, 86, 332, 12, KLicenseLabel, 0x82, L"");
        Item(WS_BORDER | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL, 14, 100, 332, 19, KLicenseInput, 0x81, L"");
        Item(WS_TABSTOP | BS_AUTOCHECKBOX, 14, 124, 160, 14, KShowLicense, 0x80, L"");
        Item(0, 14, 145, 332, 28, KLicenseReason, 0x82, L"");
        Item(WS_TABSTOP | BS_DEFPUSHBUTTON, 164, 183, 108, 23, IDOK, 0x80, L"");
        Item(WS_TABSTOP | BS_PUSHBUTTON, 280, 183, 66, 23, IDCANCEL, 0x80, L"");
        Item(SS_ETCHEDHORZ, 14, 175, 332, 1, 0xffff, 0x82, L"");
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
            SetDlgItemTextW(Window, KIntro, State->Chinese
                ? L"验证卡密后启动程序。验证成功后自动记住卡密，供当前 Windows 用户下次使用。"
                : L"Verify your license to start. A verified license is remembered for this Windows user on subsequent starts.");
            SetDlgItemTextW(Window, KMachineLabel, State->Chinese ? L"本机机器码（可选中复制给签发方）" : L"Machine ID (select and copy for your license issuer)");
            const auto Machine = crypto::Hex(license::MachineId());
            SetDlgItemTextW(Window, KMachineInput, std::wstring(Machine.begin(), Machine.end()).c_str());
            SetDlgItemTextW(Window, KLicenseLabel, State->Chinese ? L"卡密（支持粘贴）" : L"License (paste the complete key)");
            SetDlgItemTextW(Window, KShowLicense, State->Chinese ? L"显示卡密" : L"Show license");
            SetDlgItemTextW(Window, IDOK, State->Chinese ? L"验证并启动" : L"Verify and start");
            SetDlgItemTextW(Window, IDCANCEL, State->Chinese ? L"取消" : L"Cancel");
            SetDlgItemTextW(Window, KLicenseReason, Explain(State->InitialReason, State->Chinese));
            SendDlgItemMessageW(Window, KLicenseInput, EM_SETLIMITTEXT, license::KMaximumTextBytes + 1, 0);
            SetFocus(GetDlgItem(Window, KLicenseInput));
            return FALSE;
        }
        if (!State) return FALSE;
        if (Message == WM_CLOSE || (Message == WM_COMMAND && LOWORD(WParam) == IDCANCEL)) {
            EndDialog(Window, IDCANCEL); return TRUE;
        }
        if (Message != WM_COMMAND) return FALSE;
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
            if (Reason.empty() && TryVerifyLicense(State->Policy, Text, Reason)) {
                State->Result = license::FormatLicense(license::ParseLicense(Text));
                SetWindowTextW(Input, L"");
                EndDialog(Window, IDOK); return TRUE;
            }
        }
        SetDlgItemTextW(Window, KLicenseReason, Explain(Reason, State->Chinese));
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
