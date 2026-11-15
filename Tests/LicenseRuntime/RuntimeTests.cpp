#include "../../Src/Apps/Stub/LicenseRuntime.h"
#include "../../Src/Apps/Stub/LicenseClock.h"
#include "../../Src/Apps/Stub/LicenseDialog.h"
#include "PeVmCrypto.h"
#include "FileIo.h"
#include <windows.h>
#include <dpapi.h>
#include <ole2.h>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>
#include <vector>

namespace {
using namespace pevm::activation;
using namespace pevm::license;
namespace fs = std::filesystem;
std::atomic<unsigned> Checks{};
void Require(bool Value, const char* Message) {
    ++Checks;
    if (!Value) throw std::runtime_error(Message);
}
template<class F> void Reject(F&& Action) {
    ++Checks;
    try { Action(); } catch (const std::exception&) { return; }
    throw std::runtime_error("invalid operation accepted");
}
template<class F> void RejectWith(F&& Action, std::string_view Expected) {
    ++Checks;
    try { Action(); }
    catch (const std::exception& Error) {
        if (std::string_view(Error.what()).find(Expected) != std::string_view::npos) return;
        throw std::runtime_error("unexpected rejection: " + std::string(Error.what()));
    }
    throw std::runtime_error("invalid operation accepted");
}
struct EnvironmentGuard {
    std::wstring Name, Value;
    bool Present{};
    explicit EnvironmentGuard(const wchar_t* Name) : Name(Name) {
        SetLastError(ERROR_SUCCESS);
        const auto Size = GetEnvironmentVariableW(Name, nullptr, 0);
        Present = Size || GetLastError() != ERROR_ENVVAR_NOT_FOUND;
        Value.resize(Size ? Size : 1);
        if (Size) GetEnvironmentVariableW(Name, Value.data(), Size);
        SetEnvironmentVariableW(Name, nullptr);
    }
    ~EnvironmentGuard() { SetEnvironmentVariableW(Name.c_str(), Present ? Value.c_str() : nullptr); }
};
std::wstring Wide(const std::string& Text) { return {Text.begin(), Text.end()}; }
void SealFixture(const fs::path& Path, const std::string& Text);

void TestPersistentClock(const fs::path& Work, const fs::path& Private, const LicensePolicy& Policy) {
    const auto Directory = Work / "clocks";
    const auto Machine = MachineId();
    const auto Path = LicenseClockPath(Policy, Machine, Directory);
    const auto Now = CurrentFileTime();
    const auto Advance = [&](std::uint64_t Time) {
        LicenseClockTransaction Clock(Policy, Machine, Directory, Time);
        const auto Effective = Clock.EffectiveTime();
        Clock.Commit();
        return Effective;
    };
    {
        LicenseClockTransaction Cancelled(Policy, Machine, Directory, Now);
        Require(Cancelled.EffectiveTime() == Now, "first clock observation");
    }
    Require(!fs::exists(Path), "uncommitted clock created a time record");
    Require(Advance(Now) == Now, "first clock commit");
    const auto First = util::ReadFile(Path);
    {
        LicenseClockTransaction Invalid(Policy, Machine, Directory, Now + KTicksPerDay);
        auto Forged = IssueLicense(Private, "runtime.test", Machine, 30, Now);
        Forged.Signature[0] ^= 1;
        Require(!VerifyPayload(Forged, Policy, Machine, Invalid.EffectiveTime()).empty(), "forged card accepted");
    }
    Require(util::ReadFile(Path) == First, "failed authorization advanced persistent clock");
    {
        LicenseClockTransaction Expired(Policy, Machine, Directory, Now + 2 * KTicksPerDay);
        const auto Card = IssueLicense(Private, "runtime.test", Machine, 1, Now);
        Require(VerifyPayload(Card, Policy, Machine, Expired.EffectiveTime()) == "license expired",
                "expired card accepted at persistent time");
    }
    Require(util::ReadFile(Path) == First, "expired authorization advanced persistent clock");
    Require(Advance(Now + KTicksPerDay) == Now + KTicksPerDay, "forward clock correction");
    Require(Advance(Now + KTicksPerDay - 1) == Now + KTicksPerDay, "small rollback lowered effective time");
    Reject([&] { Advance(Now); }); // A new transaction models a subsequent process startup.
    Require(fs::exists(Path), "rollback removed persistent state");
    Reject([&] { Advance(0); });
    Reject([&] { Advance(KMaximumTimestamp + 1); });
    auto OtherPolicy = Policy; OtherPolicy.ProductId = ProductId("different.product");
    auto OtherMachine = Machine; OtherMachine[0] ^= 1;
    Require(LicenseClockPath(OtherPolicy, Machine, Directory) != Path, "clock product isolation");
    Require(LicenseClockPath(Policy, OtherMachine, Directory) != Path, "clock device isolation");
    const auto OtherPath = LicenseClockPath(OtherPolicy, Machine, Directory);
    util::WriteFileAtomic(OtherPath, util::ReadFile(Path));
    Reject([&] { LicenseClockTransaction WrongIdentity(OtherPolicy, Machine, Directory, Now + KTicksPerDay); });
    const auto Healthy = util::ReadFile(Path);
    SealFixture(Path, std::string(56, '\0'));
    Reject([&] { Advance(Now + KTicksPerDay); });
    Require(fs::exists(Path), "malformed DPAPI clock record removed");
    util::WriteFileAtomic(Path, std::vector<std::uint8_t>{1, 2, 3});
    Reject([&] { Advance(Now + KTicksPerDay); });
    Require(util::ReadFile(Path).size() == 3, "corrupt clock was silently reset");
    util::WriteFileAtomic(Path, std::vector<std::uint8_t>(4097, 0));
    Reject([&] { Advance(Now + KTicksPerDay); });
    util::WriteFileAtomic(Path, Healthy);
    {
        auto Held = std::make_unique<LicenseClockTransaction>(Policy, Machine, Directory, Now + KTicksPerDay + 10000);
        std::atomic<bool> Entered{}, Finished{};
        std::exception_ptr Failure;
        std::jthread Contender([&] {
            Entered = true;
            try { Advance(Now + KTicksPerDay); Finished = true; }
            catch (...) { Failure = std::current_exception(); }
        });
        while (!Entered) Sleep(1);
        Sleep(50);
        const auto Premature = Finished.load();
        Held->Commit();
        Held.reset();
        Contender.join();
        if (Failure) std::rethrow_exception(Failure);
        Require(!Premature && Finished, "concurrent transaction bypassed product clock lock");
        Require(Advance(Now + KTicksPerDay) == Now + KTicksPerDay + 10000,
                "concurrent writer lowered persistent clock");
    }
    fs::remove(Path);
    fs::create_directory(Path);
    Reject([&] { Advance(Now + KTicksPerDay); });
    fs::remove(Path);
    util::WriteFileAtomic(Path, Healthy);
    const auto Alias = Work / "clock-hardlink.bin";
    Require(CreateHardLinkW(Alias.c_str(), Path.c_str(), nullptr) != FALSE, "clock hardlink fixture");
    Reject([&] { Advance(Now + KTicksPerDay); });
    fs::remove(Alias);
    {
        LicenseClockTransaction Clock(Policy, Machine, Directory, Now + KTicksPerDay);
        Clock.Commit();
        Reject([&] { Clock.Commit(); });
    }
}

// Expired/forged cache fixtures are DPAPI-sealed exactly as a previous installation
// would have saved them. The public filename contains the optional-entropy digest.
void SealFixture(const fs::path& Path, const std::string& Text) {
    const auto Hex = Path.stem().string();
    std::vector<BYTE> Entropy;
    for (std::size_t I = 0; I < Hex.size(); I += 2)
        Entropy.push_back(static_cast<BYTE>(std::stoul(Hex.substr(I, 2), nullptr, 16)));
    DATA_BLOB Input{static_cast<DWORD>(Text.size()), reinterpret_cast<BYTE*>(const_cast<char*>(Text.data()))};
    DATA_BLOB Salt{static_cast<DWORD>(Entropy.size()), Entropy.data()}, Output{};
    if (!CryptProtectData(&Input, L"test fixture", &Salt, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &Output))
        throw std::runtime_error("fixture DPAPI encryption failed");
    struct Free { BYTE* Data; ~Free() { LocalFree(Data); } } Owner{Output.pbData};
    util::WriteFileAtomic(Path, {Output.pbData, Output.cbData});
}

void TestCache(const fs::path& Work, const fs::path& Private, const LicensePolicy& Policy, const std::string& Token) {
    const auto Wrapper = Work / L"应用.exe", Directory = Work / "cache";
    const auto Path = CachePath(Policy, Wrapper, Directory);
    std::string Reason;
    Require(ReadLicenseCache(Policy, Wrapper, Directory, Reason).empty(), "missing cache accepted");
    WriteLicenseCache(Policy, Wrapper, Directory, " \r\n" + Token + "\t");
    const auto Sealed = util::ReadFile(Path);
    Require(std::search(Sealed.begin(), Sealed.end(), Token.begin(), Token.end()) == Sealed.end(), "plaintext token in cache");
    Require(ReadLicenseCache(Policy, Wrapper, Directory, Reason) == Token, "cache roundtrip");
    const auto ClockFile = LicenseClockPath(Policy, MachineId(), LicenseClockDirectory());
    const auto ClockBefore = util::ReadFile(ClockFile);
    util::WriteFileAtomic(ClockFile, std::vector<std::uint8_t>{1, 2, 3});
    Require(ReadLicenseCache(Policy, Wrapper, Directory, Reason).empty() && fs::exists(Path),
            "clock failure removed valid cached card");
    Require(util::ReadFile(ClockFile).size() == 3, "clock failure reset persistent state");
    util::WriteFileAtomic(ClockFile, ClockBefore);
    Require(ReadLicenseCache(Policy, Wrapper, Directory, Reason) == Token, "clock repair did not restore authorization");
    Require(CachePath(Policy, Work / "APP.exe", Directory) == CachePath(Policy, Work / "app.exe", Directory), "path case normalization");
    Require(CachePath(Policy, Work / "sub" / ".." / L"应用.exe", Directory) == Path, "path lexical normalization");
    Reject([&] { WriteLicenseCache(Policy, Wrapper, Directory, "bad"); });
    Require(util::ReadFile(Path) == Sealed, "invalid write destroyed good cache");
    const auto Expired = FormatLicense(IssueLicense(Private, "runtime.test", MachineId(), 1, CurrentFileTime() - 2 * KTicksPerDay));
    Reject([&] { WriteLicenseCache(Policy, Wrapper, Directory, Expired); });
    Require(util::ReadFile(Path) == Sealed, "expired write destroyed good cache");
    const auto Locked = CreateFileW(Path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    Require(Locked != INVALID_HANDLE_VALUE, "cannot lock cache fixture");
    try { Reject([&] { WriteLicenseCache(Policy, Wrapper, Directory, Token); }); }
    catch (...) { CloseHandle(Locked); throw; }
    CloseHandle(Locked);
    Require(util::ReadFile(Path) == Sealed, "failed replacement destroyed good cache");
    SealFixture(Path, Expired);
    Require(ReadLicenseCache(Policy, Wrapper, Directory, Reason).empty() && Reason == "license expired", "cached expiry not rechecked");
    Require(!fs::exists(Path), "expired cache not removed");
    const auto Future = FormatLicense(IssueLicense(Private, "runtime.test", MachineId(), 1, CurrentFileTime() + KTicksPerDay));
    SealFixture(Path, Future);
    Require(ReadLicenseCache(Policy, Wrapper, Directory, Reason).empty() && fs::exists(Path) &&
            Reason == "license issued in the future or system clock rolled back", "clock skew removed signed cache");
    auto Forged = ParseLicense(Token); Forged.Signature[0] ^= 1;
    SealFixture(Path, FormatLicense(Forged));
    Require(ReadLicenseCache(Policy, Wrapper, Directory, Reason).empty() && Reason == "license signature invalid", "cached signature not rechecked");
    auto Corrupt = Sealed; Corrupt.back() ^= 1;
    util::WriteFileAtomic(Path, Corrupt);
    Require(ReadLicenseCache(Policy, Wrapper, Directory, Reason).empty() && !fs::exists(Path), "corrupt cache accepted");
    util::WriteFileAtomic(Path, std::vector<std::uint8_t>(16385));
    Require(ReadLicenseCache(Policy, Wrapper, Directory, Reason).empty(), "oversized cache accepted");
    auto OtherPolicy = Policy; OtherPolicy.ProductId = ProductId("other.product");
    Require(CachePath(OtherPolicy, Wrapper, Directory) != Path, "product not in cache identity");
    util::WriteFileAtomic(CachePath(OtherPolicy, Wrapper, Directory), Sealed);
    Require(ReadLicenseCache(OtherPolicy, Wrapper, Directory, Reason).empty(), "copied product cache accepted");
    GenerateKeyFiles(Work / "other.private", Work / "other.pub");
    const auto OtherKey = MakePolicy(Work / "other.pub", "runtime.test");
    Require(CachePath(OtherKey, Wrapper, Directory) != Path, "public key not in cache identity");
    util::WriteFileAtomic(CachePath(OtherKey, Wrapper, Directory), Sealed);
    Require(ReadLicenseCache(OtherKey, Wrapper, Directory, Reason).empty(), "copied issuer cache accepted");
    const auto Moved = Work / "moved.exe";
    util::WriteFileAtomic(CachePath(Policy, Moved, Directory), Sealed);
    Require(ReadLicenseCache(Policy, Moved, Directory, Reason).empty(), "copied path cache accepted");
    fs::create_directory(Path);
    Require(ReadLicenseCache(Policy, Wrapper, Directory, Reason).empty() && fs::is_directory(Path), "directory entry removed");
    fs::remove(Path);
    WriteNewTextFile(Work / "blocked", "not a directory");
    Reject([&] { WriteLicenseCache(Policy, Wrapper, Work / "blocked", Token); });

    Require(!TryResolveLicense(Policy, Wrapper, Directory, Reason), "missing sources accepted");
    SetEnvironmentVariableW(L"PEVM_LICENSE", L"bad");
    Require(!TryResolveLicense(Policy, Wrapper, Directory, Reason), "invalid env accepted");
    WriteNewTextFile(Wrapper.wstring() + L".license", Token);
    Require(TryResolveLicense(Policy, Wrapper, Directory, Reason), "valid sidecar did not rescue invalid env");
    SetEnvironmentVariableW(L"PEVM_LICENSE", std::wstring(4097, L'A').c_str());
    Require(TryResolveLicense(Policy, Wrapper, Directory, Reason), "valid sidecar did not rescue oversized env");
    SetEnvironmentVariableW(L"PEVM_LICENSE", L"非ASCII");
    Require(TryResolveLicense(Policy, Wrapper, Directory, Reason), "valid sidecar did not rescue non-ASCII env");
    fs::remove(Wrapper.wstring() + L".license");
    WriteNewTextFile(Wrapper.wstring() + L".license", "bad");
    WriteLicenseCache(Policy, Wrapper, Directory, Token);
    Require(TryResolveLicense(Policy, Wrapper, Directory, Reason), "valid cache fallback failed");
    fs::remove(Path);
    Require(!TryResolveLicense(Policy, Wrapper, Directory, Reason), "all invalid sources accepted");
    SetEnvironmentVariableW(L"PEVM_LICENSE", Wide(Token).c_str());
    Require(TryResolveLicense(Policy, Wrapper, Directory, Reason), "valid env failed");
    SetEnvironmentVariableW(L"PEVM_LICENSE", nullptr);
    Reject([&] { EnsureLicense(Policy, Wrapper, false); });
}

struct FindWindowState { DWORD Process; HWND Window{}; bool Warning{}; HWND Button{}; };
BOOL CALLBACK FindDialog(HWND Window, LPARAM Param) {
    auto& State = *reinterpret_cast<FindWindowState*>(Param);
    DWORD Process{}; GetWindowThreadProcessId(Window, &Process);
    if (Process != State.Process) return TRUE;
    if (!State.Warning && GetDlgItem(Window, KLicenseInput)) { State.Window = Window; return FALSE; }
    if (State.Warning && !GetDlgItem(Window, KLicenseInput)) {
        wchar_t Title[128]{}; GetWindowTextW(Window, Title, 128);
        if (std::wstring_view(Title) == L"License could not be remembered" || std::wstring_view(Title) == L"无法记住卡密") {
            // Windows message-box button IDs/layout vary. Discover the real
            // enabled button rather than requiring a direct IDOK child.
            EnumChildWindows(Window, [](HWND Child, LPARAM Param) -> BOOL {
                wchar_t Class[32]{}; GetClassNameW(Child, Class, 32);
                if (std::wstring_view(Class) == L"Button" && IsWindowEnabled(Child)) {
                    *reinterpret_cast<HWND*>(Param) = Child; return FALSE;
                }
                return TRUE;
            }, reinterpret_cast<LPARAM>(&State.Button));
            if (State.Button) { State.Window = Window; return FALSE; }
        }
    }
    return TRUE;
}
LRESULT Send(HWND Window, UINT Message, WPARAM W = 0, LPARAM L = 0) {
    DWORD_PTR Result{};
    // Clipboard operations may synchronously notify this thread's clipboard owner.
    if (!SendMessageTimeoutW(Window, Message, W, L, SMTO_ABORTIFHUNG, 5000, &Result))
        throw std::runtime_error("dialog message timed out: message=" + std::to_string(Message) +
            "; control=" + std::to_string(GetDlgCtrlID(Window)) + "; error=" + std::to_string(GetLastError()));
    return static_cast<LRESULT>(Result);
}
std::wstring ControlText(HWND Control) {
    const auto Size = Send(Control, WM_GETTEXTLENGTH) + 1;
    std::wstring Text(static_cast<std::size_t>(Size), L'\0');
    Text.resize(static_cast<std::size_t>(Send(Control, WM_GETTEXT, Size, reinterpret_cast<LPARAM>(Text.data()))));
    return Text;
}

// Preserve all duplicable clipboard formats, and remove test licenses on exit.
class ClipboardFixture {
    struct Entry { UINT Format; HANDLE Data; };
    HWND Owner{CreateWindowExW(0, L"STATIC", L"", WS_POPUP, 0, 0, 0, 0, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr)};
    std::vector<Entry> Saved;
    bool Open() {
        for (int I = 0; I < 50; ++I) { if (OpenClipboard(Owner)) return true; Sleep(20); }
        return false;
    }
    static void Free(Entry Item) {
        if (Item.Format == CF_BITMAP || Item.Format == CF_PALETTE) DeleteObject(Item.Data);
        else if (Item.Format == CF_ENHMETAFILE) DeleteEnhMetaFile(static_cast<HENHMETAFILE>(Item.Data));
        else if (Item.Format == CF_METAFILEPICT) {
            if (const auto Picture = static_cast<METAFILEPICT*>(GlobalLock(Item.Data))) {
                DeleteMetaFile(Picture->hMF); GlobalUnlock(Item.Data);
            }
            GlobalFree(Item.Data);
        } else GlobalFree(Item.Data);
    }
public:
    ClipboardFixture() {
        Require(Owner != nullptr, "clipboard fixture window failed");
        Require(Open(), "cannot snapshot clipboard");
        try {
            for (UINT Format = EnumClipboardFormats(0); Format; Format = EnumClipboardFormats(Format)) {
                const auto Data = OleDuplicateData(GetClipboardData(Format), static_cast<CLIPFORMAT>(Format), 0);
                Require(Data != nullptr, "cannot preserve clipboard format");
                Saved.push_back({Format, Data});
            }
            CloseClipboard();
        } catch (...) {
            CloseClipboard(); for (const auto Item : Saved) Free(Item);
            DestroyWindow(Owner); throw;
        }
    }
    ~ClipboardFixture() {
        if (Open()) {
            if (EmptyClipboard()) for (auto& Item : Saved)
                if (SetClipboardData(Item.Format, Item.Data)) Item.Data = nullptr;
            CloseClipboard();
        }
        for (const auto Item : Saved) if (Item.Data) Free(Item);
        DestroyWindow(Owner);
    }
    void Put(const std::wstring& Text) {
        const auto Data = GlobalAlloc(GMEM_MOVEABLE, (Text.size() + 1) * sizeof(wchar_t));
        Require(Data != nullptr, "clipboard allocation failed");
        const auto Buffer = GlobalLock(Data);
        Require(Buffer != nullptr, "clipboard lock failed");
        std::memcpy(Buffer, Text.c_str(), (Text.size() + 1) * sizeof(wchar_t)); GlobalUnlock(Data);
        if (!Open()) { GlobalFree(Data); throw std::runtime_error("clipboard busy in test"); }
        const bool Success = EmptyClipboard() && SetClipboardData(CF_UNICODETEXT, Data);
        CloseClipboard(); if (!Success) GlobalFree(Data);
        Require(Success, "cannot set test clipboard");
    }
    std::wstring Read() {
        Require(Open(), "cannot read copied machine ID");
        const auto Data = GetClipboardData(CF_UNICODETEXT);
        const auto Buffer = Data ? static_cast<const wchar_t*>(GlobalLock(Data)) : nullptr;
        std::wstring Text = Buffer ? Buffer : L"";
        if (Buffer) GlobalUnlock(Data); CloseClipboard();
        return Text;
    }
};

void ExpectFocus(HWND Window, HWND Expected) {
    GUITHREADINFO Info{sizeof(Info)};
    const auto Thread = GetWindowThreadProcessId(Window, nullptr);
    for (unsigned I = 0; I < 100; ++I) {
        if (GetGUIThreadInfo(Thread, &Info) && Info.hwndFocus == Expected) return;
        Sleep(20);
    }
    Require(false, "keyboard focus moved to the wrong control");
}
void Capture(HWND Window, const fs::path& Path) {
    const auto PreviousDpi = SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    struct DpiRestore { DPI_AWARENESS_CONTEXT Value; ~DpiRestore() {
        if (Value) SetThreadDpiAwarenessContext(Value);
    } } Dpi{PreviousDpi};
    RECT Rect{}; GetWindowRect(Window, &Rect);
    const auto W = Rect.right - Rect.left, H = Rect.bottom - Rect.top;
    const auto Screen = GetDC(Window), Dc = CreateCompatibleDC(Screen);
    const auto Bitmap = CreateCompatibleBitmap(Screen, W, H);
    const auto Previous = SelectObject(Dc, Bitmap);
    PrintWindow(Window, Dc, 0);
    SelectObject(Dc, Previous);
    BITMAPINFO Info{};
    Info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER); Info.bmiHeader.biWidth = W;
    Info.bmiHeader.biHeight = -H; Info.bmiHeader.biPlanes = 1; Info.bmiHeader.biBitCount = 32;
    std::vector<std::uint8_t> Pixels(static_cast<std::size_t>(W) * H * 4);
    const auto Lines = GetDIBits(Dc, Bitmap, 0, H, Pixels.data(), &Info, DIB_RGB_COLORS);
    DeleteObject(Bitmap); DeleteDC(Dc); ReleaseDC(Window, Screen);
    Require(Lines != 0, "dialog screenshot failed");
    BITMAPFILEHEADER Header{}; Header.bfType = 0x4d42;
    Header.bfOffBits = sizeof(Header) + sizeof(BITMAPINFOHEADER);
    Header.bfSize = Header.bfOffBits + static_cast<DWORD>(Pixels.size());
    std::ofstream File(Path, std::ios::binary);
    File.write(reinterpret_cast<const char*>(&Header), sizeof(Header));
    File.write(reinterpret_cast<const char*>(&Info.bmiHeader), sizeof(BITMAPINFOHEADER));
    File.write(reinterpret_cast<const char*>(Pixels.data()), static_cast<std::streamsize>(Pixels.size()));
    Require(!!File, "cannot write dialog screenshot");
}

// All automation lives in this test process. The production loader exposes no
// auto-submit environment switch, verifier stub or test authorization branch.
void DriveDialog(DWORD Process, const std::string& Token, bool Cancel, const fs::path& Screenshot = {}) {
    FindWindowState Found{Process};
    for (unsigned I = 0; I < 200 && !Found.Window; ++I) {
        EnumWindows(FindDialog, reinterpret_cast<LPARAM>(&Found));
        if (!Found.Window) Sleep(50);
    }
    Require(Found.Window != nullptr, "native license dialog not found");
    const auto Window = Found.Window, Input = GetDlgItem(Window, KLicenseInput);
    const auto RequireInput = [&](const std::wstring& Expected, const char* Message) {
        // Windows blocks cross-process WM_GETTEXT on password controls. Check exact
        // text in local dialogs; wrappers additionally prove the token by launching.
        Require(Process == GetCurrentProcessId() ? ControlText(Input) == Expected :
            static_cast<std::size_t>(Send(Input, WM_GETTEXTLENGTH)) == Expected.size(), Message);
    };
    try {
        Send(Window, WM_NULL); // WM_INITDIALOG must finish before checking initial state.
        Require((GetWindowLongPtrW(Input, GWL_STYLE) & ES_PASSWORD) != 0, "license input is not masked");
        Require(!IsWindowEnabled(GetDlgItem(Window, IDOK)), "empty input enabled activation");
        ExpectFocus(Window, Input);
        if (Cancel) { PostMessageW(Input, WM_KEYDOWN, VK_ESCAPE, 0); return; }
        ClipboardFixture Clipboard;
        if (!Screenshot.empty()) Capture(Window, Screenshot.parent_path() / (Screenshot.stem().wstring() + L"-empty.bmp"));
        PostMessageW(Input, WM_KEYDOWN, VK_TAB, 0);
        ExpectFocus(Window, GetDlgItem(Window, KPasteLicense));
        Send(Window, WM_NEXTDLGCTL, reinterpret_cast<WPARAM>(Input), TRUE);
        Send(GetDlgItem(Window, KCopyMachine), BM_CLICK);
        Require(Clipboard.Read() == Wide(pevm::crypto::Hex(MachineId())), "copy machine ID changed its value");
        Require(ControlText(GetDlgItem(Window, KCopyMachine)).find(L"复制机器码") == std::wstring::npos &&
                ControlText(GetDlgItem(Window, KCopyMachine)) != L"&Copy ID", "copy confirmation missing");
        Send(Input, WM_SETTEXT, 0, reinterpret_cast<LPARAM>(L"preserve-input"));
        for (const auto& Invalid : {std::wstring(), std::wstring(L"非ASCII"), std::wstring(4097, L'A')}) {
            Clipboard.Put(Invalid); Send(GetDlgItem(Window, KPasteLicense), BM_CLICK);
            RequireInput(L"preserve-input", "invalid paste replaced existing input");
            Require(!ControlText(GetDlgItem(Window, KLicenseReason)).empty(), "invalid paste had no feedback");
        }
        Clipboard.Put(L"bad");
        Send(Input, EM_SETSEL, 0, -1);
        Send(Input, WM_PASTE);
        RequireInput(L"bad", "keyboard paste did not use clipboard text");
        Send(Input, EM_SETSEL, 1, 2); Clipboard.Put(L"oo"); Send(Input, WM_PASTE);
        RequireInput(L"bood", "keyboard paste did not replace only the selection");
        Send(Input, EM_UNDO);
        RequireInput(L"bad", "pasting could not be undone");
        Require(IsWindowEnabled(GetDlgItem(Window, IDOK)) != FALSE, "nonempty input did not enable activation");
        for (const auto& Invalid : {std::wstring(), std::wstring(L"bad"), std::wstring(L"非ASCII"), std::wstring(4097, L'A')}) {
            Send(Input, WM_SETTEXT, 0, reinterpret_cast<LPARAM>(Invalid.c_str()));
            Send(Window, WM_COMMAND, IDOK);
            Require(IsWindow(Window) != FALSE, "invalid submission closed dialog");
            wchar_t Reason[512]{};
            Send(GetDlgItem(Window, KLicenseReason), WM_GETTEXT, 512, reinterpret_cast<LPARAM>(Reason));
            Require(Reason[0] != 0, "invalid submission missing reason");
            ExpectFocus(Window, Input);
            if (Invalid == L"bad" && !Screenshot.empty())
                Capture(Window, Screenshot.parent_path() / (Screenshot.stem().wstring() + L"-error.bmp"));
        }
        Send(GetDlgItem(Window, KShowLicense), BM_CLICK);
        Require(Send(Input, EM_GETPASSWORDCHAR) == 0, "show license failed");
        Send(GetDlgItem(Window, KShowLicense), BM_CLICK);
        Require(Send(Input, EM_GETPASSWORDCHAR) != 0, "hide license failed");
        Send(Input, WM_SETTEXT, 0, reinterpret_cast<LPARAM>(L""));
        Require(!IsWindowEnabled(GetDlgItem(Window, IDOK)), "clearing input kept activation enabled");
        const auto Text = Wide(" \t" + Token + " \r\n");
        Clipboard.Put(Text); Send(GetDlgItem(Window, KPasteLicense), BM_CLICK);
        RequireInput(Wide(Token), "paste failed to normalize boundary whitespace");
        ExpectFocus(Window, Input);
        Require(Send(Input, EM_GETPASSWORDCHAR) != 0, "pasting exposed the license");
        if (!Screenshot.empty()) Capture(Window, Screenshot);
        PostMessageW(Input, WM_KEYDOWN, VK_RETURN, 0);
    } catch (...) { PostMessageW(Window, WM_COMMAND, IDCANCEL, 0); throw; }
}

void TestDialog(const fs::path& Work, const LicensePolicy& Policy, const std::string& Token) {
    const auto OriginalLanguage = GetThreadUILanguage();
    for (const bool Chinese : {false, true}) {
        SetThreadUILanguage(MAKELANGID(Chinese ? LANG_CHINESE : LANG_ENGLISH, Chinese ? SUBLANG_CHINESE_SIMPLIFIED : SUBLANG_ENGLISH_US));
        Require(UseChineseLicenseUi() == Chinese, "dialog language selection failed");
        std::exception_ptr DriverError;
        std::thread Driver([&] { try { DriveDialog(GetCurrentProcessId(), Token, false, Work / (Chinese ? "dialog-zh.bmp" : "dialog-en.bmp")); }
            catch (...) { DriverError = std::current_exception(); } });
        std::string Result;
        std::exception_ptr PromptError;
        try { Result = PromptForLicense(Policy, Work / "demo.exe", "license required"); }
        catch (...) { PromptError = std::current_exception(); }
        Driver.join();
        if (DriverError) std::rethrow_exception(DriverError);
        if (PromptError) std::rethrow_exception(PromptError);
        Require(Result == Token, "dialog returned unverified/noncanonical token");
    }
    SetThreadUILanguage(OriginalLanguage);
    std::exception_ptr DriverError;
    std::thread Driver([&] { try { DriveDialog(GetCurrentProcessId(), Token, true); }
        catch (...) { DriverError = std::current_exception(); } });
    bool CancelledInput{};
    try { PromptForLicense(Policy, Work / "demo.exe", "license required"); }
    catch (const Cancelled&) { CancelledInput = true; }
    catch (...) { Driver.join(); throw; }
    Driver.join();
    if (DriverError) std::rethrow_exception(DriverError);
    Require(CancelledInput, "cancel did not abort authorization");
}

DWORD RunWrapper(const fs::path& Wrapper, const std::string& Token, int DialogAction) {
    STARTUPINFOW Start{}; Start.cb = sizeof(Start);
    PROCESS_INFORMATION Process{};
    if (!CreateProcessW(Wrapper.c_str(), nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &Start, &Process))
        throw std::runtime_error("cannot launch test wrapper");
    struct ProcessOwner { PROCESS_INFORMATION P; ~ProcessOwner() {
        if (WaitForSingleObject(P.hProcess, 0) == WAIT_TIMEOUT) TerminateProcess(P.hProcess, 90);
        CloseHandle(P.hThread); CloseHandle(P.hProcess);
    } } Owner{Process};
    if (DialogAction) DriveDialog(Process.dwProcessId, Token, DialogAction == 2);
    if (DialogAction == 3) {
        FindWindowState Warning{Process.dwProcessId, nullptr, true};
        for (unsigned I = 0; I < 200 && !Warning.Window; ++I) {
            EnumWindows(FindDialog, reinterpret_cast<LPARAM>(&Warning));
            if (!Warning.Window) Sleep(50);
        }
        if (!Warning.Window) {
            EnumWindows([](HWND Window, LPARAM Param) -> BOOL {
                DWORD Pid{}; GetWindowThreadProcessId(Window, &Pid);
                if (Pid == static_cast<DWORD>(Param)) {
                    wchar_t Title[256]{}, Class[128]{};
                    GetWindowTextW(Window, Title, 256); GetClassNameW(Window, Class, 128);
                    const auto Length = WideCharToMultiByte(CP_UTF8, 0, Title, -1, nullptr, 0, nullptr, nullptr);
                    std::string Text(Length > 0 ? Length : 1, '\0');
                    WideCharToMultiByte(CP_UTF8, 0, Title, -1, Text.data(), static_cast<int>(Text.size()), nullptr, nullptr);
                    std::cerr << "wrapper window: " << Text.c_str() << "; class="
                              << std::string(Class, Class + std::wcslen(Class))
                              << "; OK=" << GetDlgItem(Window, IDOK)
                              << "; input=" << GetDlgItem(Window, KLicenseInput) << '\n';
                }
                return TRUE;
            }, Process.dwProcessId);
            DWORD Exit{}; GetExitCodeProcess(Process.hProcess, &Exit);
            std::cerr << "wrapper exit code at warning check: " << Exit << '\n';
        }
        Require(Warning.Window != nullptr, "cache write failure warning missing");
        Send(Warning.Button, BM_CLICK);
    }
    Require(WaitForSingleObject(Process.hProcess, 15000) == WAIT_OBJECT_0, "wrapper did not terminate");
    DWORD Code{}; GetExitCodeProcess(Process.hProcess, &Code);
    return Code;
}
void TestWrapper(const fs::path& Wrapper, const fs::path& TokenFile, const fs::path& Public, const std::string& Product) {
    EnvironmentGuard NoDialog(L"PEVM_TEST_NO_DIALOG");
    const auto Policy = MakePolicy(Public, Product);
    const auto Token = FormatLicense(ParseLicense(ReadTextFile(TokenFile)));
    const auto Path = CachePath(Policy, Wrapper, CacheDirectory());
    // The caller provides a freshly built, unique test wrapper. Only its exact cache is touched.
    Require(!fs::exists(Path), "wrapper test cache already exists");
    struct Cleanup { fs::path Path; ~Cleanup() { DeleteFileW(Path.c_str()); RemoveDirectoryW(Path.c_str()); } } Clean{Path};
    const auto ClockPath = LicenseClockPath(Policy, MachineId(), LicenseClockDirectory());
    struct CleanupClock { fs::path Path; ~CleanupClock() {
        DeleteFileW(Path.c_str()); DeleteFileW((Path.wstring() + L".lock").c_str());
    } } ClockClean{ClockPath};
    Require(RunWrapper(Wrapper, Token, 2) == ERROR_CANCELLED, "cancelled wrapper exit code");
    Require(!fs::exists(Path), "cancel created cache");
    Require(!fs::exists(Wrapper.wstring() + L".vmbridge-hit"), "cancel executed protected payload");
    Require(RunWrapper(Wrapper, Token, 1) == 0, "dialog activation failed to execute payload");
    Require(fs::exists(Wrapper.wstring() + L".vmbridge-hit"), "dialog activation missed VM bridge");
    std::string Reason;
    Require(ReadLicenseCache(Policy, Wrapper, CacheDirectory(), Reason) == Token, "dialog did not remember verified license");
    SetEnvironmentVariableW(L"PEVM_TEST_NO_DIALOG", L"1");
    Require(RunWrapper(Wrapper, Token, 0) == 0, "second startup did not use cache");
    util::WriteFileAtomic(Path, std::vector<std::uint8_t>{1, 2, 3});
    Require(RunWrapper(Wrapper, Token, 0) != 0, "corrupt cache authorized wrapper");
    SetEnvironmentVariableW(L"PEVM_TEST_NO_DIALOG", nullptr);
    Require(RunWrapper(Wrapper, Token, 1) == 0, "corrupt cache did not allow reactivation");
    fs::remove(Path);
    fs::create_directory(Path);
    Require(RunWrapper(Wrapper, Token, 3) == 0, "cache write failure blocked valid authorization");
    Require(fs::is_directory(Path), "cache writer replaced directory");
    fs::remove(Path);
}
} // namespace

int wmain(int Argc, wchar_t** Argv) {
    // Bound a failed native-dialog test even if a window cannot be discovered.
    std::jthread Watchdog([](std::stop_token Stop) {
        for (unsigned I = 0; I < 1200 && !Stop.stop_requested(); ++I) Sleep(100);
        if (!Stop.stop_requested()) TerminateProcess(GetCurrentProcess(), 91);
    });
    try {
        EnvironmentGuard License(L"PEVM_LICENSE");
        if (Argc == 6 && std::wstring_view(Argv[1]) == L"--wrapper") {
            std::string Product;
            for (const auto C : std::wstring_view(Argv[5])) {
                if (C > 127) throw std::runtime_error("test product must be ASCII");
                Product.push_back(static_cast<char>(C));
            }
            TestWrapper(Argv[2], Argv[3], Argv[4], Product);
        } else {
            const auto Base = Argc > 1 ? fs::path(Argv[1]) : fs::temp_directory_path();
            const auto Work = fs::absolute(Base) / ("license-runtime-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64()));
            fs::create_directories(Work);
            const auto Private = Work / "issuer.private", Public = Work / "issuer.pub";
            GenerateKeyFiles(Private, Public);
            const auto Policy = MakePolicy(Public, "runtime.test");
            const auto ClockFile = LicenseClockPath(Policy, MachineId(), LicenseClockDirectory());
            struct CleanupClock { fs::path Path; ~CleanupClock() {
                DeleteFileW(Path.c_str()); DeleteFileW((Path.wstring() + L".lock").c_str());
            } } ClockCleanup{ClockFile};
            const auto Token = FormatLicense(IssueLicense(Private, "runtime.test", MachineId(), 30, CurrentFileTime()));
            TestCache(Work, Private, Policy, Token);
            TestDialog(Work, Policy, Token);
            TestPersistentClock(Work, Private, Policy);
            const auto ExpiringPayload = IssueLicense(Private, "runtime.test", MachineId(), 1,
                CurrentFileTime() - KTicksPerDay + 50000000);
            const auto Expiring = FormatLicense(ExpiringPayload);
            InitializeLicenseSession(Policy, Expiring);
            Require(HasLicenseSession(), "signed license session created");
            RevalidateLicenseSession(true);
            Reject([&] { InitializeLicenseSession(Policy, "forged"); });
            const auto BaseTime = CurrentFileTime();
            Require(MonotonicLicenseTime(BaseTime, BaseTime, 30000, 0) == BaseTime + 300000000,
                    "monotonic time prevents expiry delay");
            Reject([&] { MonotonicLicenseTime(BaseTime - KClockSkewTicks - 1, BaseTime, 0, 0); });
            Reject([&] { MonotonicLicenseTime(BaseTime, BaseTime, 0, 1); });
            Reject([&] { MonotonicLicenseTime(BaseTime, KMaximumTimestamp, 1, 0); });
            Reject([&] { MonotonicLicenseTime(0, BaseTime, 0, 0); });
            Reject([&] { MonotonicLicenseTime(KMaximumTimestamp + 1, BaseTime, 0, 0); });
            const auto Forward = MonotonicLicenseTime(BaseTime + KTicksPerDay, BaseTime, 30000, 0);
            Reject([&] { MonotonicLicenseTime(BaseTime + 600000000, Forward, 60000, 30000); });
            Require(LicenseCheckDue(100, 100, 0), "initial session check skipped");
            Require(!LicenseCheckDue(30099, 100, 30100), "early scheduled check");
            Require(LicenseCheckDue(30100, 100, 30100), "due scheduled check skipped");
            Reject([&] { LicenseCheckDue(100, 100, UINT64_MAX); });
            Reject([&] { LicenseCheckDue(99, 100, 30100); });
            Reject([&] { LicenseCheckDue(UINT64_MAX, UINT64_MAX - 1, 0); });
            while (CurrentFileTime() < ExpiringPayload.ExpiresFileTime) Sleep(20);
            RejectWith([&] { RevalidateLicenseSession(true); }, "license expired");
            RejectWith([&] { RevalidateLicenseSession(); }, "invalid license session state");
            RejectWith([&] { InitializeLicenseSession(Policy, Token); }, "license session already initialized");
            const auto Utf8Path = Work.u8string();
            std::clog << "Artifacts: " << std::string(Utf8Path.begin(), Utf8Path.end()) << '\n';
            std::ofstream(Work / "result.txt") << "License runtime: " << Checks << " checks passed\n";
        }
        std::clog << "License runtime: " << Checks << " checks passed\n";
        return 0;
    } catch (const std::exception& Error) { std::cerr << "License runtime FAILED: " << Error.what() << '\n'; return 1; }
}
