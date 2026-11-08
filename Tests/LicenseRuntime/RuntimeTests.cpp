#include "../../Src/Apps/Stub/LicenseRuntime.h"
#include "../../Src/Apps/Stub/LicenseDialog.h"
#include "PeVmCrypto.h"
#include "FileIo.h"
#include <windows.h>
#include <dpapi.h>
#include <algorithm>
#include <atomic>
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
    if (!SendMessageTimeoutW(Window, Message, W, L, SMTO_ABORTIFHUNG | SMTO_BLOCK, 5000, &Result))
        throw std::runtime_error("dialog message timed out");
    return static_cast<LRESULT>(Result);
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
    try {
        Require((GetWindowLongPtrW(Input, GWL_STYLE) & ES_PASSWORD) != 0, "license input is not masked");
        if (Cancel) { Send(Window, WM_CLOSE); return; }
        for (const auto& Invalid : {std::wstring(), std::wstring(L"bad"), std::wstring(L"非ASCII"), std::wstring(4097, L'A')}) {
            Send(Input, WM_SETTEXT, 0, reinterpret_cast<LPARAM>(Invalid.c_str()));
            Send(Window, WM_COMMAND, IDOK);
            Require(IsWindow(Window) != FALSE, "invalid submission closed dialog");
            wchar_t Reason[512]{};
            Send(GetDlgItem(Window, KLicenseReason), WM_GETTEXT, 512, reinterpret_cast<LPARAM>(Reason));
            Require(Reason[0] != 0, "invalid submission missing reason");
        }
        Send(GetDlgItem(Window, KShowLicense), BM_CLICK);
        Require(Send(Input, EM_GETPASSWORDCHAR) == 0, "show license failed");
        Send(GetDlgItem(Window, KShowLicense), BM_CLICK);
        Require(Send(Input, EM_GETPASSWORDCHAR) != 0, "hide license failed");
        Send(Input, WM_SETTEXT, 0, reinterpret_cast<LPARAM>(L""));
        Send(Window, WM_COMMAND, IDOK);
        if (!Screenshot.empty()) Capture(Window, Screenshot);
        const auto Text = Wide(" \t" + Token + " \r\n");
        Send(Input, WM_SETTEXT, 0, reinterpret_cast<LPARAM>(Text.c_str()));
        Send(Window, WM_COMMAND, IDOK);
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
            const auto Token = FormatLicense(IssueLicense(Private, "runtime.test", MachineId(), 30, CurrentFileTime()));
            TestCache(Work, Private, Policy, Token);
            TestDialog(Work, Policy, Token);
            std::wcout << L"Artifacts: " << Work.wstring() << L"\n";
        }
        std::cout << "License runtime: " << Checks << " checks passed\n";
        return 0;
    } catch (const std::exception& Error) { std::cerr << "License runtime FAILED: " << Error.what() << '\n'; return 1; }
}
