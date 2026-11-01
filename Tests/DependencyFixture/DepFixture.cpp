#include <windows.h>

extern "C" __declspec(dllexport) int DependencyAnswer() {
    return 42;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) {
    return TRUE;
}
