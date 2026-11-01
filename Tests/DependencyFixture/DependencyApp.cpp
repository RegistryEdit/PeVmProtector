#include <fstream>
#include <string>

extern "C" __declspec(dllimport) int DependencyAnswer();

int main() {
    if (DependencyAnswer() != 42) return 10;
    std::ifstream File("dependency.txt", std::ios::binary);
    std::string Value;
    std::getline(File, Value);
    if (!File && Value.empty()) return 11;
    return Value == "PEVM_DEPENDENCY_OK" ? 0 : 12;
}
