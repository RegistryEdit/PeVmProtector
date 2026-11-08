#include <QApplication>
#include <QHash>
#include <QRegularExpression>
#include <QTimer>
#include <QWidget>
#include <QElapsedTimer>
#include <algorithm>
#include <cstdio>
#include <vector>
#include <thread>

extern "C" __declspec(dllexport, noinline) unsigned long long LoaderArithmetic(
    unsigned long long A, unsigned long long B, unsigned long long C, unsigned long long D) {
    return A ^ B ^ C ^ D;
}

struct TranslationCatalog {
    QHash<QString, QString> Cache;
    QRegularExpression Pattern{QStringLiteral("([a-z]+)=(\\d+)")};
    bool Check() {
        const auto Match = Pattern.globalMatch(QStringLiteral("value=42")).next();
        Cache.insert(Match.captured(1), Match.captured(2));
        return Cache.value(QStringLiteral("value")) == QStringLiteral("42");
    }
};
bool CheckCatalog() {
    static thread_local TranslationCatalog Catalog;
    return Catalog.Check();
}
int main(int Argc, char** Argv) {
    QApplication App(Argc, Argv);
    if (LoaderArithmetic(0x11, 0x22, 0x44, 0x88) != 0xff) return 22;
    if (!CheckCatalog()) return 20;
    bool Passed = false;
    std::thread Worker([&] { Passed = CheckCatalog(); });
    Worker.join();
    if (!Passed) return 21;
    QWidget Window;
    Window.setWindowTitle(QStringLiteral("PEVM Qt TLS regression"));
    if (App.arguments().contains(QStringLiteral("--benchmark"))) {
        std::vector<qint64> Times;
        unsigned long long Checksum = 0;
        QTimer Tick;
        QObject::connect(&Tick, &QTimer::timeout, [&] {
            QElapsedTimer Clock;
            Clock.start();
            for (unsigned I = 0; I < 2000; ++I)
                Checksum += LoaderArithmetic(I, 0x22, 0x44, 0x88);
            Times.push_back(Clock.nsecsElapsed());
            if (Times.size() == 31) {
                Tick.stop();
                std::sort(Times.begin(), Times.end());
                std::printf("PEVM_QT_BENCH median_ns=%lld max_ns=%lld calls=62000 checksum=%llu\n",
                            Times[15], Times.back(), Checksum);
                App.quit();
            }
        });
        Tick.start(0);
        return App.exec();
    }
    QTimer::singleShot(20, &App, &QApplication::quit);
    return App.exec();
}
