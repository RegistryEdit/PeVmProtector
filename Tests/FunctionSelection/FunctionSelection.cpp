#define main PeVmProductionMain
#include "../../Src/Apps/Gui/QtGui.cpp"
#undef main
#include <QElapsedTimer>
#include <QFontDatabase>
#include <QThread>
#include <iostream>
#include <stdexcept>

namespace {
void Check(bool Condition, const char* Message) {
    if (!Condition) throw std::runtime_error(Message);
}
void Wait(QProcess* Process) {
    QElapsedTimer Timer;
    Timer.start();
    while (Process->state() != QProcess::NotRunning && Timer.elapsed() < 60000) {
        QApplication::processEvents();
        QThread::msleep(10);
    }
    if (Process->state() != QProcess::NotRunning) { Process->kill(); Process->waitForFinished(); throw std::runtime_error("CLI timeout"); }
    QApplication::processEvents();
}
}

int main(int Argc, char** Argv) {
    QApplication App(Argc, Argv);
    QApplication::setApplicationName("FunctionSelectionRegression");
    QApplication::setOrganizationName("PeVmTests");
    const auto Work = QCoreApplication::applicationDirPath() + "/TestArtifacts/FunctionSelection";
    QDir().mkpath(Work);
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, Work);
    QSettings().setValue("Language", 1);
    const auto Font = QFontDatabase::addApplicationFont("C:/Windows/Fonts/msyh.ttc");
    const auto Families = QFontDatabase::applicationFontFamilies(Font);
    if (!Families.isEmpty()) App.setFont(QFont(Families.front(), 9));
    try {
        MainWindow Window;
        Window.show();
        auto* Input = Window.findChild<QLineEdit*>("InputPath");
        auto* Output = Window.findChild<QLineEdit*>("OutputPath");
        auto* Password = Window.findChild<QLineEdit*>("BuildPassword");
        auto* Search = Window.findChild<QLineEdit*>("FunctionSearch");
        auto* Pdb = Window.findChild<QLineEdit*>("FunctionPdbPath");
        auto* Scan = Window.findChild<QPushButton*>("ScanFunctions");
        auto* Protect = Window.findChild<QPushButton*>("VirtualizeSelected");
        auto* Table = Window.findChild<QTableWidget*>("FunctionTable");
        auto* Runner = Window.findChild<QProcess*>();
        Check(Input && Output && Password && Search && Pdb && Scan && Protect && Table && Runner, "UI controls missing");
        const auto Fixture = QCoreApplication::applicationDirPath() + "/LifterFixture.exe";
        Input->setText(Fixture);
        Output->setText(Work + "/selected.exe");
        Password->setText("selection-regression-key");
        Window.findChild<QPushButton*>("FunctionPage")->click();
        Scan->click();
        Wait(Runner);
        Check(Runner->exitCode() == 0 && Table->rowCount() > 10, "GUI scan did not populate table");
        Check(!Protect->isEnabled(), "scan must not automatically select all functions");
        QTableWidgetItem *First{}, *Second{};
        bool PrivateName{};
        for (int I = 0; I < Table->rowCount(); ++I) {
            auto* Item = Table->item(I, 0);
            if (Item->text() == "LiftTarget") First = Item;
            if (Item->text() == "LoopTarget") Second = Item;
            if (Item->text() == "PrintFixtureRva" && Table->item(I, 3)->text() == "pdb") PrivateName = true;
        }
        Check(First && Second && PrivateName, "export/PDB names missing");
        First->setCheckState(Qt::Checked);
        Second->setCheckState(Qt::Checked);
        const QStringList Expected{Table->item(First->row(), 1)->text(), Table->item(Second->row(), 1)->text()};
        Search->setText("LiftTarget");
        Check(!Table->isRowHidden(First->row()) && Table->isRowHidden(Second->row()) && Protect->isEnabled(), "filter should retain checked hidden functions");
        Protect->click();
        const auto Arguments = Runner->arguments();
        Check(Arguments[0] == "protect-functions" && Arguments.mid(4, 2) == Expected && Arguments.size() == 7,
              "GUI did not send exactly the two checked RVAs");
        Wait(Runner);
        Check(Runner->exitCode() == 0 && QFileInfo::exists(Output->text()), "selected virtualization failed");
        QProcess Inspect;
        Inspect.start(QCoreApplication::applicationDirPath() + "/PeVm.exe", {"inspect", Output->text()});
        Wait(&Inspect);
        const auto Metadata = Inspect.readAllStandardOutput();
        Check(Inspect.exitCode() == 0 && Metadata.contains(".vmp3 functions: 2"), "output includes an unexpected function count");
        for (const auto& Rva : Expected) Check(Metadata.contains(("RVA: " + Rva).toUtf8()), "output lost a checked RVA");
        QProcess Execute;
        auto Environment = QProcessEnvironment::systemEnvironment();
        Environment.insert("PEVM_TEST_NO_DIALOG", "1");
        Execute.setProcessEnvironment(Environment);
        Execute.start(Output->text(), QStringList{});
        Wait(&Execute);
        Check(Execute.exitStatus() == QProcess::NormalExit && Execute.exitCode() == 0,
              "program with checked functions virtualized failed to run");
        Search->clear();
        QApplication::processEvents();
        Check(Window.grab().save(Work + "/functions.png"), "cannot save function UI preview");
        for (auto* Button : Window.findChildren<QPushButton*>())
            if (Button->text() == "English") { Button->click(); break; }
        QApplication::processEvents();
        Check(Window.grab().save(Work + "/functions-english.png"), "cannot save English UI preview");
        First->setCheckState(Qt::Unchecked);
        Second->setCheckState(Qt::Unchecked);
        Check(!Protect->isEnabled(), "empty checks left protect enabled");
        Pdb->setText(Work + "/missing.pdb");
        Check(Table->rowCount() == 0, "PDB change retained stale choices");
        Scan->click(); Wait(Runner);
        Check(Runner->exitCode() != 0 && Table->rowCount() == 0, "failed scan retained old results");
        Pdb->clear();
        Scan->click();
        Input->setText(QCoreApplication::applicationDirPath() + "/DependencyApp.exe");
        Wait(Runner);
        Check(Table->rowCount() == 0 && !Protect->isEnabled(), "in-flight scan populated a different input");
        std::cout << "Function selection regression: scan, PDB names, filtering, exact selection, output and invalidation passed\n";
        return 0;
    } catch (const std::exception& Error) {
        std::cerr << "Function selection regression failed: " << Error.what() << '\n';
        return 1;
    }
}
