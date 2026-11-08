#define main PeVmProductionMain
#include "../../Src/Apps/Gui/QtGui.cpp"
#undef main
#include <QElapsedTimer>
#include <QFontDatabase>
#include <QThread>
#include <iostream>
#include <stdexcept>

namespace {
int Checks{};
void Check(bool Condition, const char* Message) {
    ++Checks;
    if (!Condition) throw std::runtime_error(Message);
}
template<class T> T* Find(QWidget& Window, const char* Name) {
    auto* Value = Window.findChild<T*>(Name);
    if (!Value) throw std::runtime_error(std::string("Missing control: ") + Name);
    return Value;
}
void Wait(QProcess& Process) {
    QElapsedTimer Timer;
    Timer.start();
    do {
        QApplication::processEvents();
        if (Process.state() == QProcess::NotRunning) break;
        QThread::msleep(10);
    } while (Timer.elapsed() < 60000);
    if (Process.state() != QProcess::NotRunning) {
        Process.kill(); Process.waitForFinished();
        throw std::runtime_error("CLI timeout");
    }
    QApplication::processEvents();
}
QByteArray Read(const QString& Path) {
    QFile File(Path);
    Check(File.open(QIODevice::ReadOnly), "Cannot read generated artifact");
    return File.readAll();
}
}

int main(int Argc, char** Argv) {
    QApplication App(Argc, Argv);
    QApplication::setApplicationName("GuiFeaturesRegression");
    QApplication::setOrganizationName("PeVmTests");
    const auto Artifacts = QCoreApplication::applicationDirPath() + "/TestArtifacts/GuiFeatures";
    QDir().mkpath(Artifacts);
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, Artifacts);
    QSettings().setValue("Language", 1);
    const auto Font = QFontDatabase::addApplicationFont("C:/Windows/Fonts/msyh.ttc");
    const auto Families = QFontDatabase::applicationFontFamilies(Font);
    if (!Families.isEmpty()) App.setFont(QFont(Families.front(), 9));
    try {
        QTemporaryDir Work(QDir::tempPath() + "/PeVm GUI features XXXXXX");
        Check(Work.isValid(), "Cannot create test directory");
        MainWindow Window;
        Window.show();
        auto* Runner = Window.findChild<QProcess*>();
        Check(Runner != nullptr, "CLI runner missing");
        auto* Log = Find<QPlainTextEdit>(Window, "CommandLog");
        auto* Result = Find<QLabel>(Window, "LicenseResult");
        const auto Button = [&](const char* Name) { return Find<QPushButton>(Window, Name); };
        const auto Edit = [&](const char* Name) { return Find<QLineEdit>(Window, Name); };
        const auto Box = [&](const char* Name) { return Find<QCheckBox>(Window, Name); };
        QSet<QString> Commands;
        int Starts{};
        QObject::connect(Runner, &QProcess::started, &Window, [&] { ++Starts; Commands.insert(Runner->arguments().front()); });
        const auto Run = [&](const char* Name, const char* Command, bool Success = true) {
            const auto Before = Starts;
            Button(Name)->click();
            Wait(*Runner);
            if (Starts != Before + 1 || Runner->arguments().front() != Command ||
                Runner->exitStatus() != QProcess::NormalExit || ((Runner->exitCode() == 0) != Success)) {
                throw std::runtime_error(std::string("GUI command failed: ") + Name + "\n" + Log->toPlainText().right(2500).toStdString());
            }
            ++Checks;
        };

        Button("LicensePage")->click();
        Check(!Find<QWidget>(Window, "BuildFields")->isVisible(), "License page retained unrelated build inputs");
        Run("GetMachineId", "license-machine-id");
        const auto Machine = Edit("IssueMachine")->text();
        Check(QRegularExpression("^[0-9a-fA-F]{64}$").match(Machine).hasMatch(), "Machine ID was not populated");
        Button("CopyMachineId")->click();
        Check(QApplication::clipboard()->text() == Machine, "Machine copy failed");
        const auto Private = Work.filePath("issuer.private");
        const auto Public = Work.filePath("issuer.pub");
        const auto License = Work.filePath("customer.license");
        Edit("SigningPrivatePath")->setText(Private);
        Edit("SigningPublicPath")->setText(Public);
        Run("GenerateKeyPair", "license-keygen");
        const auto OriginalPrivate = Read(Private);
        const auto OriginalPublic = Read(Public);
        Check(OriginalPrivate.startsWith("PEVM-PRIVATE.") && OriginalPublic.startsWith("PEVM-PUBLIC."), "Invalid key files");
        auto Before = Starts;
        Button("GenerateKeyPair")->click();
        QApplication::processEvents();
        Check(Starts == Before && Read(Private) == OriginalPrivate && Read(Public) == OriginalPublic, "Key generation replaced existing keys");
        Edit("SigningPublicPath")->setText(Work.filePath("exported.pub"));
        Run("ExportPublicKey", "license-export-public");
        Check(Read(Edit("SigningPublicPath")->text()) == OriginalPublic, "Exported public key differs");
        Edit("IssueProduct")->setText("gui.regression");
        Edit("IssuedLicensePath")->setText(License);
        Run("IssueLicense", "license-issue");
        const auto Token = Read(License).trimmed();
        auto* LicenseText = Find<QPlainTextEdit>(Window, "IssuedLicenseText");
        Check(LicenseText->toPlainText().toUtf8() == Token, "Issued file was not displayed");
        Check(Result->text().contains("expires:") && !Result->text().contains("perpetual"), "Expiry metadata missing");
        Button("CopyLicense")->click();
        Check(QApplication::clipboard()->text().toUtf8() == Token, "License copy failed");
        Run("VerifyLicense", "license-verify");
        Check(Result->text().contains("license valid"), "Verification result missing");
        Edit("IssueProduct")->setText("wrong.product");
        Run("VerifyLicense", "license-verify", false);
        Check(!Result->text().contains("license valid"), "Failed verification retained success");
        Edit("IssueProduct")->setText("gui.regression");
        Edit("IssueMachine")->setText(QString(64, '0'));
        Run("VerifyLicense", "license-verify", false);
        Edit("IssueMachine")->clear();
        Run("VerifyLicense", "license-verify");
        Check(!Runner->arguments().join(' ').contains("--machine="), "Blank verification machine not omitted");
        Edit("IssueMachine")->setText(Machine);
        Before = Starts;
        Button("IssueLicense")->click(); QApplication::processEvents();
        Check(Starts == Before && Read(License).trimmed() == Token && LicenseText->toPlainText().isEmpty(), "Issuance overwrite was not rejected");
        Edit("IssuedLicensePath")->clear();
        Find<QSpinBox>(Window, "IssueDays")->setValue(0);
        Run("IssueLicense", "license-issue");
        Check(LicenseText->toPlainText().startsWith("PEVM-LICENSE.") && Result->text().contains("perpetual"), "Perpetual display-only issue failed");
        Check(!Log->toPlainText().contains("PEVM-LICENSE.") && !Log->toPlainText().contains("PEVM-PRIVATE."), "License material leaked to log");
        Edit("IssueMachine")->setText("invalid");
        Before = Starts;
        Button("IssueLicense")->click(); QApplication::processEvents();
        Check(Starts == Before && LicenseText->toPlainText().isEmpty(), "Invalid machine accepted or stale card retained");
        Edit("IssueMachine")->setText(Machine);
        Button("ApplyLicensePolicy")->click();
        Check(Box("RequireLicense")->isChecked() && Edit("ProtectionPublicKey")->text() == Edit("SigningPublicPath")->text() &&
              Edit("ProtectionProduct")->text() == "gui.regression" && Button("ProtectionSettingsPage")->isChecked(), "Apply protection did not transfer policy");

        const auto Fixture = QCoreApplication::applicationDirPath() + "/LifterFixture.exe";
        Edit("InputPath")->setText(Fixture);
        Edit("OutputPath")->setText(Work.filePath("licensed.exe"));
        Edit("BuildPassword")->setText("gui-build-private-password");
        Box("CompressPayload")->setChecked(true);
        Edit("Watermark")->setText("gui-watermark");
        Button("ContainerPage")->click();
        Run("Wrap", "wrap");
        Check(Runner->arguments().contains("--license-product=gui.regression") && Runner->arguments().contains("--compress") &&
              Runner->arguments().contains("--watermark=gui-watermark") && !Runner->arguments().contains(Private), "Wrapper lost protection options");
        Check(QFile::copy(License, Edit("OutputPath")->text() + ".license"), "Cannot attach test license");
        QProcess Execute;
        auto Environment = QProcessEnvironment::systemEnvironment();
        Environment.insert("PEVM_TEST_NO_DIALOG", "1");
        Execute.setProcessEnvironment(Environment);
        Execute.start(Edit("OutputPath")->text(), QStringList{});
        Wait(Execute);
        Check(Execute.exitStatus() == QProcess::NormalExit && Execute.exitCode() == 0, "GUI-built licensed wrapper did not run");
        Edit("InputPath")->setText(Edit("OutputPath")->text());
        Run("Inspect", "inspect");
        Check(Log->toPlainText().contains("license: ECDSA P-256") && Log->toPlainText().contains("watermark: gui-watermark"), "Policy or watermark missing from wrapper");
        Edit("InputPath")->setText(Fixture);
        Edit("OutputPath")->setText(Work.filePath("payload.pvm"));
        Run("Pack", "pack");
        Check(Runner->arguments().size() == 5 && Runner->arguments().last() == "--compress", "Pack received unrelated licensing flags");
        Edit("InputPath")->setText(Edit("OutputPath")->text());
        Run("VmDump", "vm-dump");
        Edit("OutputPath")->setText(Work.filePath("restored.exe"));
        Run("Unpack", "unpack");
        Check(Read(Edit("OutputPath")->text()) == Read(Fixture), "GUI pack/unpack roundtrip differs");

        Box("RequireLicense")->setChecked(false);
        Box("CompressPayload")->setChecked(false);
        Edit("Watermark")->clear();
        Edit("InputPath")->setText(Fixture);
        Button("FunctionPage")->click();
        Run("ScanFunctions", "scan-functions");
        Edit("ScanExportPath")->setText(Work.filePath("scan.json"));
        Button("ExportScan")->click();
        const auto Scan = QJsonDocument::fromJson(Read(Edit("ScanExportPath")->text())).object();
        Check(Scan["format"].toString() == "pevm-scan-functions" && Scan["functions"].toArray().size() > 10, "Scan export failed");
        QString First, Second;
        for (const auto& Item : Scan["functions"].toArray()) {
            if (Item.toObject()["name"].toString() == "LiftTarget") First = Item.toObject()["rva"].toString();
            if (Item.toObject()["name"].toString() == "LoopTarget") Second = Item.toObject()["rva"].toString();
        }
        Check(!First.isEmpty() && !Second.isEmpty(), "Named fixture functions missing");
        Find<QSpinBox>(Window, "ScanMinimumBytes")->setValue(32);
        Run("ScanFunctions", "scan-functions");
        Check(Runner->arguments().contains("--min-bytes=32"), "Scan minimum not forwarded");
        Edit("FunctionRvas")->setText(First);
        Edit("ManifestPath")->setText(Fixture);
        const auto FixtureBytes = Read(Fixture);
        Before = Starts;
        Button("AnalyzeFunction")->click(); QApplication::processEvents();
        Check(Starts == Before && Read(Fixture) == FixtureBytes, "Manifest export replaced input executable");
        Edit("MultiRvas")->setText(First + ", " + Second);
        Button("MultiJson")->click(); QApplication::processEvents();
        Check(Starts == Before && Read(Fixture) == FixtureBytes, "Multi manifest export replaced input executable");
        Edit("FunctionSeed")->setText("0x1234");
        Edit("BridgeRcx")->setText("0x11"); Edit("BridgeRdx")->setText("0x22");
        Edit("BridgeR8")->setText("0x44"); Edit("BridgeR9")->setText("0x88");
        Edit("ManifestPath")->setText(Work.filePath("single.json"));
        Box("FunctionTrace")->setChecked(true);
        Run("AnalyzeFunction", "lift-x64");
        Check(Runner->arguments().contains("--trace") && Log->toPlainText().contains("bridge smoke RAX: 0xff") &&
              !QJsonDocument::fromJson(Read(Edit("ManifestPath")->text())).isNull(), "Function bridge parameters or manifest failed");
        Edit("MultiRvas")->setText(First + ", " + Second);
        Edit("ManifestPath")->setText(Work.filePath("multi.json"));
        Run("MultiJson", "lift-x64-multi");
        Check(!QJsonDocument::fromJson(Read(Edit("ManifestPath")->text())).isNull(), "Multi-function manifest invalid");
        Button("ViewJson")->click();
        Check(Log->toPlainText().contains("---- manifest:"), "Manifest viewer did not read custom path");
        Edit("OutputPath")->setText(Work.filePath("single.exe"));
        Run("VirtualizeManual", "protect-function");
        Edit("FunctionRvas")->setText(First + ", " + Second);
        Edit("OutputPath")->setText(Work.filePath("multi.exe"));
        Run("VirtualizeManual", "protect-functions");
        Check(Runner->arguments().mid(4, 2) == QStringList{First, Second}, "Manual multi-function RVAs changed");
        Edit("OutputPath")->setText(Work.filePath("all.exe"));
        Find<QSpinBox>(Window, "ProtectMinimumBytes")->setValue(12);
        Box("AllowMemory")->setChecked(true);
        Run("ProtectAll", "protect-all");
        Check(Runner->arguments().contains("--min-bytes=12") && Runner->arguments().contains("--allow-mem"), "Protect ALL options missing");

        Button("RawPage")->click();
        Edit("RawRcx")->setText("0x2a");
        Box("RawTrace")->setChecked(true);
        Run("AnalyzeRaw", "lift-raw");
        Check(Log->toPlainText().contains("raw bridge RAX: 0x2a") && Runner->arguments().contains("--trace"), "Raw bridge output wrong");
        Edit("RawEntry")->setText("0x100000000");
        Before = Starts; Button("AnalyzeRaw")->click(); QApplication::processEvents();
        Check(Starts == Before && !Find<QLabel>(Window, "RawError")->text().isEmpty(), "Out-of-range entry was silently truncated");
        Edit("RawEntry")->setText("0");
        Find<QPlainTextEdit>(Window, "RawBytes")->setPlainText("0zz");
        Before = Starts; Button("AnalyzeRaw")->click(); QApplication::processEvents();
        Check(Starts == Before && !Find<QLabel>(Window, "RawError")->text().isEmpty(), "Invalid raw bytes accepted");

        Button("DemoPage")->click();
        Edit("DemoInput")->setText("5"); Edit("DemoSeed")->setText("0x9876");
        Box("DemoTrace")->setChecked(true);
        Run("FactorialDemo", "virtualize-demo");
        Check(Runner->arguments() == QStringList{"virtualize-demo", "5", "0x9876", "--trace"} &&
              Log->toPlainText().contains("factorial(5) = 120"), "Demo used function seed or dropped trace");
        Run("CallMemoryDemo", "call-memory-demo");
        Check(Runner->arguments().contains("0x9876") && Runner->arguments().contains("--trace"), "Call/memory parameters wrong");
        Edit("DemoPassword")->setText("gui-key-private-password");
        Run("KeyVmDemo", "vm-demo");
        Run("Vm2SelfTest", "vm2-self-test");
        Run("FullSelfTest", "self-test");
        Check(!Log->toPlainText().contains("gui-build-private-password") && !Log->toPlainText().contains("gui-key-private-password"), "Password exposed in command log");
        Check(Log->toPlainText().contains("<redacted>"), "Redaction marker missing");
        QProcess Usage;
        Usage.start(QCoreApplication::applicationDirPath() + "/PeVm.exe", QStringList{});
        Wait(Usage);
        QSet<QString> Declared;
        auto Matches = QRegularExpression("pevm ([a-z0-9-]+)").globalMatch(QString::fromLocal8Bit(Usage.readAllStandardOutput()));
        while (Matches.hasNext()) Declared.insert(Matches.next().captured(1));
        Check(!Declared.isEmpty() && Commands == Declared, "GUI regression coverage differs from CLI usage commands");
        Button("ClearLog")->click();
        Check(Log->toPlainText().isEmpty(), "Clear log failed");

        // Capture clean bilingual pages without transient notifications or card data.
        MainWindow Preview;
        Preview.show();
        for (const auto* Id : {"LicensePage", "RawPage", "DemoPage", "ProtectionSettingsPage", "ContainerPage"}) {
            Find<QPushButton>(Preview, Id)->click();
            QApplication::processEvents();
            Check(Preview.grab().save(Artifacts + "/" + Id + "-zh.png"), "Cannot render Chinese page");
            Find<QPushButton>(Preview, "LanguageToggle")->click();
            QApplication::processEvents();
            Check(Preview.grab().save(Artifacts + "/" + Id + "-en.png"), "Cannot render English page");
            Find<QPushButton>(Preview, "LanguageToggle")->click();
        }
        std::cout << "GUI features: " << Checks << " checks passed; all " << Commands.size()
                  << " CLI commands exercised, license lifecycle, wrapper execution, parameter forwarding and bilingual renders passed\n";
        return 0;
    } catch (const std::exception& Error) {
        std::cerr << "GUI features failed: " << Error.what() << '\n';
        return 1;
    }
}
