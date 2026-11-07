// PeVmProtector Qt6 front-end built on QFluentWidgets. The GUI drives
// PeVm.exe (same directory) in the background and streams its output into
// the log pane; navigation uses a Fluent-style rail with a stacked view.
//
// No moc is required on our side: every signal connection uses a lambda
// receiver and the window subclass only overrides virtual event handlers.
// Localization is a hand-rolled retranslate table (English / Chinese) so no
// Qt Linguist toolchain is needed either.

#include <QApplication>
#include "PeVmLicenseFormat.h"
#include <QButtonGroup>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QMimeData>
#include <QPlainTextEdit>
#include <QProcess>
#include <QPushButton>
#include <QSettings>
#include <QScrollArea>
#include <QStackedWidget>
#include <QStatusBar>
#include <QTabWidget>
#include <QTextCursor>
#include <QVBoxLayout>
#include <QWidget>

#include "CheckBox.h"
#include "FluentIcon.h"
#include "FluentGlobal.h"
#include "InfoBar.h"
#include "LineEdit.h"
#include "Navigation/NavigationBar.h"
#include "Progress/IndeterminateProgressRing.h"
#include "PushButton.h"
#include "ScrollBar.h"
#include "Theme.h"

#include <chrono>
#include <filesystem>

namespace Fs = std::filesystem;

namespace {

enum class UiLang { English, Chinese };

// Bilingual string pair; T() picks the active language.
struct Bi {
    const char* En;
    const char* Zh;
};

class MainWindow final : public QMainWindow {
public:
    MainWindow() {
        setAcceptDrops(true);
        resize(960, 680);
        Theme::setThemeMode(Fluent::ThemeMode::DARK);
        QSettings Settings;
        const auto SystemLang = QLocale::system().language() == QLocale::Chinese
                                    ? UiLang::Chinese
                                    : UiLang::English;
        Lang = static_cast<UiLang>(Settings.value("Language",
            static_cast<int>(SystemLang)).toInt());
        BuildUi();
        RetranslateUi();
        const QFileInfo PevmInfo(PevmPath());
        if (!PevmInfo.exists()) {
            AppendLog(T({"PeVm.exe not found beside the GUI - protection commands will fail.\n",
                          "GUI \u540c\u76ee\u5f55\u672a\u627e\u5230 PeVm.exe\uff0c\u4fdd\u62a4\u547d\u4ee4\u5c06\u65e0\u6cd5\u6267\u884c\u3002\n"}));
        }
    }

protected:
    void dragEnterEvent(QDragEnterEvent* Event) override {
        if (Event->mimeData()->hasUrls()) Event->acceptProposedAction();
    }

    void dropEvent(QDropEvent* Event) override {
        const auto Urls = Event->mimeData()->urls();
        if (Urls.isEmpty()) return;
        const auto Path = Urls.first().toLocalFile();
        InputEdit->setText(Path);
        SuggestOutput(Path);
        Event->acceptProposedAction();
    }

private:
    UiLang Lang = UiLang::English;

    LineEdit* InputEdit{};
    LineEdit* OutputEdit{};
    PasswordLineEdit* PasswordEdit{};
    CheckBox* ShowPassword{};
    CheckBox* TraceCheck{};
    CheckBox* AntiDisasmCheck{};
    CheckBox* MutateCheck{};
    CheckBox* CompressCheck{};
    CheckBox* LicenseCheck{};
    LineEdit* WatermarkEdit{};
    LineEdit* LicensePublicKeyEdit{};
    LineEdit* LicenseProductEdit{};
    PushButton* BrowseLicenseKeyBtn{};

    LineEdit* FunctionRvaEdit{};
    LineEdit* LiftSeedEdit{};
    LineEdit* BridgeRcx{};
    LineEdit* BridgeRdx{};
    LineEdit* BridgeR8{};
    LineEdit* BridgeR9{};
    LineEdit* MultiRvaEdit{};
    LineEdit* DemoInput{};
    LineEdit* DemoSeed{};

    QLabel* InputLabel{};
    QLabel* OutputLabel{};
    QLabel* PasswordLabel{};
    QLabel* LanguageLabel{};
    QLabel* WatermarkLabel{};
    QLabel* LicensePublicKeyLabel{};
    QLabel* LicenseProductLabel{};
    QLabel* LogLabel{};
    QLabel* RvaLabel{};
    QLabel* SeedLabel{};
    QLabel* RcxLabel{};
    QLabel* RdxLabel{};
    QLabel* R8Label{};
    QLabel* R9Label{};
    QLabel* MultiRvaLabel{};
    QLabel* VmInputLabel{};
    QLabel* DemoSeedLabel{};
    QLabel* ContainerDesc{};
    QLabel* FunctionDesc{};
    QLabel* DemoDesc{};

    QPushButton* BrowseInputBtn{};
    QPushButton* BrowseOutputBtn{};
    QPushButton* WrapBtn{};
    QPushButton* PackBtn{};
    QPushButton* UnpackBtn{};
    QPushButton* InspectBtn{};
    QPushButton* DumpBtn{};
    QPushButton* AnalyzeBtn{};
    QPushButton* VirtualizeBtn{};
    QPushButton* MultiJsonBtn{};
    QPushButton* ViewJsonBtn{};
    QPushButton* ScanBtn{};
    QPushButton* ProtectAllBtn{};
    QPushButton* FactorialBtn{};
    QPushButton* CallMemoryBtn{};
    QPushButton* SelfTestBtn{};
    QPushButton* LangToggleBtn{};
    QPushButton* NavContainerBtn{};
    QPushButton* NavFunctionsBtn{};
    QPushButton* NavDemoBtn{};

    QFormLayout* FunctionForm{};
    QFormLayout* DemoForm{};
    QPlainTextEdit* Log{};
    IndeterminateProgressRing* Ring{};
    QProcess* Runner{};
    std::chrono::steady_clock::time_point Started{};
    bool Running{};

    QString T(const Bi& Text) const {
        return Lang == UiLang::Chinese ? QString::fromUtf8(Text.Zh)
                                       : QString::fromUtf8(Text.En);
    }

    static QString PevmPath() {
        return QCoreApplication::applicationDirPath() + "/PeVm.exe";
    }

    // QProcess escapes every argument automatically; manual quoting would
    // reach PeVm.exe as literal quote characters and break paths.
    static QString Quote(const QString& Text) {
        return Text;
    }

    void NotifyError(const Bi& Title, const Bi& Content) {
        InfoBar::error(T(Title), T(Content), Qt::Horizontal, true, 4000,
                       InfoBar::Position::TOP_RIGHT, this);
    }

    void NotifyInfo(const Bi& Title, const Bi& Content) {
        InfoBar::info(T(Title), T(Content), Qt::Horizontal, true, 3000,
                      InfoBar::Position::TOP_RIGHT, this);
    }

    void NotifyInfo(const Bi& Title, const QString& Content) {
        InfoBar::info(T(Title), Content, Qt::Horizontal, true, 3000,
                      InfoBar::Position::TOP_RIGHT, this);
    }

    void BuildUi() {
        InputEdit = new LineEdit;
        OutputEdit = new LineEdit;
        PasswordEdit = new PasswordLineEdit;
        ShowPassword = new CheckBox;
        TraceCheck = new CheckBox;
        AntiDisasmCheck = new CheckBox;
        MutateCheck = new CheckBox;
        CompressCheck = new CheckBox;
        LicenseCheck = new CheckBox;
        WatermarkEdit = new LineEdit;
        LicensePublicKeyEdit = new LineEdit;
        LicenseProductEdit = new LineEdit;
        BrowseLicenseKeyBtn = new PushButton(QString(), Fluent::IconType::FOLDER);
        connect(BrowseLicenseKeyBtn, &QPushButton::clicked, this, [this] {
            const auto Path = QFileDialog::getOpenFileName(this,
                T({"Select license public key", "选择卡密公钥文件"}), QString(), "Public keys (*.pub);;All files (*)");
            if (!Path.isEmpty()) LicensePublicKeyEdit->setText(Path);
        });
        LicensePublicKeyEdit->setEnabled(false);
        LicenseProductEdit->setEnabled(false);
        BrowseLicenseKeyBtn->setEnabled(false);
        connect(LicenseCheck, &QCheckBox::toggled, this, [this](bool Enabled) {
            LicensePublicKeyEdit->setEnabled(Enabled);
            LicenseProductEdit->setEnabled(Enabled);
            BrowseLicenseKeyBtn->setEnabled(Enabled);
        });

        BrowseInputBtn = new PushButton(QString(), Fluent::IconType::FOLDER);
        BrowseOutputBtn = new PushButton(QString(), Fluent::IconType::FOLDER);
        connect(BrowseInputBtn, &QPushButton::clicked, this, [this] {
            const auto Path = QFileDialog::getOpenFileName(
                this, T({"Select input", "\u9009\u62e9\u8f93\u5165\u6587\u4ef6"}), QString(),
                "Executables (*.exe *.sys *.pvm);;All files (*)");
            if (Path.isEmpty()) return;
            InputEdit->setText(Path);
            SuggestOutput(Path);
        });
        connect(BrowseOutputBtn, &QPushButton::clicked, this, [this] {
            const auto Path = QFileDialog::getSaveFileName(
                this, T({"Select output", "\u9009\u62e9\u8f93\u51fa\u6587\u4ef6"}), OutputEdit->text());
            if (!Path.isEmpty()) OutputEdit->setText(Path);
        });
        connect(ShowPassword, &QCheckBox::toggled, this, [this](bool Checked) {
            PasswordEdit->setEchoMode(Checked ? QLineEdit::Normal : QLineEdit::Password);
        });

        const auto Shared = new QGridLayout;
        int Row = 0;
        InputLabel = new QLabel;
        Shared->addWidget(InputLabel, Row, 0);
        Shared->addWidget(InputEdit, Row, 1);
        Shared->addWidget(BrowseInputBtn, Row, 2);
        OutputLabel = new QLabel;
        Shared->addWidget(OutputLabel, ++Row, 0);
        Shared->addWidget(OutputEdit, Row, 1);
        Shared->addWidget(BrowseOutputBtn, Row, 2);
        PasswordLabel = new QLabel;
        Shared->addWidget(PasswordLabel, ++Row, 0);
        Shared->addWidget(PasswordEdit, Row, 1);
        Shared->addWidget(ShowPassword, Row, 2);
        Shared->addWidget(LicenseCheck, ++Row, 0, 1, 3);
        LicensePublicKeyLabel = new QLabel;
        Shared->addWidget(LicensePublicKeyLabel, ++Row, 0);
        Shared->addWidget(LicensePublicKeyEdit, Row, 1);
        Shared->addWidget(BrowseLicenseKeyBtn, Row, 2);
        LicenseProductLabel = new QLabel;
        Shared->addWidget(LicenseProductLabel, ++Row, 0);
        Shared->addWidget(LicenseProductEdit, Row, 1, 1, 2);
        LanguageLabel = new QLabel;
        Shared->addWidget(LanguageLabel, ++Row, 0);
        LangToggleBtn = new PushButton;
        connect(LangToggleBtn, &QPushButton::clicked, this, [this] {
            Lang = Lang == UiLang::English ? UiLang::Chinese : UiLang::English;
            QSettings().setValue("Language", static_cast<int>(Lang));
            RetranslateUi();
        });
        Shared->addWidget(LangToggleBtn, Row, 1, 1, 2);
        Shared->setColumnStretch(1, 1);

        const auto Pages = new QStackedWidget;
        Pages->addWidget(BuildContainerPage());
        Pages->addWidget(BuildFunctionPage());
        Pages->addWidget(BuildDemoPage());

        // QFluent's NavigationBar renders in a compact icon strip without a
        // public expand API, so the nav rail is plain checkable buttons with
        // a selected highlight - visually consistent and fully controllable.
        const auto Nav = new QWidget;
        Nav->setFixedWidth(200);
        Nav->setStyleSheet(
            "QPushButton { text-align: left; padding: 9px 14px; border: none; border-radius: 6px;"
            "  color: #d7dae0; background-color: transparent; }"
            "QPushButton:hover { background-color: #2a2d35; }"
            "QPushButton:checked { background-color: #406eb4; color: white; }");
        const auto NavLayout = new QVBoxLayout(Nav);
        NavLayout->setContentsMargins(8, 8, 8, 8);
        NavLayout->setSpacing(4);
        const auto NavGroup = new QButtonGroup(this);
        NavGroup->setExclusive(true);
        const auto AddNavButton = [&](int Page) {
            const auto Button = new QPushButton;
            Button->setCheckable(true);
            NavGroup->addButton(Button);
            NavLayout->addWidget(Button);
            connect(Button, &QPushButton::clicked, this, [this, Pages, Page] {
                Pages->setCurrentIndex(Page);
            });
            return Button;
        };
        NavContainerBtn = AddNavButton(0);
        NavFunctionsBtn = AddNavButton(1);
        NavDemoBtn = AddNavButton(2);
        NavContainerBtn->setChecked(true);
        NavLayout->addStretch(1);

        Log = new QPlainTextEdit;
        Log->setReadOnly(true);
        Log->setMaximumBlockCount(5000);
        Log->setStyleSheet(
            "QPlainTextEdit { font-family: Consolas, monospace; background-color: #181a1f;"
            " color: #d7dae0; border: 1px solid #3a3f4b; border-radius: 4px; }");
        // Fluent scrollbars (Qt ships default ones otherwise).
        Log->setVerticalScrollBar(new ScrollBar(Log));
        Log->setHorizontalScrollBar(new ScrollBar(Log));

        Ring = new IndeterminateProgressRing(this, false);
        Ring->setFixedSize(28, 28);

        const auto Body = new QWidget;
        const auto BodyLayout = new QVBoxLayout(Body);
        BodyLayout->addLayout(Shared);
        const auto PageScroll = new QScrollArea;
        PageScroll->setWidgetResizable(true);
        PageScroll->setFrameShape(QFrame::NoFrame);
        PageScroll->setMinimumHeight(180);
        PageScroll->setVerticalScrollBar(new ScrollBar(PageScroll));
        PageScroll->setHorizontalScrollBar(new ScrollBar(PageScroll));
        PageScroll->setWidget(Pages);
        BodyLayout->addWidget(PageScroll, 1);

        LogLabel = new QLabel;
        const auto LogRow = new QHBoxLayout;
        LogRow->addWidget(LogLabel);
        LogRow->addStretch(1);
        LogRow->addWidget(Ring);
        const auto Right = new QWidget;
        const auto RightLayout = new QVBoxLayout(Right);
        RightLayout->addWidget(Body, 1);
        RightLayout->addLayout(LogRow);
        RightLayout->addWidget(Log, 1);

        const auto Central = new QWidget;
        Central->setAutoFillBackground(true);
        auto CentralPalette = Central->palette();
        CentralPalette.setColor(QPalette::Window, QColor(30, 32, 38));
        CentralPalette.setColor(QPalette::WindowText, QColor(215, 218, 224));
        CentralPalette.setColor(QPalette::ButtonText, QColor(215, 218, 224));
        CentralPalette.setColor(QPalette::Base, QColor(24, 26, 31));
        CentralPalette.setColor(QPalette::Text, QColor(215, 218, 224));
        Central->setPalette(CentralPalette);
        const auto Layout = new QHBoxLayout(Central);
        Layout->setContentsMargins(0, 0, 0, 0);
        Layout->addWidget(Nav);
        Layout->addWidget(Right, 1);
        setCentralWidget(Central);

        Runner = new QProcess(this);
        connect(Runner, &QProcess::readyReadStandardOutput, this, [this] {
            AppendLog(QString::fromLocal8Bit(Runner->readAllStandardOutput()));
        });
        connect(Runner, &QProcess::readyReadStandardError, this, [this] {
            AppendLog(QString::fromLocal8Bit(Runner->readAllStandardError()));
        });
        connect(Runner, &QProcess::errorOccurred, this, [this](QProcess::ProcessError) {
            if (Runner->state() != QProcess::NotRunning) return;
            FinishRun(T({"failed to launch PeVm.exe", "\u65e0\u6cd5\u542f\u52a8 PeVm.exe"}));
        });
        connect(Runner, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                this, [this](int ExitCode, QProcess::ExitStatus) {
            FinishRun(ExitCode == 0
                          ? T({"done", "\u5b8c\u6210"})
                          : T({"exit code", "\u9000\u51fa\u7801"}) + QString(" %1").arg(ExitCode));
        });
    }

    // Applies every visible text for the active language. Called once after
    // the widgets are built and on every language toggle.
    void RetranslateUi() {
        InputLabel->setText(T({"Input", "\u8f93\u5165\u6587\u4ef6"}));
        OutputLabel->setText(T({"Output", "\u8f93\u51fa\u6587\u4ef6"}));
        PasswordLabel->setText(T({"Password", "\u53e3\u4ee4"}));
        LanguageLabel->setText(T({"Language", "\u754c\u9762\u8bed\u8a00"}));
        LangToggleBtn->setText(Lang == UiLang::English
                                   ? QString::fromUtf8("\u4e2d\u6587")
                                   : "English");
        ShowPassword->setText(T({"Show password", "\u663e\u793a\u53e3\u4ee4"}));
        BrowseInputBtn->setText(T({"Browse...", "\u6d4f\u89c8..."}));
        BrowseOutputBtn->setText(T({"Browse...", "\u6d4f\u89c8..."}));

        NavContainerBtn->setText(T({"Container & Wrapper", "\u5bb9\u5668\u4e0e\u5c01\u88c5"}));
        NavFunctionsBtn->setText(T({"Function Virtualization", "\u51fd\u6570\u865a\u62df\u5316"}));
        NavDemoBtn->setText(T({"VM Demo", "VM \u6f14\u793a"}));

        WrapBtn->setText(T({"Wrap -> runnable EXE", "Wrap -> \u53ef\u8fd0\u884c EXE"}));
        PackBtn->setText(T({"Pack -> .pvm container", "Pack -> .pvm \u5bb9\u5668"}));
        UnpackBtn->setText(T({"Unpack", "\u89e3\u5305"}));
        InspectBtn->setText(T({"Inspect", "\u68c0\u89c6"}));
        DumpBtn->setText(T({"VM Dump", "VM \u53cd\u6c47\u7f16"}));
        ContainerDesc->setText(T({
            "Wrapper runs by double-click without a password; a .pvm container is a pure\n"
            "encrypted package restored by `PeVm unpack`. VM Dump disassembles the key-VM\n"
            "bytecode inside a container. Container v5 also accepts native .sys images.",
            "Wrapper \u53cc\u51fb\u5373\u8fd0\u884c\u3001\u65e0\u9700\u53e3\u4ee4\uff1b.pvm \u4e3a\u7eaf\u52a0\u5bc6\u5bb9\u5668\uff0c\u7528 `PeVm unpack` \u8fd8\u539f\u3002\n"
            "VM Dump \u53cd\u6c47\u7f16\u5bb9\u5668\u5185\u7684 key-VM \u5b57\u7801\u3002\u5bb9\u5668 v5 \u540c\u6837\u63a5\u53d7 native \u9a71\u52a8 .sys \u955c\u50cf\u3002"}));

        RvaLabel->setText(T({"Function RVA(s)", "\u51fd\u6570 RVA"}));
        FunctionRvaEdit->setToolTip(
            T({"One RVA, or several separated by commas for protect-functions",
               "\u4e00\u4e2a RVA\uff0c\u6216\u591a\u4e2a\uff08\u9017\u53f7\u5206\u9694\uff0c\u8d70 protect-functions\uff09"}));
        SeedLabel->setText(T({"Seed", "\u79cd\u5b50"}));
        RcxLabel->setText("RCX");
        RdxLabel->setText("RDX");
        R8Label->setText("R8");
        R9Label->setText("R9");
        MultiRvaLabel->setText(T({"Multi RVA list", "\u591a\u51fd\u6570 RVA \u5217\u8868"}));
        WatermarkLabel->setText(T({"Watermark", "\u6c34\u5370"}));
        WatermarkEdit->setToolTip(T({
            "Customer watermark embedded in the wrapper metadata",
            "\u5d4c\u5165 wrapper \u5143\u6570\u636e\u7684\u5ba2\u6237\u6c34\u5370"}));
        AntiDisasmCheck->setText(T({"Anti-Disasm decoys", "Anti-Disasm \u9677\u9631\u5b57\u8282"}));
        MutateCheck->setText(T({"Mutation pass", "\u53d8\u5f02\u5904\u7406"}));
        CompressCheck->setText(T({"Compress payload", "\u538b\u7f29 payload"}));
        LicenseCheck->setText(T({"Require signed license (wrap / virtualize)", "启用签名卡密（封装 / 虚拟化）"}));
        LicenseCheck->setToolTip(T({
            "Require a signed license. Existing licenses must be reissued. Does not apply to pack/unpack.",
            "仅接受 签名卡密，旧卡需重新签发。此设置不影响打包 / 解包。"}));
        LicensePublicKeyLabel->setText(T({"License public key", "卡密公钥"}));
        LicensePublicKeyEdit->setPlaceholderText(T({"Select a .pub file", "选择 .pub 公钥文件"}));
        LicensePublicKeyEdit->setToolTip(T({"Generate keys with PeVm license-keygen; select the public file.",
                                           "使用 PeVm license-keygen 生成密钥，然后选择公钥文件。"}));
        BrowseLicenseKeyBtn->setText(T({"Browse...", "浏览..."}));
        LicenseProductLabel->setText(T({"Product ID", "产品 ID"}));
        LicenseProductEdit->setPlaceholderText("my-product");
        LicenseProductEdit->setToolTip(T({"Case-sensitive; must match the product used when issuing licenses.",
                                         "区分大小写，必须与签发卡密时的产品 ID 一致。"}));
        AnalyzeBtn->setText(T({"Analyze / bridge test", "\u5206\u6790 / \u6865\u63a5\u6d4b\u8bd5"}));
        VirtualizeBtn->setText(T({"Virtualize function(s)", "\u865a\u62df\u5316\u51fd\u6570"}));
        MultiJsonBtn->setText(T({"Multi-function JSON", "\u591a\u51fd\u6570 JSON"}));
        ViewJsonBtn->setText(T({"View manifest JSON", "\u67e5\u770b\u6e05\u5355 JSON"}));
        ScanBtn->setText(T({"Scan functions", "\u626b\u63cf\u51fd\u6570"}));
        ProtectAllBtn->setText(T({"Protect ALL (VMP-style)", "\u5168\u91cf\u865a\u62df\u5316\uff08VMP \u98ce\u683c\uff09"}));
        FunctionDesc->setText(T({
            "Memory operands map to flat VM-memory offsets (not native pointers).\n"
            "Analyze and multi-function produce JSON manifests; virtualize builds a\n"
            "protected EXE with a .vmp3 section and one trampoline per function.\n"
            "Unsupported instructions fail closed with a clear error.",
            "\u5185\u5b58\u64cd\u4f5c\u6570\u6309 VM \u5e73\u5766\u5185\u5b58\u504f\u79fb\u7ffb\u8bd1\uff08\u975e native \u6307\u9488\uff09\u3002\n"
            "\u5206\u6790\u4e0e\u591a\u51fd\u6570\u751f\u6210 JSON \u6e05\u5355\uff1b\u865a\u62df\u5316\u751f\u6210\u5e26 .vmp3 \u8282\u7684\u53d7\u4fdd\u62a4 EXE\uff0c\n"
            "\u6bcf\u4e2a\u51fd\u6570\u4e00\u4e2a trampoline\u3002\u4e0d\u652f\u6301\u7684\u6307\u4ee4\u4f1a\u660e\u786e\u62a5\u9519\u800c\u975e\u9519\u8bef\u7ffb\u8bd1\u3002"}));

        VmInputLabel->setText(T({"VM input", "VM \u8f93\u5165"}));
        DemoSeedLabel->setText(T({"Seed", "\u79cd\u5b50"}));
        TraceCheck->setText("Trace");
        FactorialBtn->setText("Factorial VM");
        CallMemoryBtn->setText("Call/Memory VM");
        SelfTestBtn->setText(T({"VM Self-Test", "VM \u81ea\u6d4b"}));
        DemoDesc->setText(T({
            "Both demos execute entirely inside VM2: randomized opcode map, encrypted\n"
            "bytecode, per-instruction authentication. Trace prints every virtual\n"
            "instruction; Self-Test runs the differential suite against native results.",
            "\u4e24\u4e2a\u6f14\u793a\u5b8c\u5168\u5728 VM2 \u5185\u6267\u884c\uff1a\u968f\u673a opcode \u6620\u5c04\u3001\u52a0\u5bc6 bytecode\u3001\n"
            "\u9010\u6307\u4ee4\u8ba4\u8bc1\u3002Trace \u9010\u6761\u6253\u5370\u865a\u62df\u6307\u4ee4\uff1b\u81ea\u6d4b\u4e0e native \u7ed3\u679c\u505a\u5dee\u5206\u3002"}));

        LogLabel->setText(T({"Log", "\u8fd0\u884c\u65e5\u5fd7"}));
        statusBar()->showMessage(T({"Ready", "\u5c31\u7eea"}));
    }

    // Shared tail options appended to every protection command.
    QStringList ProtectionOptions(bool Virtualize = true) const {
        QStringList Options;
        if (Virtualize && AntiDisasmCheck->isChecked()) Options << "--anti-disasm";
        if (Virtualize && MutateCheck->isChecked()) Options << "--mutate";
        if (CompressCheck->isChecked()) Options << "--compress";
        if (LicenseCheck->isChecked()) {
            Options << "--license" << "--license-public-key=" + LicensePublicKeyEdit->text()
                    << "--license-product=" + LicenseProductEdit->text();
        }
        if (!WatermarkEdit->text().isEmpty()) Options << "--watermark=" + WatermarkEdit->text();
        return Options;
    }

    QWidget* BuildContainerPage() {
        const auto Page = new QWidget;
        const auto Layout = new QVBoxLayout(Page);
        const auto Buttons = new QHBoxLayout;
        WrapBtn = new PrimaryPushButton(QString(), Fluent::IconType::SAVE);
        PackBtn = new PrimaryPushButton(QString(), Fluent::IconType::SAVE);
        UnpackBtn = new PushButton(QString(), Fluent::IconType::SYNC);
        InspectBtn = new PushButton(QString(), Fluent::IconType::INFO);
        DumpBtn = new PushButton(QString(), Fluent::IconType::CODE);
        Buttons->addWidget(WrapBtn);
        Buttons->addWidget(PackBtn);
        Buttons->addWidget(UnpackBtn);
        Buttons->addWidget(InspectBtn);
        Buttons->addWidget(DumpBtn);
        Buttons->addStretch(1);
        Layout->addLayout(Buttons);
        ContainerDesc = new QLabel;
        Layout->addWidget(ContainerDesc);
        Layout->addStretch(1);
        connect(WrapBtn, &QPushButton::clicked, this, [this] { RunProtection("wrap"); });
        connect(PackBtn, &QPushButton::clicked, this, [this] { RunProtection("pack"); });
        connect(UnpackBtn, &QPushButton::clicked, this, [this] { RunProtection("unpack"); });
        connect(InspectBtn, &QPushButton::clicked, this, [this] {
            if (!RequireInput()) return;
            Start({ "inspect", Quote(InputEdit->text()) }, "inspect");
        });
        connect(DumpBtn, &QPushButton::clicked, this, [this] {
            if (!RequireInput()) return;
            Start({ "vm-dump", Quote(InputEdit->text()) }, "vm-dump");
        });
        return Page;
    }

    QWidget* BuildFunctionPage() {
        const auto Page = new QWidget;
        const auto Layout = new QVBoxLayout(Page);
        FunctionForm = new QFormLayout;
        FunctionRvaEdit = new LineEdit;
        FunctionRvaEdit->setText("0x1000");
        LiftSeedEdit = new LineEdit;
        LiftSeedEdit->setText("12345");
        BridgeRcx = new LineEdit;
        BridgeRcx->setText("0");
        BridgeRdx = new LineEdit;
        BridgeRdx->setText("0");
        BridgeR8 = new LineEdit;
        BridgeR8->setText("0");
        BridgeR9 = new LineEdit;
        BridgeR9->setText("0");
        MultiRvaEdit = new LineEdit;
        MultiRvaEdit->setText("0x1000, 0x1010");
        RvaLabel = new QLabel;
        FunctionForm->addRow(RvaLabel, FunctionRvaEdit);
        SeedLabel = new QLabel;
        FunctionForm->addRow(SeedLabel, LiftSeedEdit);
        RcxLabel = new QLabel;
        FunctionForm->addRow(RcxLabel, BridgeRcx);
        RdxLabel = new QLabel;
        FunctionForm->addRow(RdxLabel, BridgeRdx);
        R8Label = new QLabel;
        FunctionForm->addRow(R8Label, BridgeR8);
        R9Label = new QLabel;
        FunctionForm->addRow(R9Label, BridgeR9);
        MultiRvaLabel = new QLabel;
        FunctionForm->addRow(MultiRvaLabel, MultiRvaEdit);
        Layout->addLayout(FunctionForm);
        const auto OptionsRow = new QHBoxLayout;
        OptionsRow->addWidget(AntiDisasmCheck);
        OptionsRow->addWidget(MutateCheck);
        OptionsRow->addWidget(CompressCheck);
        WatermarkLabel = new QLabel;
        OptionsRow->addWidget(WatermarkLabel);
        OptionsRow->addWidget(WatermarkEdit, 1);
        Layout->addLayout(OptionsRow);

        const auto Buttons = new QGridLayout;
        AnalyzeBtn = new PushButton(QString(), Fluent::IconType::CODE);
        VirtualizeBtn = new PrimaryPushButton(QString(), Fluent::IconType::PLAY);
        MultiJsonBtn = new PushButton(QString(), Fluent::IconType::INFO);
        ViewJsonBtn = new PushButton(QString(), Fluent::IconType::INFO);
        ScanBtn = new PushButton(QString(), Fluent::IconType::INFO);
        ProtectAllBtn = new PrimaryPushButton(QString(), Fluent::IconType::PLAY);
        Buttons->addWidget(AnalyzeBtn, 0, 0);
        Buttons->addWidget(VirtualizeBtn, 0, 1);
        Buttons->addWidget(MultiJsonBtn, 1, 0);
        Buttons->addWidget(ViewJsonBtn, 1, 1);
        Buttons->addWidget(ScanBtn, 2, 0);
        Buttons->addWidget(ProtectAllBtn, 2, 1);
        Layout->addLayout(Buttons);
        FunctionDesc = new QLabel;
        Layout->addWidget(FunctionDesc);
        Layout->addStretch(1);

        connect(AnalyzeBtn, &QPushButton::clicked, this, [this] {
            if (!RequireInput() || !RequireRva(FunctionRvaEdit->text())) return;
            const auto Manifest = ManifestPath(".vm2.json");
            Start({ "lift-x64", Quote(InputEdit->text()), Quote(FunctionRvaEdit->text()), Quote(Manifest),
                    Quote(SeedOr("12345")),
                    "--rcx=" + BridgeRcx->text(), "--rdx=" + BridgeRdx->text(),
                    "--r8=" + BridgeR8->text(), "--r9=" + BridgeR9->text() },
                  "lift-x64");
        });
        connect(VirtualizeBtn, &QPushButton::clicked, this, [this] {
            if (!RequireProtection()) return;
            const auto Rvas = SplitRvas(FunctionRvaEdit->text());
            if (Rvas.empty()) {
                NotifyError({"Missing input", "\u7f3a\u5c11\u8f93\u5165"},
                            {"Enter at least one function RVA.", "\u8bf7\u586b\u5199\u81f3\u5c11\u4e00\u4e2a\u51fd\u6570 RVA\u3002"});
                return;
            }
            QStringList Arguments{ Rvas.size() == 1 ? "protect-function" : "protect-functions",
                                   Quote(InputEdit->text()), Quote(OutputOr(".protected.exe")),
                                   Quote(PasswordEdit->text()) };
            for (const auto& Rva : Rvas) Arguments << Quote(Rva);
            if (Rvas.size() == 1) Arguments << Quote(SeedOr("12345"));
            else Arguments << "--seed=" + SeedOr("12345");
            Arguments << ProtectionOptions();
            Start(Arguments, Rvas.size() == 1 ? "protect-function" : "protect-functions");
        });
        connect(MultiJsonBtn, &QPushButton::clicked, this, [this] {
            if (!RequireInput()) return;
            const auto Rvas = SplitRvas(MultiRvaEdit->text());
            if (Rvas.empty()) {
                NotifyError({"Missing input", "\u7f3a\u5c11\u8f93\u5165"},
                            {"Enter at least one RVA.", "\u8bf7\u586b\u5199\u81f3\u5c11\u4e00\u4e2a RVA\u3002"});
                return;
            }
            const auto Manifest = ManifestPath(".multi.json");
            QStringList Arguments{ "lift-x64-multi", Quote(InputEdit->text()), Quote(Manifest) };
            for (const auto& Rva : Rvas) Arguments << Rva;
            Start(Arguments, "lift-x64-multi");
        });
        connect(ScanBtn, &QPushButton::clicked, this, [this] {
            if (!RequireInput()) return;
            Start({ "scan-functions", Quote(InputEdit->text()) }, "scan-functions");
        });
        connect(ProtectAllBtn, &QPushButton::clicked, this, [this] {
            if (!RequireProtection()) return;
            QStringList Arguments{ "protect-all", Quote(InputEdit->text()),
                                   Quote(OutputOr(".protected.exe")), Quote(PasswordEdit->text()),
                                   Quote(SeedOr("12345")) };
            Arguments << ProtectionOptions();
            Start(Arguments, "protect-all");
        });
        connect(ViewJsonBtn, &QPushButton::clicked, this, [this] {
            const auto Candidate = ManifestPath(".vm2.json");
            const auto Alt = ManifestPath(".multi.json");
            const auto Path = QFileInfo::exists(Candidate) ? Candidate : Alt;
            if (!QFileInfo::exists(Path)) {
                NotifyInfo({"No manifest", "\u6ca1\u6709\u6e05\u5355"},
                           {"Generate a manifest first.", "\u8bf7\u5148\u751f\u6210\u6e05\u5355\u3002"});
                return;
            }
            QFile File(Path);
            if (File.open(QIODevice::ReadOnly | QIODevice::Text)) {
                AppendLog("---- manifest: " + Path + " ----\n" + QString::fromUtf8(File.readAll()) + "\n");
            }
        });
        return Page;
    }

    QWidget* BuildDemoPage() {
        const auto Page = new QWidget;
        const auto Layout = new QVBoxLayout(Page);
        DemoForm = new QFormLayout;
        DemoInput = new LineEdit;
        DemoInput->setText("10");
        DemoSeed = new LineEdit;
        DemoSeed->setText("12345");
        VmInputLabel = new QLabel;
        DemoForm->addRow(VmInputLabel, DemoInput);
        DemoSeedLabel = new QLabel;
        DemoForm->addRow(DemoSeedLabel, DemoSeed);
        Layout->addLayout(DemoForm);
        Layout->addWidget(TraceCheck);
        const auto Buttons = new QHBoxLayout;
        FactorialBtn = new PrimaryPushButton(QString(), Fluent::IconType::PLAY);
        CallMemoryBtn = new PushButton(QString(), Fluent::IconType::PLAY);
        SelfTestBtn = new PushButton(QString(), Fluent::IconType::INFO);
        Buttons->addWidget(FactorialBtn);
        Buttons->addWidget(CallMemoryBtn);
        Buttons->addWidget(SelfTestBtn);
        Buttons->addStretch(1);
        Layout->addLayout(Buttons);
        DemoDesc = new QLabel;
        Layout->addWidget(DemoDesc);
        Layout->addStretch(1);
        connect(FactorialBtn, &QPushButton::clicked, this, [this] {
            const auto Value = DemoInput->text().isEmpty() ? "10" : DemoInput->text();
            Start({ "virtualize-demo", Value, SeedOr("12345") }, "virtualize-demo");
        });
        connect(CallMemoryBtn, &QPushButton::clicked, this, [this] {
            const auto Value = DemoInput->text().isEmpty() ? "10" : DemoInput->text();
            Start({ "call-memory-demo", Value, SeedOr("12345") }, "call-memory-demo");
        });
        connect(SelfTestBtn, &QPushButton::clicked, this, [this] {
            Start({ "vm2-self-test" }, "vm2-self-test");
        });
        return Page;
    }

    QString SeedOr(const QString& Fallback) const {
        const auto Text = LiftSeedEdit->text().trimmed();
        return Text.isEmpty() ? Fallback : Text;
    }

    QString OutputOr(const QString& Suffix) const {
        const auto Text = OutputEdit->text().trimmed();
        return Text.isEmpty() ? InputEdit->text() + Suffix : Text;
    }

    QString ManifestPath(const QString& Suffix) const {
        const auto Text = OutputEdit->text().trimmed();
        return Text.isEmpty() ? InputEdit->text() + Suffix : Text + Suffix;
    }

    static QStringList SplitRvas(const QString& Text) {
        QStringList Rvas;
        for (const auto& Token : Text.split(',', Qt::SkipEmptyParts)) {
            const auto Trimmed = Token.trimmed();
            if (!Trimmed.isEmpty()) Rvas << Trimmed;
        }
        return Rvas;
    }

    void SuggestOutput(const QString& Input) {
        if (!OutputEdit->text().trimmed().isEmpty()) return;
        Fs::path Path(Input.toStdWString());
        Path.replace_extension(L".protected.exe");
        OutputEdit->setText(QString::fromStdWString(Path.wstring()));
    }

    bool RequireInput() {
        if (InputEdit->text().trimmed().isEmpty()) {
            NotifyError({"Missing input", "\u7f3a\u5c11\u8f93\u5165"},
                        {"Select an input file first.", "\u8bf7\u5148\u9009\u62e9\u8f93\u5165\u6587\u4ef6\u3002"});
            return false;
        }
        return true;
    }

    bool RequireRva(const QString& Text) {
        if (Text.trimmed().isEmpty()) {
            NotifyError({"Missing input", "\u7f3a\u5c11\u8f93\u5165"},
                        {"Enter a function RVA.", "\u8bf7\u586b\u5199\u51fd\u6570 RVA\u3002"});
            return false;
        }
        return true;
    }

    bool RequireProtection(bool UsesLicense = true) {
        if (!RequireInput()) return false;
        if (OutputEdit->text().trimmed().isEmpty() || PasswordEdit->text().isEmpty()) {
            NotifyError({"Missing input", "\u7f3a\u5c11\u8f93\u5165"},
                        {"Function protection needs an output EXE and a build password.",
                         "\u51fd\u6570\u4fdd\u62a4\u9700\u8981\u8f93\u51fa EXE \u548c\u6784\u5efa\u53e3\u4ee4\u3002"});
            return false;
        }
        if (UsesLicense && LicenseCheck->isChecked()) {
            QFile PublicFile(LicensePublicKeyEdit->text());
            const QRegularExpression ProductPattern("^[A-Za-z0-9._-]{1,64}$");
            if (!QFileInfo(LicensePublicKeyEdit->text()).isFile() ||
                !PublicFile.open(QIODevice::ReadOnly) || PublicFile.size() > 4096 ||
                !PublicFile.readAll().trimmed().startsWith(pevm::license::KPublicKeyPrefix) ||
                !ProductPattern.match(LicenseProductEdit->text()).hasMatch()) {
                NotifyError({"Invalid license settings", "卡密设置无效"},
                            {"Select a license public key file and enter a product ID (1-64 ASCII letters/digits/._-).",
                             "请选择卡密公钥文件，并填写产品 ID（1-64 位英文字母、数字或 ._-）。"});
                return false;
            }
        }
        return true;
    }

    void RunProtection(const QString& Verb) {
        if (!RequireProtection(Verb == "wrap")) return;
        QStringList Arguments{ Verb, Quote(InputEdit->text()), Quote(OutputEdit->text()), Quote(PasswordEdit->text()) };
        if (Verb == "wrap") Arguments << ProtectionOptions(false);
        else if (Verb == "pack" && CompressCheck->isChecked()) Arguments << "--compress";
        Start(Arguments, Verb);
    }

    void Start(const QStringList& Arguments, const QString& Title) {
        if (Running) {
            NotifyInfo({"Busy", "\u5fd9\u788c"},
                       {"Wait for the running command to finish.", "\u8bf7\u7b49\u5f85\u5f53\u524d\u547d\u4ee4\u5b8c\u6210\u3002"});
            return;
        }
        const auto Program = PevmPath();
        if (!QFileInfo::exists(Program)) {
            NotifyError({"PeVm.exe missing", "\u627e\u4e0d\u5230 PeVm.exe"},
                        {"PeVm.exe must sit next to the GUI executable.",
                         "PeVm.exe \u5fc5\u987b\u4e0e GUI \u4f4d\u4e8e\u540c\u4e00\u76ee\u5f55\u3002"});
            return;
        }
        Running = true;
        Ring->show();
        statusBar()->showMessage(T({"Running: ", "\u8fd0\u884c\u4e2d: "}) + Title);
        auto LogArguments = Arguments;
        if (!LogArguments.isEmpty()) {
            const auto& Command = LogArguments.front();
            if ((Command == "pack" || Command == "unpack" || Command == "wrap" ||
                 Command == "protect-function" || Command == "protect-functions" ||
                 Command == "protect-all") && LogArguments.size() > 3) {
                LogArguments[3] = "<redacted>";
            }
        }
        AppendLog("PeVm " + LogArguments.join(' ') + "\n");
        Started = std::chrono::steady_clock::now();
        Runner->start(Program, Arguments);
    }

    void FinishRun(const QString& Outcome) {
        const auto Millis = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - Started).count();
        AppendLog(QString("---- %1 (%2 ms) ----\n\n").arg(Outcome).arg(Millis));
        Ring->hide();
        statusBar()->showMessage(Outcome + QString(" (%1 ms)").arg(Millis));
        Running = false;
        if (Outcome == T({"done", "\u5b8c\u6210"})) {
            NotifyInfo({"Finished", "\u5b8c\u6210"},
                       QString(T({"Command completed in %1 ms.", "\u547d\u4ee4\u5df2\u5728 %1 ms \u5185\u5b8c\u6210\u3002"})).arg(Millis));
        }
    }

    void AppendLog(const QString& Text) {
        Log->insertPlainText(Text);
        Log->moveCursor(QTextCursor::End);
    }
};

} // namespace

int main(int Argc, char** Argv) {
    QApplication App(Argc, Argv);
    QApplication::setApplicationName("PeVmProtector");
    MainWindow Window;
    Window.show();
    Window.raise();
    Window.activateWindow();
    return App.exec();
}
