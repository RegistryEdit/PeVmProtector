#pragma once

#include "LineEdit.h"
#include "PushButton.h"
#include "Label.h"
#include "SpinBox.h"
#include "TextEdit.h"
#include "InfoBar.h"
#include "ScrollBar.h"
#include "PeVmLicenseFormat.h"
#include <QApplication>
#include <QClipboard>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QRegularExpression>
#include <QVBoxLayout>
#include <functional>
#include <vector>

class LicensePage final : public QWidget {
public:
    using Completion = std::function<void(bool, const QByteArray&)>;
    std::function<bool(const QStringList&, Completion)> Run;
    std::function<void(const QString&, const QString&)> ApplyProtection;

    explicit LicensePage(QWidget* Parent = nullptr) : QWidget(Parent) {
        const auto Layout = new QVBoxLayout(this);
        auto* Title = new SubtitleLabel;
        Bind(Title, "License issuance", "卡密签发与验证");
        Layout->addWidget(Title);
        auto* Help = new BodyLabel;
        Help->setWordWrap(true);
        Bind(Help, "Generate a signing key pair, enter the product and customer machine ID, then issue or verify a license. Private keys use this Windows user's DPAPI; new files never overwrite existing files.",
                   "生成签发密钥对，填写产品和客户机器码，再签发或验证卡密。私钥由当前 Windows 用户的 DPAPI 保护；新文件不会覆盖已有文件。");
        Layout->addWidget(Help);
        const auto Form = new QFormLayout;
        PrivatePath = PathRow(Form, "Signing private key", "签发私钥", "SigningPrivatePath", "Private key (*.private);;All files (*)");
        PublicPath = PathRow(Form, "Verification public key", "验证公钥", "SigningPublicPath", "Public key (*.pub);;All files (*)");
        Layout->addLayout(Form);
        const auto KeyActions = new QHBoxLayout;
        auto* Generate = Button(KeyActions, "GenerateKeyPair", "Generate key pair", "生成密钥对");
        auto* Export = Button(KeyActions, "ExportPublicKey", "Export public key", "从私钥导出公钥");
        Layout->addLayout(KeyActions);

        const auto Policy = new QFormLayout;
        Product = new LineEdit;
        Product->setObjectName("IssueProduct");
        Product->setPlaceholderText("my-product");
        Product->setMaxLength(64);
        AddRow(Policy, "Product ID", "产品 ID", Product);
        const auto MachineRow = new QWidget;
        const auto MachineLayout = new QHBoxLayout(MachineRow);
        MachineLayout->setContentsMargins(0, 0, 0, 0);
        Machine = new LineEdit;
        Machine->setObjectName("IssueMachine");
        Machine->setMaxLength(64);
        MachineLayout->addWidget(Machine, 1);
        auto* GetMachine = Button(MachineLayout, "GetMachineId", "This machine", "获取本机机器码");
        auto* CopyMachine = Button(MachineLayout, "CopyMachineId", "Copy", "复制");
        AddRow(Policy, "Customer machine ID", "客户机器码", MachineRow);
        Days = new SpinBox;
        Days->setObjectName("IssueDays");
        Days->setRange(0, 36500);
        Days->setValue(30);
        AddRow(Policy, "Valid days (0 = perpetual)", "有效天数（0 为永久）", Days);
        LicensePath = PathRow(Policy, "License file", "卡密文件", "IssuedLicensePath", "License (*.license);;All files (*)");
        Layout->addLayout(Policy);
        const auto Actions = new QHBoxLayout;
        auto* Issue = Button(Actions, "IssueLicense", "Issue license", "签发卡密", true);
        auto* Verify = Button(Actions, "VerifyLicense", "Verify license file", "验证卡密文件");
        auto* Apply = Button(Actions, "ApplyLicensePolicy", "Use for protection", "用于程序保护");
        Layout->addLayout(Actions);
        Result = new BodyLabel;
        Result->setObjectName("LicenseResult");
        Result->setWordWrap(true);
        Layout->addWidget(Result);
        LicenseText = new PlainTextEdit;
        LicenseText->setObjectName("IssuedLicenseText");
        LicenseText->setReadOnly(true);
        LicenseText->setVerticalScrollBar(new ScrollBar(LicenseText));
        LicenseText->setHorizontalScrollBar(new ScrollBar(LicenseText));
        LicenseText->setMinimumHeight(100);
        LicenseText->setMaximumHeight(140);
        Layout->addWidget(LicenseText);
        const auto CopyRow = new QHBoxLayout;
        auto* Copy = Button(CopyRow, "CopyLicense", "Copy issued license", "复制已签发卡密");
        CopyRow->addStretch(1);
        Layout->addLayout(CopyRow);
        Layout->addStretch(1);

        connect(Generate, &QPushButton::clicked, this, [this] {
            if (!NewFile(PrivatePath->text()) || !NewFile(PublicPath->text())) return;
            if (QFileInfo(PrivatePath->text()).absoluteFilePath().compare(QFileInfo(PublicPath->text()).absoluteFilePath(), Qt::CaseInsensitive) == 0) {
                Error("Private and public paths must differ.", "私钥与公钥路径必须不同。"); return;
            }
            Execute({"license-keygen", PrivatePath->text(), PublicPath->text()});
        });
        connect(Export, &QPushButton::clicked, this, [this] {
            if (!ExistingFile(PrivatePath->text()) || !NewFile(PublicPath->text())) return;
            Execute({"license-export-public", PrivatePath->text(), PublicPath->text()});
        });
        connect(GetMachine, &QPushButton::clicked, this, [this] {
            if (!Run) return;
            Run({"license-machine-id"}, [this](bool Success, const QByteArray& Output) {
                const auto Match = QRegularExpression("machine id: ([0-9a-fA-F]{64})").match(QString::fromUtf8(Output));
                if (Success && Match.hasMatch()) Machine->setText(Match.captured(1));
                Result->setText(Success ? Tr("Machine ID loaded.", "已获取本机机器码。") : QString::fromUtf8(Output));
            });
        });
        connect(CopyMachine, &QPushButton::clicked, this, [this] { QApplication::clipboard()->setText(Machine->text()); });
        connect(Issue, &QPushButton::clicked, this, [this] {
            LicenseText->clear();
            Result->clear();
            if (!ExistingFile(PrivatePath->text()) || !ValidProduct() || !ValidMachine(true)) return;
            if (!LicensePath->text().trimmed().isEmpty() && !NewFile(LicensePath->text())) return;
            QStringList Arguments{"license-issue", PrivatePath->text(), QString::number(Days->value()),
                                  "--machine=" + Machine->text().trimmed(), "--product=" + Product->text().trimmed()};
            const auto OutputPath = LicensePath->text().trimmed();
            if (!OutputPath.isEmpty()) Arguments << "--output=" + OutputPath;
            if (!Run) return;
            Run(Arguments, [this, OutputPath](bool Success, const QByteArray& Output) {
                LicenseText->clear();
                QString Summary = QString::fromUtf8(Output);
                if (Success) {
                    if (!OutputPath.isEmpty()) {
                        QFile File(OutputPath);
                        if (File.open(QIODevice::ReadOnly) && File.size() <= 4096) LicenseText->setPlainText(QString::fromUtf8(File.readAll()).trimmed());
                    } else {
                        QStringList Details;
                        for (const auto& Line : Summary.split('\n')) {
                            if (Line.startsWith(pevm::license::KLicensePrefix)) LicenseText->setPlainText(Line.trimmed());
                            else Details << Line;
                        }
                        Summary = Details.join('\n');
                    }
                }
                Result->setText(Summary.trimmed());
            });
        });
        connect(Verify, &QPushButton::clicked, this, [this] {
            if (!ExistingFile(PublicPath->text()) || !ExistingFile(LicensePath->text()) || !ValidProduct() || !ValidMachine(false)) return;
            QStringList Arguments{"license-verify", PublicPath->text(), LicensePath->text(), "--product=" + Product->text().trimmed()};
            if (!Machine->text().trimmed().isEmpty()) Arguments << "--machine=" + Machine->text().trimmed();
            Execute(Arguments);
        });
        connect(Apply, &QPushButton::clicked, this, [this] {
            if (!ExistingFile(PublicPath->text()) || !ValidProduct()) return;
            if (ApplyProtection) ApplyProtection(PublicPath->text(), Product->text().trimmed());
        });
        connect(Copy, &QPushButton::clicked, this, [this] { QApplication::clipboard()->setText(LicenseText->toPlainText()); });
        SetChinese(false);
    }

    void SetChinese(bool Value) {
        Chinese = Value;
        for (const auto& Update : Translations) Update();
        Machine->setPlaceholderText(Tr("64 hex digits; blank verifies this machine", "64 位十六进制；验证时留空使用本机"));
        LicensePath->setPlaceholderText(Tr("Optional when issuing; required for verification", "签发时可留空显示卡密；验证时必填"));
    }

private:
    bool Chinese{};
    LineEdit *PrivatePath{}, *PublicPath{}, *Product{}, *Machine{}, *LicensePath{};
    SpinBox* Days{};
    BodyLabel* Result{};
    PlainTextEdit* LicenseText{};
    std::vector<std::function<void()>> Translations;
    QString Tr(const char* En, const char* Zh) const { return QString::fromUtf8(Chinese ? Zh : En); }
    template<class T> void Bind(T* Widget, const char* En, const char* Zh) {
        Translations.push_back([=, this] { Widget->setText(Tr(En, Zh)); });
    }
    void AddRow(QFormLayout* Form, const char* En, const char* Zh, QWidget* Widget) {
        auto* Label = new BodyLabel;
        Bind(Label, En, Zh);
        Form->addRow(Label, Widget);
    }
    PushButton* Button(QHBoxLayout* Row, const char* Id, const char* En, const char* Zh, bool Primary = false) {
        PushButton* Value = Primary ? new PrimaryPushButton : new PushButton;
        Value->setObjectName(Id);
        Bind(Value, En, Zh);
        Row->addWidget(Value);
        return Value;
    }
    LineEdit* PathRow(QFormLayout* Form, const char* En, const char* Zh, const char* Id, const char* Filter) {
        const auto Container = new QWidget;
        const auto Row = new QHBoxLayout(Container);
        Row->setContentsMargins(0, 0, 0, 0);
        auto* Edit = new LineEdit;
        Edit->setObjectName(Id);
        Row->addWidget(Edit, 1);
        auto* Open = Button(Row, "", "Open…", "选择已有…");
        auto* Save = Button(Row, "", "New…", "新建路径…");
        connect(Open, &QPushButton::clicked, this, [=, this] {
            const auto Path = QFileDialog::getOpenFileName(this, Tr(En, Zh), Edit->text(), Filter);
            if (!Path.isEmpty()) Edit->setText(Path);
        });
        connect(Save, &QPushButton::clicked, this, [=, this] {
            const auto Path = QFileDialog::getSaveFileName(this, Tr(En, Zh), Edit->text(), Filter);
            if (!Path.isEmpty()) Edit->setText(Path);
        });
        AddRow(Form, En, Zh, Container);
        return Edit;
    }
    void Error(const char* En, const char* Zh) {
        Result->setText(Tr(En, Zh));
        InfoBar::error(Tr("Invalid input", "输入无效"), Tr(En, Zh), Qt::Horizontal, true, 4000, InfoBar::Position::TOP_RIGHT, window());
    }
    bool ExistingFile(const QString& Path) {
        if (QFileInfo(Path).isFile()) return true;
        Error("Select an existing file.", "请选择已有文件。"); return false;
    }
    bool NewFile(const QString& Path) {
        if (!Path.trimmed().isEmpty() && !QFileInfo::exists(Path) && QFileInfo(QFileInfo(Path).absolutePath()).isDir()) return true;
        Error("Choose a new file path in an existing directory; existing files are preserved.", "请选择已有目录中的新文件路径；已有文件会保留。"); return false;
    }
    bool ValidProduct() {
        if (QRegularExpression("^[A-Za-z0-9._-]{1,64}$").match(Product->text().trimmed()).hasMatch()) return true;
        Error("Product ID: 1–64 ASCII letters, digits or ._-.", "产品 ID 需为 1–64 位英文字母、数字或 ._-。"); return false;
    }
    bool ValidMachine(bool Required) {
        const auto Value = Machine->text().trimmed();
        if ((!Required && Value.isEmpty()) || QRegularExpression("^[0-9a-fA-F]{64}$").match(Value).hasMatch()) return true;
        Error("Enter a 64-digit hexadecimal machine ID.", "请输入 64 位十六进制机器码。"); return false;
    }
    void Execute(const QStringList& Arguments) {
        if (Run) Run(Arguments, [this](bool, const QByteArray& Output) { Result->setText(QString::fromUtf8(Output).trimmed()); });
    }
};
