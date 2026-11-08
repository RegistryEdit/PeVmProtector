#pragma once
#include "LineEdit.h"
#include "PushButton.h"
#include "CheckBox.h"
#include "Label.h"
#include "TextEdit.h"
#include "ScrollBar.h"
#include <QFormLayout>
#include <QRegularExpression>
#include <QVBoxLayout>
#include <array>
#include <cstdint>
#include <functional>
#include <vector>

class RawCodePage final : public QWidget {
public:
    std::function<void(const QStringList&)> Run;

    explicit RawCodePage(QWidget* Parent = nullptr) : QWidget(Parent) {
        const auto Layout = new QVBoxLayout(this);
        auto* Title = new SubtitleLabel;
        Bind(Title, "Raw x64 machine code", "原始 x64 机器码分析");
        Layout->addWidget(Title);
        auto* Help = new BodyLabel;
        Help->setWordWrap(true);
        Bind(Help, "Enter hexadecimal bytes, an entry RVA, and initial registers. Memory operands use VM offsets. Lifting results and optional execution trace appear in the log.",
                   "输入十六进制机器码、入口 RVA 和初始寄存器。内存操作数按 VM 偏移处理；提升结果和可选的执行跟踪显示在日志中。");
        Layout->addWidget(Help);
        Code = new PlainTextEdit;
        Code->setObjectName("RawBytes");
        Code->setVerticalScrollBar(new ScrollBar(Code));
        Code->setHorizontalScrollBar(new ScrollBar(Code));
        Code->setPlainText("48 89 C8 C3");
        Code->setMinimumHeight(80);
        Code->setMaximumHeight(150);
        Layout->addWidget(Code);
        const auto Form = new QFormLayout;
        Entry = Field(Form, "RawEntry", "Entry RVA", "入口 RVA", "0");
        Seed = Field(Form, "RawSeed", "Seed", "种子", "12345");
        Registers = {Field(Form, "RawRcx", "RCX", "RCX", "0"), Field(Form, "RawRdx", "RDX", "RDX", "0"),
                     Field(Form, "RawR8", "R8", "R8", "0"), Field(Form, "RawR9", "R9", "R9", "0")};
        Layout->addLayout(Form);
        Trace = new CheckBox;
        Trace->setObjectName("RawTrace");
        Bind(Trace, "Execution trace", "执行跟踪");
        Layout->addWidget(Trace);
        auto* Analyze = new PrimaryPushButton;
        Analyze->setObjectName("AnalyzeRaw");
        Bind(Analyze, "Analyze / run bridge", "分析 / 运行桥接测试");
        Layout->addWidget(Analyze);
        Error = new BodyLabel;
        Error->setWordWrap(true);
        Error->setObjectName("RawError");
        Layout->addWidget(Error);
        Layout->addStretch(1);
        connect(Analyze, &QPushButton::clicked, this, [this] {
            Error->clear();
            auto Bytes = Code->toPlainText();
            Bytes.remove(QRegularExpression("\\s+"));
            if (Bytes.isEmpty() || Bytes.size() % 2 || !QRegularExpression("^[0-9a-fA-F]+$").match(Bytes).hasMatch()) {
                Error->setText(Tr("Enter complete hexadecimal byte pairs (spaces and newlines are accepted).", "请输入完整的十六进制字节对，可使用空格与换行分隔。")); return;
            }
            // Leave room for the executable name, register arguments and quoting
            // under Windows' 32,767-character command-line limit.
            if (Bytes.size() > 16000) {
                Error->setText(Tr("At most 8,000 bytes per raw analysis; use PE analysis for larger code.", "单次原始分析最多 8,000 字节；更大的代码请使用 PE 函数分析。")); return;
            }
            quint64 EntryValue{};
            if (!Number(Entry, &EntryValue) || !Number(Seed)) return;
            if (EntryValue > UINT32_MAX) {
                Error->setText(Tr("Entry RVA must fit in 32 bits.", "入口 RVA 必须在 32 位无符号整数范围内。")); return;
            }
            QStringList Args{"lift-raw", Bytes, Entry->text().trimmed(), Seed->text().trimmed()};
            const std::array<const char*, 4> Options{"--rcx=", "--rdx=", "--r8=", "--r9="};
            for (size_t I = 0; I < Registers.size(); ++I) {
                if (!Number(Registers[I])) return;
                Args << Options[I] + Registers[I]->text().trimmed();
            }
            if (Trace->isChecked()) Args << "--trace";
            if (Run) Run(Args);
        });
        SetChinese(false);
    }

    void SetChinese(bool Value) { Chinese = Value; for (const auto& Update : Translations) Update(); }

private:
    bool Chinese{};
    PlainTextEdit* Code{};
    LineEdit *Entry{}, *Seed{};
    std::array<LineEdit*, 4> Registers{};
    CheckBox* Trace{};
    BodyLabel* Error{};
    std::vector<std::function<void()>> Translations;
    QString Tr(const char* En, const char* Zh) const { return QString::fromUtf8(Chinese ? Zh : En); }
    template<class T> void Bind(T* Widget, const char* En, const char* Zh) {
        Translations.push_back([=, this] { Widget->setText(Tr(En, Zh)); });
    }
    LineEdit* Field(QFormLayout* Form, const char* Name, const char* En, const char* Zh, const char* Default) {
        auto* Label = new BodyLabel;
        Bind(Label, En, Zh);
        auto* Edit = new LineEdit;
        Edit->setObjectName(Name);
        Edit->setText(Default);
        Form->addRow(Label, Edit);
        return Edit;
    }
    bool Number(LineEdit* Edit, quint64* Output = nullptr) {
        bool Ok{};
        const auto Value = Edit->text().trimmed().toULongLong(&Ok, 0);
        if (Ok && !Edit->text().trimmed().startsWith('-')) {
            if (Output) *Output = Value;
            return true;
        }
        Error->setText(Tr("Use unsigned integers or 0x-prefixed hexadecimal values for the RVA, seed and registers.", "RVA、种子和寄存器需填写无符号整数，十六进制以 0x 开头。"));
        Edit->setFocus();
        return false;
    }
};
