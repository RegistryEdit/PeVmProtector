#pragma once

#include <QFileDialog>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSet>
#include <QSignalBlocker>
#include "TableView.h"
#include "LineEdit.h"
#include "PushButton.h"
#include "Label.h"
#include "ScrollBar.h"
#include <QVBoxLayout>
#include <functional>

// No moc: the owner supplies callbacks and the selected RVAs are the identity.
class FunctionPicker final : public QWidget {
public:
    explicit FunctionPicker(QWidget* Parent = nullptr) : QWidget(Parent) {
        const auto Layout = new QVBoxLayout(this);
        Layout->setContentsMargins(0, 0, 0, 0);
        const auto PdbRow = new QHBoxLayout;
        Pdb = new LineEdit;
        Pdb->setObjectName("FunctionPdbPath");
        Browse = new PushButton;
        PdbRow->addWidget(Pdb, 1);
        PdbRow->addWidget(Browse);
        Layout->addLayout(PdbRow);
        const auto FilterRow = new QHBoxLayout;
        Search = new LineEdit;
        Search->setObjectName("FunctionSearch");
        SelectVisible = new PushButton;
        ClearSelection = new PushButton;
        FilterRow->addWidget(Search, 1);
        FilterRow->addWidget(SelectVisible);
        FilterRow->addWidget(ClearSelection);
        Layout->addLayout(FilterRow);
        Summary = new CaptionLabel;
        Summary->setFixedHeight(28);
        Layout->addWidget(Summary);
        Table = new TableWidget;
        Table->setObjectName("FunctionTable");
        Table->setColumnCount(4);
        Table->setMinimumHeight(220);
        Table->setSelectionMode(QAbstractItemView::ExtendedSelection);
        Table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
        for (int I = 1; I < 4; ++I) Table->horizontalHeader()->setSectionResizeMode(I, QHeaderView::ResizeToContents);
        Table->setBorderVisible(true);
        Table->verticalHeader()->hide();
        Table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        Table->setVerticalScrollBar(new ScrollBar(Table));
        Table->setHorizontalScrollBar(new ScrollBar(Table));
        Layout->addWidget(Table);
        connect(Search, &QLineEdit::textChanged, this, [this] { Filter(); });
        connect(Table, &QTableWidget::itemChanged, this, [this] { UpdateSummary(); });
        connect(SelectVisible, &QPushButton::clicked, this, [this] {
            const QSignalBlocker Block(Table);
            for (int I = 0; I < Table->rowCount(); ++I) {
                auto* Item = Table->item(I, 0);
                if (!Table->isRowHidden(I)) Item->setCheckState(Qt::Checked);
            }
            UpdateSummary();
        });
        connect(ClearSelection, &QPushButton::clicked, this, [this] {
            const QSignalBlocker Block(Table);
            for (int I = 0; I < Table->rowCount(); ++I) Table->item(I, 0)->setCheckState(Qt::Unchecked);
            UpdateSummary();
        });
        connect(Browse, &QPushButton::clicked, this, [this] {
            const auto Path = QFileDialog::getOpenFileName(this, Chinese ? "选择 PDB" : "Select PDB", Pdb->text(), "PDB (*.pdb)");
            if (!Path.isEmpty()) Pdb->setText(Path);
        });
        connect(Pdb, &QLineEdit::textChanged, this, [this] {
            Clear();
            if (SymbolsChanged) SymbolsChanged();
        });
        SetChinese(false);
    }

    std::function<void()> SelectionChanged;
    std::function<void()> SymbolsChanged;

    QString PdbPath() const { return Pdb->text().trimmed(); }
    QStringList Rvas() const {
        QStringList Result;
        for (int I = 0; I < Table->rowCount(); ++I) {
            const auto* Item = Table->item(I, 0);
            if (Item->checkState() == Qt::Checked) Result << Table->item(I, 1)->text();
        }
        return Result;
    }

    void Clear() {
        Table->setRowCount(0);
        Loaded = false;
        UpdateSummary();
    }

    bool Load(const QByteArray& Json) {
        QJsonParseError Error;
        const auto Document = QJsonDocument::fromJson(Json, &Error);
        const auto Root = Document.object();
        if (Error.error != QJsonParseError::NoError || Root["format"].toString() != "pevm-scan-functions" ||
            !Root["functions"].isArray()) return false;
        // Validate the whole manifest before making it actionable.
        const auto Functions = Root["functions"].toArray();
        QSet<quint32> Seen;
        for (const auto& Value : Functions) {
            const auto Entry = Value.toObject();
            bool Valid{};
            const auto Rva = Entry["rva"].toString().toUInt(&Valid, 0);
            if (!Valid || !Rva || Seen.contains(Rva)) return false;
            Seen.insert(Rva);
        }
        const QSignalBlocker Block(Table);
        Table->setRowCount(0);
        for (const auto& Value : Functions) {
            const auto Entry = Value.toObject();
            const auto Rva = Entry["rva"].toString();
            auto Name = Entry["name"].toString();
            if (Name.isEmpty()) Name = "sub_" + Rva.mid(2).toUpper();
            QStringList Aliases;
            for (const auto& Alias : Entry["aliases"].toArray()) Aliases << Alias.toString();
            const auto Size = Entry["size"].toInteger();
            const auto Row = Table->rowCount();
            Table->insertRow(Row);
            auto* Item = new QTableWidgetItem(Name);
            Table->setItem(Row, 0, Item);
            Table->setItem(Row, 1, new QTableWidgetItem(Rva));
            Table->setItem(Row, 2, new QTableWidgetItem(Size ? QString::number(Size) : "?"));
            Table->setItem(Row, 3, new QTableWidgetItem(Entry["nameSource"].toString()));
            Item->setFlags(Item->flags() | Qt::ItemIsUserCheckable);
            Item->setCheckState(Qt::Unchecked);
            const auto Detail = Name + "\n" + Entry["decoratedName"].toString() + "\n" + Aliases.join('\n');
            Item->setToolTip(Detail);
            Item->setData(Qt::UserRole, Detail + "\n" + Rva);
        }
        Loaded = true;
        Filter();
        return true;
    }

    void SetChinese(bool Value) {
        Chinese = Value;
        Pdb->setPlaceholderText(Chinese ? "PDB（可选，自动查找同目录及原构建路径）" : "PDB (optional; searches beside PE and original build path)");
        Browse->setText(Chinese ? "选择 PDB…" : "Browse PDB…");
        Search->setPlaceholderText(Chinese ? "搜索函数名 / RVA" : "Search function name / RVA");
        SelectVisible->setText(Chinese ? "勾选筛选结果" : "Check filtered");
        ClearSelection->setText(Chinese ? "清空勾选" : "Clear checks");
        Table->setHorizontalHeaderLabels(Chinese ? QStringList{"函数名", "RVA", "字节数", "名称来源"}
                                     : QStringList{"Function name", "RVA", "Bytes", "Name source"});
        UpdateSummary();
    }

private:
    LineEdit *Pdb{}, *Search{};
    PushButton *Browse{}, *SelectVisible{}, *ClearSelection{};
    TableWidget* Table{};
    CaptionLabel* Summary{};
    bool Chinese{}, Loaded{};

    void Filter() {
        const auto Query = Search->text().trimmed();
        for (int I = 0; I < Table->rowCount(); ++I) {
            auto* Item = Table->item(I, 0);
            Table->setRowHidden(I, !Item->data(Qt::UserRole).toString().contains(Query, Qt::CaseInsensitive));
        }
        UpdateSummary();
    }
    void UpdateSummary() {
        int Visible{}, Named{};
        for (int I = 0; I < Table->rowCount(); ++I) {
            Visible += !Table->isRowHidden(I);
            Named += !Table->item(I, 3)->text().isEmpty();
        }
        Summary->setText(Loaded
            ? QString(Chinese ? "共 %1 个 · 已命名 %2 个 · 显示 %3 个 · 已勾选 %4 个（含隐藏项）"
                       : "%1 functions · %2 named · %3 visible · %4 checked (including hidden)")
                  .arg(Table->rowCount()).arg(Named).arg(Visible).arg(Rvas().size())
            : (Chinese ? "扫描后勾选要虚拟化的函数；无符号时显示 sub_RVA。" : "Scan, then check functions to virtualize; unnamed entries use sub_RVA."));
        if (SelectionChanged) SelectionChanged();
    }
};
