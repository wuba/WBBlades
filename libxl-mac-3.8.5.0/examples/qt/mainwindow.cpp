#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QProcess>

#ifdef _WIN32
  #include <windows.h>
#endif

#include "libxl.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);   
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::generateExcel()
{
    using namespace libxl;

    Book* book = xlCreateBook(); // use xlCreateXMLBook() for working with xlsx files

    Sheet* sheet = book->addSheet("Sheet1");

    sheet->writeStr(2, 1, "Hello, World !");
    sheet->writeNum(4, 1, 1000);
    sheet->writeNum(5, 1, 2000);

    Font* font = book->addFont();
    font->setColor(COLOR_RED);
    font->setBold(true);
    Format* boldFormat = book->addFormat();
    boldFormat->setFont(font);
    sheet->writeFormula(6, 1, "SUM(B5:B6)", boldFormat);

    Format* dateFormat = book->addFormat();
    dateFormat->setNumFormat(NUMFORMAT_DATE);
    sheet->writeNum(8, 1, book->datePack(2011, 7, 20), dateFormat);

    sheet->setCol(1, 1, 12);

    book->save("report.xls");

    book->release();

    ui->pushButton->setText("Please wait...");
    ui->pushButton->setEnabled(false);

#ifdef _WIN32

    ::ShellExecuteA(NULL, "open", "report.xls", NULL, NULL, SW_SHOW);

#elif __APPLE__

    QProcess::execute("open report.xls");

#else

    QProcess::execute("oocalc report.xls");

#endif

    ui->pushButton->setText("Generate Excel Report");
    ui->pushButton->setEnabled(true);

}
