#-------------------------------------------------
#
# Project created by QtCreator 2011-07-21T09:01:37
#
#-------------------------------------------------

QT       += core gui

TARGET = qt-libxl
TEMPLATE = app

SOURCES += main.cpp\
        mainwindow.cpp

HEADERS  += mainwindow.h

FORMS    += mainwindow.ui

win32 {

    INCLUDEPATH = ../../../include_cpp
    LIBS += ../../../lib/libxl.lib

    QMAKE_POST_LINK +=$$quote(cmd /c copy /y ..\..\..\bin\libxl.dll .)

} else:macx {

    INCLUDEPATH = ../../include_cpp
    LIBS += -framework LibXL

    QMAKE_LFLAGS += -F../../
    QMAKE_POST_LINK +=$$quote(mkdir $${TARGET}.app/Contents/Frameworks;cp -R ../../LibXL.framework $${TARGET}.app/Contents/Frameworks/)

} else {

    INCLUDEPATH = ../../include_cpp
    LIBS += ../../lib/libxl.so

    QMAKE_LFLAGS_DEBUG = "-Wl,-rpath,../../lib"
    QMAKE_LFLAGS_RELEASE = "-Wl,-rpath,../../lib"
}

