QT += core gui widgets concurrent printsupport

TARGET = ultimaker-monitor
TEMPLATE = app

INCLUDEPATH += \
    dependencies/curl/include \
    dependencies/nlohmann-json \
    dependencies/qcustomplot

LIBS += \
    -L..\..\dependencies/curl/lib \
    -llibcurl \
    -lws2_32 \
    -lwldap32 \
    -ladvapi32 \
    -lkernel32 \
    -lcomdlg32 \
    -lcrypt32 \
    -lnormaliz \

CONFIG += c++17

SOURCES += \
        source/main.cxx \
        source/main_wnd.cxx \
        dependencies/qcustomplot/qcustomplot.cpp

HEADERS += \
        source/main_wnd.hxx \
        dependencies/qcustomplot/qcustomplot.h \
        dependencies/nlohmann-json/json.hpp

FORMS += \
        source\main_wnd.ui