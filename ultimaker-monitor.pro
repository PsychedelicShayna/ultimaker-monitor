QT += core gui charts widgets printsupport concurrent

TARGET = ultimaker-monitor
TEMPLATE = app

INCLUDEPATH += \
    C:/Curl/include

LIBS += -LC:/Curl/lib
LIBS += -llibcurl

LIBS += \
    -lws2_32 \
    -lwldap32 \
    -ladvapi32 \
    -lkernel32 \
    -lcomdlg32 \
    -lcrypt32 \
    -lnormaliz

CONFIG += c++17

SOURCES += \
        main.cxx \
        main_wnd.cxx \
        qcustomplot.cpp
        # printer_state.cxx \
        # ltimaker_printer.cxx \
        # ltimaker_printer_api.cxx

HEADERS += \
        main_wnd.hxx \
        qcustomplot.h \
        json.hpp

        # printer_state.hxx \
        # ultimaker_printer.hxx \
        # ultimaker_printer_api.hxx

FORMS += \
        main_wnd.ui