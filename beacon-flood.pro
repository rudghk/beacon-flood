TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap  \
        -pthread

SOURCES += \
    main.cpp

DESTDIR = $${PWD}/bin

HEADERS += \
    beacon.h \
    dot11.h \
    mac.h
