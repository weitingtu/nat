TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
 
SOURCES += \
    nftest.c \
    checksum.c \
    net_print.c \

HEADERS += \
    checksum.h \
    net_print.h \
