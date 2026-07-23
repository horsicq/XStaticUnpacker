INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

!contains(XCONFIG, xformats) {
    XCONFIG += xformats
    include($$PWD/../Formats/xformats.pri)
}

!contains(XCONFIG, xarchives) {
    XCONFIG += xarchives
    include($$PWD/../XArchive/xarchives.pri)
}

HEADERS += \
    $$PWD/xinnosetup.h \
    $$PWD/xnsis.h \
    $$PWD/xupx.h \
    $$PWD/xsfx.h \
    $$PWD/xfsg.h \
    $$PWD/xyoda.h \
    $$PWD/xnspack.h \
    $$PWD/xaspack.h \
    $$PWD/xpetite.h \
    $$PWD/xmew.h \
    $$PWD/xpespin.h \
    $$PWD/xautoit.h \

SOURCES += \
    $$PWD/xinnosetup.cpp \
    $$PWD/xnsis.cpp \
    $$PWD/xupx.cpp \
    $$PWD/xsfx.cpp \
    $$PWD/xfsg.cpp \
    $$PWD/xyoda.cpp \
    $$PWD/xnspack.cpp \
    $$PWD/xaspack.cpp \
    $$PWD/xpetite.cpp \
    $$PWD/xmew.cpp \
    $$PWD/xpespin.cpp \
    $$PWD/xautoit.cpp \
