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
    $$PWD/xupx.h \

SOURCES += \
    $$PWD/xinnosetup.cpp \
    $$PWD/xupx.cpp \
