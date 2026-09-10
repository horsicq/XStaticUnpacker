INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

# XFormats gates the factories and detectors that refer to these sources on
# this define.  Keep qmake aligned with xstaticunpacker.cmake so compiling the
# sources also makes the corresponding file types reachable.
DEFINES += USE_STATICUNPACKER

contains(XCONFIG, use_xemulator) {
    DEFINES += USE_XEMULATOR
    XCONFIG += xinstallsimple_xemulator
    INCLUDEPATH += $$PWD/../XEmulator
    INCLUDEPATH += $$PWD/../XEmulator/arch
    DEPENDPATH += $$PWD/../XEmulator
    DEPENDPATH += $$PWD/../XEmulator/arch

    HEADERS += \
        $$PWD/../XEmulator/xemumemorymanager.h \
        $$PWD/../XEmulator/xemuregisters.h \
        $$PWD/../XEmulator/xemutypes.h \
        $$PWD/../XEmulator/arch/xemuarch.h \
        $$PWD/../XEmulator/arch/xemuopcache.h \
        $$PWD/../XEmulator/arch/xemutb.h \
        $$PWD/../XEmulator/arch/xemux86.h \
        $$PWD/xinstallsimple.h

    SOURCES += \
        $$PWD/../XEmulator/xemumemorymanager.cpp \
        $$PWD/../XEmulator/xemuregisters.cpp \
        $$PWD/../XEmulator/arch/xemuarch.cpp \
        $$PWD/../XEmulator/arch/xemux86.cpp \
        $$PWD/xinstallsimple.cpp
}

!contains(XCONFIG, xformats) {
    XCONFIG += xformats
    include($$PWD/../Formats/xformats.pri)
}

!contains(XCONFIG, xarchives) {
    XCONFIG += xarchives
    include($$PWD/../XArchive/xarchives.pri)
}

HEADERS += \
    $$PWD/xupx.h \
    $$PWD/xfsg.h \
    $$PWD/xyoda.h \
    $$PWD/xnspack.h \
    $$PWD/xaspack.h \
    $$PWD/xpetite.h \
    $$PWD/xmew.h \
    $$PWD/xautoit.h \
    $$PWD/xenigmavb.h \
    $$PWD/xboxedapp.h

SOURCES += \
    $$PWD/xupx.cpp \
    $$PWD/xfsg.cpp \
    $$PWD/xyoda.cpp \
    $$PWD/xnspack.cpp \
    $$PWD/xaspack.cpp \
    $$PWD/xpetite.cpp \
    $$PWD/xmew.cpp \
    $$PWD/xautoit.cpp \
    $$PWD/xenigmavb.cpp \
    $$PWD/xboxedapp.cpp
