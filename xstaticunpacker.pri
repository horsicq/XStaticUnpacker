INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

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
    $$PWD/xinnosetup.h \
    $$PWD/xnsis.h \
    $$PWD/nsis_bzip2/nsis_bzip2.h \
    $$PWD/nsis_bzip2/nsis_bzip2_private.h \
    $$PWD/xupx.h \
    $$PWD/xsfx.h \
    $$PWD/xfsg.h \
    $$PWD/xyoda.h \
    $$PWD/xnspack.h \
    $$PWD/xaspack.h \
    $$PWD/xpetite.h \
    $$PWD/xmew.h \
    $$PWD/xautoit.h \
    $$PWD/x7zsfx.h \
    $$PWD/xwinrarsfx.h \
    $$PWD/xiexpress.h \
    $$PWD/xmsi.h \
    $$PWD/xwix.h \
    $$PWD/xburn.h \
    $$PWD/xadvancedinstaller.h \
    $$PWD/xactualinstaller.h \
    $$PWD/xclickteam.h \
    $$PWD/xcreateinstall.h \
    $$PWD/xenigmavb.h \
    $$PWD/xboxedapp.h \
    $$PWD/xinstallforge.h \
    $$PWD/xsmartinstall.h \
    $$PWD/xtarma.h \

NSIS_BZIP2_SOURCE = $$PWD/nsis_bzip2/nsis_bzip2.cpp
!exists($$NSIS_BZIP2_SOURCE) {
    NSIS_BZIP2_SOURCE = $$PWD/nsis_bzip2/nsis_bzip2.c
    !exists($$NSIS_BZIP2_SOURCE) {
        error("Cannot find nsis_bzip2 source file: nsis_bzip2.cpp or nsis_bzip2.c")
    }
}
SOURCES += \
    $$PWD/xinnosetup.cpp \
    $$PWD/xnsis.cpp \
    $$NSIS_BZIP2_SOURCE \
    $$PWD/xupx.cpp \
    $$PWD/xsfx.cpp \
    $$PWD/xfsg.cpp \
    $$PWD/xyoda.cpp \
    $$PWD/xnspack.cpp \
    $$PWD/xaspack.cpp \
    $$PWD/xpetite.cpp \
    $$PWD/xmew.cpp \
    $$PWD/xautoit.cpp \
    $$PWD/x7zsfx.cpp \
    $$PWD/xwinrarsfx.cpp \
    $$PWD/xiexpress.cpp \
    $$PWD/xmsi.cpp \
    $$PWD/xwix.cpp \
    $$PWD/xburn.cpp \
    $$PWD/xadvancedinstaller.cpp \
    $$PWD/xactualinstaller.cpp \
    $$PWD/xclickteam.cpp \
    $$PWD/xcreateinstall.cpp \
    $$PWD/xenigmavb.cpp \
    $$PWD/xboxedapp.cpp \
    $$PWD/xinstallforge.cpp \
    $$PWD/xsmartinstall.cpp \
    $$PWD/xtarma.cpp \
