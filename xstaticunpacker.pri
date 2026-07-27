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
    $$PWD/xautoit.h \
    $$PWD/x7zsfx.h \
    $$PWD/xwinrarsfx.h \
    $$PWD/xiexpress.h \
    $$PWD/xmsi.h \
    $$PWD/xwix.h \
    $$PWD/xadvancedinstaller.h \
    $$PWD/xactualinstaller.h \
    $$PWD/xclickteam.h \
    $$PWD/xcreateinstall.h \
    $$PWD/xenigmavb.h \
    $$PWD/xboxedapp.h \
    $$PWD/xinstallforge.h \
    $$PWD/xinstallsimple.h \
    $$PWD/xsmartinstall.h \
    $$PWD/xtarma.h \

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
    $$PWD/xautoit.cpp \
    $$PWD/x7zsfx.cpp \
    $$PWD/xwinrarsfx.cpp \
    $$PWD/xiexpress.cpp \
    $$PWD/xmsi.cpp \
    $$PWD/xwix.cpp \
    $$PWD/xadvancedinstaller.cpp \
    $$PWD/xactualinstaller.cpp \
    $$PWD/xclickteam.cpp \
    $$PWD/xcreateinstall.cpp \
    $$PWD/xenigmavb.cpp \
    $$PWD/xboxedapp.cpp \
    $$PWD/xinstallforge.cpp \
    $$PWD/xinstallsimple.cpp \
    $$PWD/xsmartinstall.cpp \
    $$PWD/xtarma.cpp \
