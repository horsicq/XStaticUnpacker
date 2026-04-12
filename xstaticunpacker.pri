INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD
INCLUDEPATH += $$PWD/../../_3rdparty/upx/vendor/ucl/include
INCLUDEPATH += $$PWD/../../_3rdparty/upx/vendor/ucl

!contains(XCONFIG, xupx_ucl) {
    XCONFIG += xupx_ucl

    SOURCES += \
        $$PWD/../../_3rdparty/upx/vendor/ucl/src/alloc.c \
        $$PWD/../../_3rdparty/upx/vendor/ucl/src/n2b_d.c \
        $$PWD/../../_3rdparty/upx/vendor/ucl/src/n2b_ds.c \
        $$PWD/../../_3rdparty/upx/vendor/ucl/src/n2d_d.c \
        $$PWD/../../_3rdparty/upx/vendor/ucl/src/n2d_ds.c \
        $$PWD/../../_3rdparty/upx/vendor/ucl/src/n2e_d.c \
        $$PWD/../../_3rdparty/upx/vendor/ucl/src/n2e_ds.c \
        $$PWD/../../_3rdparty/upx/vendor/ucl/src/ucl_crc.c \
        $$PWD/../../_3rdparty/upx/vendor/ucl/src/ucl_init.c \
        $$PWD/../../_3rdparty/upx/vendor/ucl/src/ucl_ptr.c \
        $$PWD/../../_3rdparty/upx/vendor/ucl/src/ucl_str.c \
        $$PWD/../../_3rdparty/upx/vendor/ucl/src/ucl_util.c
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
    $$PWD/xupx.h \

SOURCES += \
    $$PWD/xinnosetup.cpp \
    $$PWD/xnsis.cpp \
    $$PWD/xupx.cpp \
