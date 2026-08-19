include_directories(${CMAKE_CURRENT_LIST_DIR})

# Signals to lower layers (e.g. XFormats) that the XStaticUnpacker classes are
# compiled into this target, so they may reference them (packer/installer
# FT_PE32_*/FT_CFBF_* handle-method file types).
add_definitions(-DUSE_STATICUNPACKER)

if (WITH_XEMULATOR)
    add_definitions(-DUSE_XEMULATOR)

    set(XINSTALLSIMPLE_XEMULATOR_DIR ${CMAKE_CURRENT_LIST_DIR}/../XEmulator)
    include_directories(${XINSTALLSIMPLE_XEMULATOR_DIR})
    include_directories(${XINSTALLSIMPLE_XEMULATOR_DIR}/arch)

    set(XINSTALLSIMPLE_XEMULATOR_SOURCES
        ${XINSTALLSIMPLE_XEMULATOR_DIR}/xemumemorymanager.cpp
        ${XINSTALLSIMPLE_XEMULATOR_DIR}/xemumemorymanager.h
        ${XINSTALLSIMPLE_XEMULATOR_DIR}/xemuregisters.cpp
        ${XINSTALLSIMPLE_XEMULATOR_DIR}/xemuregisters.h
        ${XINSTALLSIMPLE_XEMULATOR_DIR}/xemutypes.h
        ${XINSTALLSIMPLE_XEMULATOR_DIR}/arch/xemuarch.cpp
        ${XINSTALLSIMPLE_XEMULATOR_DIR}/arch/xemuarch.h
        ${XINSTALLSIMPLE_XEMULATOR_DIR}/arch/xemuopcache.h
        ${XINSTALLSIMPLE_XEMULATOR_DIR}/arch/xemutb.h
        ${XINSTALLSIMPLE_XEMULATOR_DIR}/arch/xemux86.cpp
        ${XINSTALLSIMPLE_XEMULATOR_DIR}/arch/xemux86.h
        ${CMAKE_CURRENT_LIST_DIR}/xinstallsimple.cpp
        ${CMAKE_CURRENT_LIST_DIR}/xinstallsimple.h
    )
endif()

if (NOT DEFINED XFORMATS_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../Formats/xformats.cmake)
    set(XSTATICUNPACKER_SOURCES ${XSTATICUNPACKER_SOURCES} ${XFORMATS_SOURCES})
endif()
if (NOT DEFINED XARCHIVES_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../XArchive/xarchives.cmake)
    set(XSTATICUNPACKER_SOURCES ${XSTATICUNPACKER_SOURCES} ${XARCHIVES_SOURCES})
endif()

set(XSTATICUNPACKER_SOURCES
    ${XSTATICUNPACKER_SOURCES}
    ${XINSTALLSIMPLE_XEMULATOR_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/xinnosetup.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xinnosetup.h
    ${CMAKE_CURRENT_LIST_DIR}/xnsis.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xnsis.h
    ${CMAKE_CURRENT_LIST_DIR}/nsis_bzip2/nsis_bzip2.c
    ${CMAKE_CURRENT_LIST_DIR}/nsis_bzip2/nsis_bzip2.h
    ${CMAKE_CURRENT_LIST_DIR}/nsis_bzip2/nsis_bzip2_private.h
    ${CMAKE_CURRENT_LIST_DIR}/xupx.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xupx.h
    ${CMAKE_CURRENT_LIST_DIR}/xsfx.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xsfx.h
    ${CMAKE_CURRENT_LIST_DIR}/xfsg.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xfsg.h
    ${CMAKE_CURRENT_LIST_DIR}/xyoda.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xyoda.h
    ${CMAKE_CURRENT_LIST_DIR}/xnspack.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xnspack.h
    ${CMAKE_CURRENT_LIST_DIR}/xaspack.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xaspack.h
    ${CMAKE_CURRENT_LIST_DIR}/xpetite.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xpetite.h
    ${CMAKE_CURRENT_LIST_DIR}/xmew.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xmew.h
    ${CMAKE_CURRENT_LIST_DIR}/xautoit.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xautoit.h
    ${CMAKE_CURRENT_LIST_DIR}/x7zsfx.cpp
    ${CMAKE_CURRENT_LIST_DIR}/x7zsfx.h
    ${CMAKE_CURRENT_LIST_DIR}/xwinrarsfx.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xwinrarsfx.h
    ${CMAKE_CURRENT_LIST_DIR}/xiexpress.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xiexpress.h
    ${CMAKE_CURRENT_LIST_DIR}/xmsi.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xmsi.h
    ${CMAKE_CURRENT_LIST_DIR}/xwix.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xwix.h
    ${CMAKE_CURRENT_LIST_DIR}/xadvancedinstaller.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xadvancedinstaller.h
    ${CMAKE_CURRENT_LIST_DIR}/xactualinstaller.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xactualinstaller.h
    ${CMAKE_CURRENT_LIST_DIR}/xclickteam.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xclickteam.h
    ${CMAKE_CURRENT_LIST_DIR}/xcreateinstall.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xcreateinstall.h
    ${CMAKE_CURRENT_LIST_DIR}/xenigmavb.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xenigmavb.h
    ${CMAKE_CURRENT_LIST_DIR}/xboxedapp.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xboxedapp.h
    ${CMAKE_CURRENT_LIST_DIR}/xinstallforge.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xinstallforge.h
    ${CMAKE_CURRENT_LIST_DIR}/xsmartinstall.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xsmartinstall.h
    ${CMAKE_CURRENT_LIST_DIR}/xtarma.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xtarma.h
)
