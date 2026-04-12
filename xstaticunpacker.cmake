include_directories(${CMAKE_CURRENT_LIST_DIR})
set(XUPX_UCL_DIR ${CMAKE_CURRENT_LIST_DIR}/../../_3rdparty/upx/vendor/ucl)
include_directories(${XUPX_UCL_DIR}/include)
include_directories(${XUPX_UCL_DIR})

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
    ${XUPX_UCL_DIR}/src/alloc.c
    ${XUPX_UCL_DIR}/src/n2b_d.c
    ${XUPX_UCL_DIR}/src/n2b_ds.c
    ${XUPX_UCL_DIR}/src/n2d_d.c
    ${XUPX_UCL_DIR}/src/n2d_ds.c
    ${XUPX_UCL_DIR}/src/n2e_d.c
    ${XUPX_UCL_DIR}/src/n2e_ds.c
    ${XUPX_UCL_DIR}/src/ucl_crc.c
    ${XUPX_UCL_DIR}/src/ucl_init.c
    ${XUPX_UCL_DIR}/src/ucl_ptr.c
    ${XUPX_UCL_DIR}/src/ucl_str.c
    ${XUPX_UCL_DIR}/src/ucl_util.c
    ${CMAKE_CURRENT_LIST_DIR}/xinnosetup.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xinnosetup.h
    ${CMAKE_CURRENT_LIST_DIR}/xnsis.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xnsis.h
    ${CMAKE_CURRENT_LIST_DIR}/xupx.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xupx.h
)
