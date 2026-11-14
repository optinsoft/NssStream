cmake_minimum_required(VERSION 3.22)
project(proxymap_nss C)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# zlib: statically linked from the vendored sources NSS itself ships in
# nss/lib/zlib (the same copy NSS links into nss3). Building it here removes
# the runtime dependency on zlib1.dll / libz.so.1. Only the codecs the
# wrapper needs are compiled (compress/uncompress); gz* file-I/O sources are
# skipped. Note: this vendored copy relies on the standard headers (NULL,
# stdio), so Z_SOLO must NOT be defined.
set(ZLIB_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../nss/lib/zlib")
set(ZLIB_SOURCES
    "${ZLIB_SRC_DIR}/adler32.c"
    "${ZLIB_SRC_DIR}/compress.c"
    "${ZLIB_SRC_DIR}/crc32.c"
    "${ZLIB_SRC_DIR}/deflate.c"
    "${ZLIB_SRC_DIR}/inffast.c"
    "${ZLIB_SRC_DIR}/inflate.c"
    "${ZLIB_SRC_DIR}/inftrees.c"
    "${ZLIB_SRC_DIR}/trees.c"
    "${ZLIB_SRC_DIR}/uncompr.c"
    "${ZLIB_SRC_DIR}/zutil.c")
add_library(zlib_static STATIC ${ZLIB_SOURCES})
target_include_directories(zlib_static PUBLIC "${ZLIB_SRC_DIR}")
# Hide zlib's symbols in the shared wrapper so they cannot interpose with
# (or be interposed by) the copy NSS links into nss3.dll / libnss3.so.
if (NOT MSVC)
    target_compile_options(zlib_static PRIVATE -fvisibility=hidden)
endif()
# Match NSS's own build (nss/lib/zlib/manifest.mn): silence the debug trace.
target_compile_definitions(zlib_static PRIVATE verbose=-1)

# brotli: statically linked from the vendored sources in ../brotli (same
# situation as zlib above) so the wrapper has no runtime dependency on
# libbrotlienc/libbrotlidec (brotlienc.dll/brotlidec.dll on Windows). Only
# the entry points the wrapper needs are exercised
# (BrotliEncoderCompress/BrotliDecoderDecompress). Set
# -DNSW_STATIC_BROTLI=OFF to fall back to the previous behaviour of
# resolving the codecs at runtime via PR_LoadLibrary.
option(NSW_STATIC_BROTLI "Statically link brotli into the wrapper" ON)
if (NSW_STATIC_BROTLI)
    set(BROTLI_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../brotli")
    # Bundle brotli as static libraries only: no CLI tool, no tests and no
    # install rules (brotli switches to bundled mode automatically because
    # it is added via add_subdirectory, but be explicit about the rest).
    set(BUILD_SHARED_LIBS OFF)
    set(BROTLI_BUILD_TOOLS OFF)
    set(BROTLI_DISABLE_TESTS TRUE)
    add_subdirectory("${BROTLI_SRC_DIR}" brotli_build EXCLUDE_FROM_ALL)
    # Hide brotli's symbols in the shared wrapper so they cannot interpose
    # with (or be interposed by) a system libbrotli loaded into the process.
    if (NOT MSVC)
        foreach(_brotli_lib brotlicommon brotlidec brotlienc)
            target_compile_options(${_brotli_lib} PRIVATE -fvisibility=hidden)
        endforeach()
    endif()
endif()

# zstd: same approach — statically linked from the vendored sources in
# ../zstd so the wrapper has no runtime dependency on libzstd
# (libzstd.dll on Windows). Only the entry points the wrapper needs are
# exercised (ZSTD_compress/ZSTD_decompress/ZSTD_isError). Set
# -DNSW_STATIC_ZSTD=OFF to fall back to the previous behaviour of
# resolving the codec at runtime via PR_LoadLibrary.
option(NSW_STATIC_ZSTD "Statically link zstd into the wrapper" ON)
if (NSW_STATIC_ZSTD)
    set(ZSTD_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../zstd")
    # Static library only: no CLI, no tests, no contrib, and single-threaded
    # (the wrapper compresses/decompresses on the TLS thread only).
    # zstd's build requires cmake >= 3.10, so its option() calls run under
    # the OLD CMP0077 policy and would overwrite plain set() values from
    # this scope — everything therefore has to be forced into the cache.
    set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
    set(ZSTD_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(ZSTD_BUILD_CONTRIB OFF CACHE BOOL "" FORCE)
    set(ZSTD_BUILD_STATIC ON CACHE BOOL "" FORCE)
    set(ZSTD_BUILD_SHARED OFF CACHE BOOL "" FORCE)
    set(ZSTD_MULTITHREAD_SUPPORT OFF CACHE BOOL "" FORCE)
    # zstd.h hard-codes "default" visibility for its public API on GCC/
    # Clang; route everything through zstd's own visibility knobs so the
    # symbols end up hidden in the shared wrapper (see below).
    set(ZSTDLIB_VISIBLE hidden CACHE STRING "" FORCE)
    set(ZSTDERRORLIB_VISIBLE hidden CACHE STRING "" FORCE)
    set(ZDICTLIB_VISIBLE hidden CACHE STRING "" FORCE)
    set(ZSTDLIB_STATIC_API hidden CACHE STRING "" FORCE)
    set(ZDICTLIB_STATIC_API hidden CACHE STRING "" FORCE)
    add_subdirectory("${ZSTD_SRC_DIR}/build/cmake" zstd_build EXCLUDE_FROM_ALL)
    # Hide zstd's symbols in the shared wrapper so they cannot interpose
    # with (or be interposed by) a system libzstd loaded into the process.
    if (NOT MSVC)
        target_compile_options(libzstd_static PRIVATE -fvisibility=hidden)
    endif()
endif()

# NSS and NSPR: prefer pkg-config (libnss3-dev / libnspr4-dev install
# nss.pc and nspr.pc), fall back to plain header/library discovery, and
# allow explicit overrides for custom prefixes:
#   cmake -DNSS_INCLUDE_DIR=/opt/nss/include/nss -DNSS_LIBRARY_DIR=/opt/nss/lib ...
find_package(PkgConfig QUIET)
if (PkgConfig_FOUND)
    set(ENV{PKG_CONFIG_PATH} "${NSS_LIBRARY_DIR}/pkgconfig:$ENV{PKG_CONFIG_PATH}")
    pkg_check_modules(NSS QUIET nss)
    pkg_check_modules(NSPR QUIET nspr)
endif()

if (NOT NSS_FOUND OR NOT NSPR_FOUND)
    find_path(NSS_INCLUDE_DIR nss.h
        HINTS ${NSS_INCLUDE_DIR}
        PATH_SUFFIXES nss)
    find_path(NSPR_INCLUDE_DIR prinit.h
        HINTS ${NSPR_INCLUDE_DIR}
        PATH_SUFFIXES nspr)
    # NSS (Windows builds name import libraries "nss3.dll.lib", Linux
    # packages provide "libnss3.so" via the plain name).
    find_library(NSS3_LIBRARY NAMES nss3 nss3.dll.lib
        HINTS ${NSS_LIBRARY_DIR})
    find_library(NSSUTIL_LIBRARY NAMES nssutil3 nssutil3.dll.lib
        HINTS ${NSS_LIBRARY_DIR})
    find_library(SSL3_LIBRARY NAMES ssl3 ssl3.dll.lib
        HINTS ${NSS_LIBRARY_DIR})
    find_library(SMIME3_LIBRARY NAMES smime3 smime3.dll.lib
        HINTS ${NSS_LIBRARY_DIR})
    find_library(NSPR4_LIBRARY NAMES nspr4 nspr4.dll.lib
        HINTS ${NSPR_LIBRARY_DIR})
    find_library(PLC4_LIBRARY NAMES plc4 plc4.dll.lib
        HINTS ${NSPR_LIBRARY_DIR})
    find_library(PLDS4_LIBRARY NAMES plds4 plds4.dll.lib
        HINTS ${NSPR_LIBRARY_DIR})

    if (NOT NSS_INCLUDE_DIR OR NOT NSPR_INCLUDE_DIR OR
        NOT NSS3_LIBRARY OR NOT SSL3_LIBRARY OR NOT NSPR4_LIBRARY)
        message(FATAL_ERROR
            "NSS/NSPR development files were not found. "
            "Install libnss3-dev and libnspr4-dev, or pass "
            "-DNSS_INCLUDE_DIR=... -DNSS_LIBRARY_DIR=... -DNSPR_INCLUDE_DIR=... -DNSPR_LIBRARY_DIR=...")
    endif()

    set(NSS_INCLUDE_DIRS "${NSS_INCLUDE_DIR};${NSPR_INCLUDE_DIR}")
    set(NSS_LIBRARIES
        "${NSS3_LIBRARY};${NSSUTIL_LIBRARY};${SSL3_LIBRARY};${SMIME3_LIBRARY};${NSPR4_LIBRARY};${PLC4_LIBRARY};${PLDS4_LIBRARY}")
endif()

add_library(proxymap_nss SHARED nss_wrapper.c)

# MSVC produces proxymap_nss.dll, but MinGW-based toolchains prefix shared
# libraries with "lib" (libproxymap_nss.dll). Strip the prefix so the DLL
# name always matches the P/Invoke name on Windows.
if(WIN32)
    set_target_properties(proxymap_nss PROPERTIES PREFIX "")
endif()

target_include_directories(proxymap_nss PRIVATE
    "${ZLIB_SRC_DIR}"
    ${NSS_INCLUDE_DIRS})

target_link_libraries(proxymap_nss PRIVATE ${NSS_LIBRARIES} zlib_static)

if (NSW_STATIC_BROTLI)
    target_compile_definitions(proxymap_nss PRIVATE NSW_BROTLI_STATIC=1)
    target_include_directories(proxymap_nss PRIVATE
        "${BROTLI_SRC_DIR}/c/include")
    # brotlienc/brotlidec pull in brotlicommon (and libm where needed).
    target_link_libraries(proxymap_nss PRIVATE brotlienc brotlidec)
endif()

if (NSW_STATIC_ZSTD)
    target_compile_definitions(proxymap_nss PRIVATE NSW_ZSTD_STATIC=1)
    target_include_directories(proxymap_nss PRIVATE "${ZSTD_SRC_DIR}/lib")
    target_link_libraries(proxymap_nss PRIVATE libzstd_static)
endif()

target_compile_features(proxymap_nss PRIVATE c_std_11)

if (MSVC)
    # strdup() and friends are flagged as deprecated by the MSVC CRT.
    target_compile_definitions(proxymap_nss PRIVATE
        _CRT_SECURE_NO_WARNINGS
        _CRT_NONSTDC_NO_WARNINGS)
    target_compile_options(proxymap_nss PRIVATE /W4)
else()
    target_compile_options(proxymap_nss PRIVATE -Wall -Wextra)
endif()
