#! /usr/bin/env bash

if [[ "z${ANDROID_NDK_HOME}" == "z" ]]
then
    echo "ERROR: Environment variable 'ANDROID_NDK_HOME' is undefined!" >&2
    exit 1
fi

if [[ "z${PROJECT_ROOT_DIR}" == "z" ]]
then
    echo "ERROR: Environment variable 'PROJECT_ROOT_DIR' is undefined!" >&2
    exit 1
fi

if [[ "z${ANDROID_PLATFORM}" == "z" ]]
then
    echo "ERROR: Environment variable 'ANDROID_API' is undefined!" >&2
    exit 1
fi


GMP_VERSION="6.2.1"
MCL_VERSION="1.62"

GMP_ARCHIVE_SHA512='c99be0950a1d05a0297d65641dd35b75b74466f7bf03c9e8a99895a3b2f9a0856cd17887738fa51cf7499781b65c049769271cbcb77d057d2e9f1ec52e07dd84'
MCL_ARCHIVE_SHA512='943b53684e1773cb07f10ec6661293e87a9fcff2d153e441899034daea560bb786f51a9bf5c711b38b9f4c9f5d406f34c625ff9042516d5480942ea31f4362c3'

CWD="${PWD}"
PREFIX_BASE="${PROJECT_ROOT_DIR}/app/src/main/jniLibs"

ANDROID_ABIS=("armeabi-v7a" "arm64-v8a" "x86")
ARCH_TRIPLES=("armv7a-linux-androideabi" "aarch64-linux-android" "i686-linux-android")
BINUTILS_TRIPLES=("arm-linux-androideabi" "aarch64-linux-android" "i686-linux-android")
CARGO_TRIPLES=("armv7-linux-androideabi" "aarch64-linux-android" "i686-linux-android")
ABIS_BITS=(32 64 32)

# Build GMP

cd /tmp || exit 3

if [[ ! -f "gmp-${GMP_VERSION}.tar.xz" ]]
then
    echo "Download GMP ${GMP_VERSION} archive." >&2
    curl -sSL -o "gmp-${GMP_VERSION}.tar.xz" "https://gmplib.org/download/gmp/gmp-${GMP_VERSION}.tar.xz"
fi

if ! echo "${GMP_ARCHIVE_SHA512}  gmp-${GMP_VERSION}.tar.xz" | sha512sum --check --status
then
    rm "gmp-${GMP_VERSION}.tar.xz"
    echo "ERROR: checksum for GMP archive failed!" >&2
    exit 2
fi

echo "Extract GMP ${GMP_VERSION} archive." >&2

if [[ -e "gmp-${GMP_VERSION}" ]]
then
    rm -r "gmp-${GMP_VERSION}"
fi

tar xf "gmp-${GMP_VERSION}.tar.xz"

cd "gmp-${GMP_VERSION}" || exit 3

GMP_INSTALL_TEMP="/tmp/gmp-install"

TOOLCHAIN="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64"
export AR="${TOOLCHAIN}/bin/llvm-ar"
export LD="${TOOLCHAIN}/bin/ld"
export RANLIB="${TOOLCHAIN}/bin/llvm-ranlib"
export STRIP="${TOOLCHAIN}/bin/llvm-strip"

for i in "${!ANDROID_ABIS[@]}"
do
    PREFIX="${GMP_INSTALL_TEMP}/${ANDROID_ABIS[$i]}"
    mkdir -p "${PREFIX}"

    if [[ ! -f "${PREFIX_BASE}/${ANDROID_ABIS[$i]}/libgmp.so" || ! -f "${PREFIX_BASE}/${ANDROID_ABIS[$i]}/libgmpxx.so" ]]
    then
        echo "Compile GMP ${GMP_VERSION} for ${ARCH_TRIPLES[$i]}." >&2
        export CC="${TOOLCHAIN}/bin/${ARCH_TRIPLES[$i]}${ANDROID_PLATFORM}-clang"
        export CXX="${TOOLCHAIN}/bin/${ARCH_TRIPLES[$i]}${ANDROID_PLATFORM}-clang++"
        export AS="${CC}"
        export ABI="${ABIS_BITS[$i]}"
        export TARGET="${ARCH_TRIPLES[$i]}"

        if [[ -f Makefile ]]
        then
            make clean
            make distclean
        fi

        ./configure --prefix="${PREFIX}" --build=x86_64-pc-linux-gnu --host="${BINUTILS_TRIPLES[$i]}" --enable-cxx
        make || exit 4

        echo "Install GMP ${GMP_VERSION} for ${ARCH_TRIPLES[$i]}." >&2
        make install
        mkdir -p "${PREFIX_BASE}/${ANDROID_ABIS[$i]}"
        cp "${PREFIX}/lib/libgmp.so" "${PREFIX_BASE}/${ANDROID_ABIS[$i]}/"
        cp "${PREFIX}/lib/libgmpxx.so" "${PREFIX_BASE}/${ANDROID_ABIS[$i]}/"
    fi
done

unset CC
unset CXX
unset AS
unset ABI
unset AR
unset LD
unset RANLIB
unset STRIP
unset CFLAGS
unset TARGET

# Build mcl

cd /tmp || exit 2


if [[ ! -f "mcl-${MCL_VERSION}.tar.gz" ]]
then
    echo "Download MCL ${MCL_VERSION} archive." >&2
    curl -sSL -o "mcl-${MCL_VERSION}.tar.gz" "https://github.com/herumi/mcl/archive/refs/tags/v${MCL_VERSION}.tar.gz"
fi

if ! echo "${MCL_ARCHIVE_SHA512}  mcl-${MCL_VERSION}.tar.gz" | sha512sum --check --status
then
    rm "mcl-${MCL_VERSION}.tar.gz"
    echo "ERROR: checksum for MCL archive failed!" >&2
    exit 2
fi

echo "Extract MCL ${MCL_VERSION} archive." >&2
tar xf "mcl-${MCL_VERSION}.tar.gz"

MCL_INSTALL_TEMP="/tmp/mcl-install"
mkdir -p "${MCL_INSTALL_TEMP}"

for i in "${!ANDROID_ABIS[@]}"
do
    PREFIX="${MCL_INSTALL_TEMP}/${ANDROID_ABIS[$i]}"
    mkdir -p "${PREFIX}"

    if [[ ! -f "${PREFIX_BASE}/${ANDROID_ABIS[$i]}/libmcl.so" ]]
    then
        echo "Compile MCL ${MCL_VERSION} for ${ARCH_TRIPLES[$i]}." >&2

        PREFIX_GMP="${GMP_INSTALL_TEMP}/${ANDROID_ABIS[$i]}"

        if [[ -e '/tmp/mcl-build' ]]
        then
            rm -r '/tmp/mcl-build'
        fi

        mkdir -p '/tmp/mcl-build'
        cd '/tmp/mcl-build' || exit 3

        cmake \
            -DGMP_INCLUDE_DIR="${PREFIX_GMP}/include" -DGMP_LIBRARY="${PREFIX_BASE}/${ANDROID_ABIS[$i]}/libgmp.so" \
            -DGMP_GMPXX_INCLUDE_DIR="${PREFIX_GMP}/include" -DGMP_GMPXX_LIBRARY="${PREFIX_BASE}/${ANDROID_ABIS[$i]}/libgmpxx.so" \
            -DMCL_USE_GMP=ON -DMCL_STATIC_LIB=ON -DMCL_USE_ASM=OFF \
            -DCMAKE_TOOLCHAIN_FILE="${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake" \
            -DANDROID_ABI="${ANDROID_ABIS[$i]}" \
            -DCMAKE_INSTALL_PREFIX="${PREFIX}" \
            "/tmp/mcl-${MCL_VERSION}"

        make VERBOSE=ON || exit 4

        echo "Install MCL ${MCL_VERSION} for ${ARCH_TRIPLES[$i]}." >&2
        make install

        cp "${PREFIX}/lib/libmcl.so" "${PREFIX_BASE}/${ANDROID_ABIS[$i]}/"

        cd /tmp || exit 3
        rm -rf '/tmp/mcl-build'
    fi
done


# Build Rust library

cd "${PROJECT_ROOT_DIR}/app/rcads_crypto" || exit 3

LIB_INSTALL_TEMP="/tmp/lib-install"
mkdir -p "${LIB_INSTALL_TEMP}"

export ANDROID_USE_LEGACY_TOOLCHAIN_FILE=ON

for i in "${!ANDROID_ABIS[@]}"
do
    PREFIX="${PWD}/target/${CARGO_TRIPLES[$i]}/release"

    if [[ ! -f "${PREFIX_BASE}/${ANDROID_ABIS[$i]}/librcads_crypto.so" ]]
    then
        PREFIX_GMP="${GMP_INSTALL_TEMP}/${ANDROID_ABIS[$i]}"
        PREFIX_MCL="${MCL_INSTALL_TEMP}/${ANDROID_ABIS[$i]}"

        echo "Compile librcads_crypto for ${ARCH_TRIPLES[$i]}." >&2

        export RUSTFLAGS="-L ${PREFIX_GMP}/lib -L ${PREFIX_MCL}/lib -l mcl -l gmp -l gmpxx"

        cargo ndk -t "${ANDROID_ABIS[$i]}" build --release || exit 4

        cp "${PREFIX}/librcads_crypto.so" "${PREFIX_BASE}/${ANDROID_ABIS[$i]}/"
    fi
done

cd "${CWD}" || exit 0
