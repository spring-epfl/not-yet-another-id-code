# Not Yet Another ID Code

## Overview

This repository contains the artifact submitted for the paper *Not Yet Another Digital ID: Privacy-preserving Humanitarian Aid Distribution*.

We provide an implementation for the smartcard solution described in the section 4 of the paper, an implementation for the smartphone solution described in the section 5 of the paper, as well as a benchmark for each operations both on smartphone and smartcard.

## Smartcard Implementation

We wrote our implementation with Oracle JavaCard 3.0.4 and we tested it on a Debian 11 "Bullseye" Linux system with a card NXP JCOP3 J3H145 and a reader uTrust 4701 F.
To build the applet and redo our measurements, you also will need a Java Development Environment for Java 11 (we used OpenJDK 11), the tool GlobalPlatformPro, and Python 3 version 3.9.2 or later (it might also work with earlier version of Python, but we have not tested).

### Implementation Details

While the JavaCard API offers a reasonable range of cryptographic functions, it does not offer support nor for large integer operations nor for basic point operations on elliptic curves. In particular, it does not offer a way to do point multiplication with the cryptographic co-processor, hence, it is not possible to compute a commitment in an efficient manner. To work around this problem, instead of computing a traditional commitment:

$$ C = H^m G^r $$

where $H$ and $G$ are points on the elliptic curve, we tweak $H$ by defining it such as:

$$ H = G^v $$

Which simplifies the computation of the commitment as:

$$ C = G^{mv} G ^r = G^{mv + r} $$

Then we used JCMathlib to compute the remaining large integers operations. Also because the multiplication is much more costly in term of computation than addition, we pre-compute the computation of $mv$ when we are setting the household entitlement $m$. This allow to improve the performance of commitment computation, by offloading the multiplication cost.

### Material

For this project we used:
- a card NXP JCOP3 J3H145
- a reader uTrust 4701 F

Using an other card model implementing JavaCard 3.0.4 API, and supporting extended APDU and T=1 communication protocol *should* work, but that will depends on the Javacard subset it implements.

### Building and Running the Applet

#### Prerequisites

To build the JavaCard applet, you will need
- a Java Development Environment installed to compile the Java 11 code
- Oracle JavaCard SDK
- Ant to build the applet
- GlobalPlatformPro to install the applet on the physical card and send it the APDUs
- Python3 to run the scripts to generate the data to send to the card by calling GlobalPlatformPro
- A compilation suite, as well as OpenSSL and its development files to build Python dependencies

You will need to install a Java Development Environment, Ant, Python3, and OpenSSL on your system.
For a Debian 11 system, you can install them using the package repositories of the distribution:

```
apt-get install ant openjdk-11-jdk libssl-dev python3 python3-dev python3-pip python3-venv
```

To build the applet, you need to have Oracle JavaCard SDK binaries for JavaCard version 3.0.4, which you can retrieve (among other SDKs) by retrieving the git submodules of this repo. If you cloned this repo with the option `--recurse-submodules `, such as:

```
git clone --recurse-submodules https://github.com/spring-epfl/not-yet-another-id-code.git
```

Then, you already retrieve the SDKs, otherwise, you will need to retrieve them with:

```
git submodule update --init
```

Inside the directory in which you cloned this git repository.

You can retrieve the latest release of GlobalPlatformPro from [their GitHub](https://github.com/martinpaljak/GlobalPlatformPro) and set an environment variable `GP` to hold the command which will be called to execute the JAR.

```
export GP="java -jar /path/to/gp.jar"
```

This `GP` environment variable will be used by Python scripts to call the tool.

Finally you will need to setup a Python virtual environment and install scripts dependencies in this virtual environment.

```
python3 -m venv venv
. venv/bin/activate
pip install smartcard/python/requirements.txt
```

And change your working directory to the `smartcard` directory at the root of this git repository.
```
cd smartcard
```


#### Building the Applet

Once your development environment is set up, you can build the applet with the command.

```
./gradlew buildJavaCard
```

Ensure that the card reader is connected to the machine, and that a card is inserted in the reader.

If you already have a previous installation of the applet on the card, you can uninstall it with:
```
$GP --uninstall ./applet/build/javacard/protocol.cap
```

Then install the last build on the card:
```
$GP --install ./applet/build/javacard/protocol.cap
```

At this point, you should be able to send commands to the applet installed on the card.

#### Testing the Applet

To ensure that the applet is indeed computing correctly the tags, commitment and other cryptographic objects described in the protocol, we can run the script `prototype.py` which will generate some data to send to the card, and do the same computations using the libraries PyCryptodome, cryptography, and petlib and output both the output from GlobalPlatformPro and the expected result. Then we check manually that the outputs are identical.

Before running these script, ensure that you activated the python virtual environment and that you are in the correct working directory:
```
. venv/bin/activate
cd smartcard
```

And ensure you are in the `python` directory to run these scripts.
```
cd python
```

We can check most of the computations with a single run:

```
python prototype.py
```

Because this script does not parse the output from GlobalPlatformPro, you will need to call this script two other times to verify the commitment, and to verify the signature.
The initial run of the script provides you the command that you will have to complete before running.

The first of these commands is:
```
python prototype.py verify-commitment <g> <z> <m> <R+COMMITMENT>
```

Where `<R+COMMITMENT>` should be replaced by the data returned by GlobalPlatformPro when running the APDU to compute the *show off proof* phase of the protocol, and the other arguments should already be provided.

And the second of these commands is:
```
python prototype.py verify-signature <pk> <tag> <period> <blocklist_hash> <R+COMMITMENT> <SIGNATURE>
```

Where `<R+COMMITMENT>` is the same as for the previous command, and where `<SIGNATURE>` should be replaced by the data returned by GlobalPlatformPro when running the APDU to compute the signature in the *sending proof* phase of the protocol, and the other arguments should already be provided.


#### Running the Benchmarks

We are benchmarking:
- the transfer speed,
- the time it takes to compute the tag from the period and household secret, and
- the time it takes to hash blocklists of different sizes.

Which are respectively measured by the scripts:
- `benchmark_blocklist.py`,
- `benchmark_tags.py`, and
- `benchmark_transfer.py`.

And the measurements are manually retrieved from GlobalPlatformPro output.

## Smartphone Implementation

The implementation is written for Android 11 (NDK 22.1.7171670) and was tested on a phone Samsung Galaxy A40 with Android 11 (kernel 4.4.177-24085844).

It is written in Rust and use the [blst](https://github.com/supranational/blst) library via the bindings [blstrs](https://docs.rs/blstrs/latest/blstrs/) to compute points arithmetics and pairing on curve BLS12-381.

### Building and Running the App

#### Prerequisites

You will need an Android phone with USB debugging enabled.

To build the app and run the benchmarks, you will need a Rust development environment, then install compilation toolchains for the targeted Android phone, and the Dinghy cargo extension to simplify the cross-compilation workflow.

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
cargo install cargo-dinghy
```

To be able to compile the code for Android, you will also need an NDK, we used the version 22.1.7171670. The easiest way is to install it via Android Studio but it can also be downloaded manually from [its download page](https://github.com/android/ndk/wiki/Unsupported-Downloads).

Once the NDK installed, you will need to set an environment variable to indicate to Dinghy where the NDK is installed.

```
export ANDROID_NDK_HOME="/path/to/extracted/NDK/archive"
```

To communicate with the phone, you will also need to have `adb` installed. As for teh NDK, the easiest way is to install it from Android Studio, but it can also be installed manually ([link](https://developer.android.com/studio/releases/platform-tools)).


#### Building the App and Running the Benchmarks

Once the prerequisite software installed and the environment variable `ANDROID_NDK_HOME` is set to the path of extracted NDK archive, the benchmark can be run with cargo, and the library `criterion` that we used to write the benchmarks will take care to report the statistics it computed from its measurements.

```
cargo dinghy -d android bench
```

## Contributors

The Android implementation was written by Nathan Duchenese, Laurent Girod, Boya Wang, and Wouter Lueks.

The JavaCard implementation was written by Lorenzo Rovati, Laurent Girod, Boya Wang, and Wouter Lueks, and uses code from [JCMathlib](https://github.com/OpenCryptoProject/JCMathLib), as well as a template written by Dusan Klinec, Martin Paljak, and Petr Svenda which can be found at this [link](https://github.com/ph4r05/javacard-gradle-template).

