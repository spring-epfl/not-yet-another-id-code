# Implementation and Evaluation of the Smartphone Prototype

In this directory, we explain how to implement a smartphone prototype and evaluate the end-to-end implementation of the protocol on the prototype. 

To implement the prototype, we need to choose a phone to build an app for the protocol, then we can run measurements using this app. Notice that the code we developed in this repository is in Rust using the [blst](https://github.com/supranational/blst) library via the bindings [blstrs](https://docs.rs/blstrs/latest/blstrs/) to compute points arithmetics and pairing on curve BLS12-381.

### A. Prerequisites

#### Hardware

We choose an Android phone with USB debugging enabled. For reproducing the numbers in the paper, use the following model: 
- Samsung Galaxy A40 with Android 11 (kernel 4.4.177-24085844) 

#### Software 

We choose to write the app in Rust. To develop the app and build it on the phone, we need to install: 
- a Rust development environment, 
- compilation toolchains for the targeted Android phone, 
- the Dinghy cargo extension to simplify the cross-compilation workflow. 

The above can be installed by running: 

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
cargo install cargo-dinghy
```

To be able to compile the code for Android, we need an NDK, in our code we used:
- Android 11 NDK 22.1.7171670

The easiest way is to install this NDK via Android Studio. It can also be downloaded manually from [its download page](https://github.com/android/ndk/wiki/Unsupported-Downloads).

Once the NDK installed, we need to set an environment variable to indicate to Dinghy where the NDK is installed:

```
export ANDROID_NDK_HOME="/path/to/extracted/NDK/archive"
```

Finally, to communicate with the phone, we also need to have `adb` installed. Similarly, the easiest way is to install it from Android Studio. It can also be installed manually ([link](https://developer.android.com/studio/releases/platform-tools)).


### B. Building the App and Running the Benchmarks

Once we set up the hardware and software as indicated in A, the benchmark can be run with cargo, and the library `criterion` that we used to write the benchmarks will take care to report the statistics it computed from its measurements:

```
cargo dinghy -d android bench
```


