# Implementation and Evaluation of the Smartphone Prototype

This directory contains the implementation of the smart-phone prototype described in the paper. We describe how to build the smartphone prototype and evaluate the end-to-end implementation of the protocol on the prototype.

To implement the prototype, we need to choose a phone to build an app for the protocol, then we can run measurements using this app. Notice that the app we developed in this repository is in Rust using the [blst](https://github.com/supranational/blst) library via the bindings [blstrs](https://docs.rs/blstrs/latest/blstrs/) to compute points arithmetics and pairing on curve BLS12-381.

## A. Prerequisites

### Hardware

We choose an Android phone with USB debugging enabled. For reproducing the numbers in the paper, use the following model:
- Samsung Galaxy A40 with Android 11 (kernel 4.4.177-24085844)

To enable debugging mode, switch on the Android phone, connect it to your PC with a USB cable, go to Settings->Developer options->enable USB Debugging.

### Software

We choose to write the app in Rust. To develop the app and build it on the phone, we need to install:
- a Rust development environment,
- the Dinghy cargo extension to simplify the cross-compilation workflow.
- compilation toolchains for the targeted Android phone,
- Android Sdk tools, and more specifically Android Debug Bridge (adb)

First, you will need to setup a Rust development environment by running:

```
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Then you will need to install the toolchains to compile the Rust code for the architecture of the phone. In our case we run:

```
$ rustup target add aarch64-linux-android
```

*Note:* If you choose a phone with a different architecture, you will need to install a different target, for example:
```
$ rustup target add armv7-linux-androideabi # for ARM 32 bits phones
$ rustup target add i686-linux-android      # for Intel 32 bits phones
$ rustup target add x86_64-linux-android    # for Intel 64 bits phones
```

We used the Dinghy cargo extension to handle the cross-compilation workflow, which you will also need to install:

```
$ cargo install cargo-dinghy
```

To communicate with the phone, Dinghy will rely on the tool *adb*, which is part of the Android Sdk Tools. You can download them from [Android website](https://developer.android.com/tools/releases/platform-tools) and install them on your machine by following their documentation. Also, we recommend to have a look at [adb's documentation](https://developer.android.com/tools/adb) to know how to pair an Android device with this tool.

To be able to compile the code for Android, you will also need an NDK, we used the LTS release r25c without encountering any problems.
You can do so by downloading an archive from [its download page](https://github.com/android/ndk/wiki) and unzip it in a directory on your system.

Once the NDK extracted, you will need to set an environment variable to indicate to Dinghy where the NDK is located:

```
export ANDROID_NDK_HOME="/path/to/extracted/NDK/archive"
```

## B. Building and testing the App

After setting up, you can run the following commands to test that everything works.

First pair your phone with adb following [its documentation](https://developer.android.com/tools/adb).

The identify your phone device with adb:
```
$ adb devices
List of devices attached
R58M89083YW	device
```

Here we see that our device is called `R58M89083YW`, and we will use this identifier in the rest of this readme.

**Note:** You might get the response similar to `R58M89083YW	unauthorized`, this is generally when the device is not paired correctly with adb.

At this point you can run the tests with this command, which should produce a similar output (with some extra build info if you compile the project for the first time):

```
$ cargo dinghy -d R58M89083YW test
   Targeting platform auto-android-aarch64 and device R58M89083YW
    Finished test [unoptimized + debuginfo] target(s) in 0.10s
     Running unittests src/lib.rs (target/aarch64-linux-android/debug/deps/pribad_crypto-868b3b664e4d853f)
  Installing pribad_crypto-868b3b664e4d853f to R58M89083YW
     Running pribad_crypto-868b3b664e4d853f on R58M89083YW

running 5 tests
test pointcheval_sanders::tests::generated_keys_are_valid ... ok
test pointcheval_sanders::tests::sign_commitent ... ok
test smartphone::tests::non_revocation_should_fails_if_blocklists_mismatch ... ok
test pointcheval_sanders::tests::verify_disclosure_proof ... ok
test smartphone::tests::full_circuit ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.26s

FORWARD_RESULT_TO_DINGHY_BECAUSE_ADB_DOES_NOT=0
```

The above output indicates that all the tests have passed, therefore, we can continue by running the benchmark.

## C. Running the benchmark

Before starting the benchmark, feel free to tweak the `MEASUREMENT_TIME_S` constant in the file `benches/benchmarks.rs` to modify the measurement time in seconds for the benchmarks (by default: 5 s).

Then you can run the benchmark with the following command, and the library `criterion` that we used to write the benchmarks will take care to report the statistics it computed from its measurements:

```
$ cargo dinghy -d R58M89083YW bench
   Targeting platform auto-android-aarch64 and device R58M89083YW
   Compiling pribad_crypto v0.1.0 (/home/laurent/src/not-yet-another-id-code/smartphone)
    Finished bench [optimized] target(s) in 3.80s
     Running unittests src/lib.rs (target/aarch64-linux-android/release/deps/pribad_crypto-875eb49ae483e5bf)
  Installing pribad_crypto-875eb49ae483e5bf to R58M89083YW
     Running pribad_crypto-875eb49ae483e5bf on R58M89083YW

running 5 tests
test pointcheval_sanders::tests::generated_keys_are_valid ... ignored
test pointcheval_sanders::tests::sign_commitent ... ignored
test pointcheval_sanders::tests::verify_disclosure_proof ... ignored
test smartphone::tests::full_circuit ... ignored
test smartphone::tests::non_revocation_should_fails_if_blocklists_mismatch ... ignored

test result: ok. 0 passed; 0 failed; 5 ignored; 0 measured; 0 filtered out; finished in 0.00s

FORWARD_RESULT_TO_DINGHY_BECAUSE_ADB_DOES_NOT=0
     Running benches/benchmark.rs (target/aarch64-linux-android/release/deps/benchmark-1231eb975692ed1d)
  Installing benchmark-1231eb975692ed1d to R58M89083YW
     Running benchmark-1231eb975692ed1d on R58M89083YW
pedersen_1_generate_parameters
                        time:   [329.05 µs 329.09 µs 329.14 µs]
                        change: [-1.0810% -0.9828% -0.8938%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 11 outliers among 1000 measurements (1.10%)
  4 (0.40%) high mild
  7 (0.70%) high severe

pedersen_2_compute_commitment
                        time:   [1.2416 ms 1.2417 ms 1.2419 ms]
                        change: [-0.3386% -0.2484% -0.1846%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 17 outliers among 1000 measurements (1.70%)
  7 (0.70%) high mild
  10 (1.00%) high severe

pedersen_3_validate_commitment
                        time:   [1.2426 ms 1.2428 ms 1.2429 ms]
                        change: [-0.2608% -0.2421% -0.2222%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 16 outliers among 1000 measurements (1.60%)
  7 (0.70%) high mild
  9 (0.90%) high severe

...

smartphone_3b_verify_non_revocation_proof/blocklist_size/65536
                        time:   [4.4644 s 4.4713 s 4.4787 s]
                        change: [-0.2147% +0.0108% +0.2373%] (p = 0.93 > 0.05)
                        No change in performance detected.

FORWARD_RESULT_TO_DINGHY_BECAUSE_ADB_DOES_NOT=0
Benchmarking pedersen_1_generate_parameters
Benchmarking pedersen_1_generate_parameters: Warming up for 3.0000 s
Benchmarking pedersen_1_generate_parameters: Collecting 1000 samples in estimated 5.3048 s (16k iterations)
Benchmarking pedersen_1_generate_parameters: Analyzing
Benchmarking pedersen_2_compute_commitment
Benchmarking pedersen_2_compute_commitment: Warming up for 3.0000 s
Benchmarking pedersen_2_compute_commitment: Collecting 1000 samples in estimated 5.0076 s (4000 iterations)
Benchmarking pedersen_2_compute_commitment: Analyzing
Benchmarking pedersen_3_validate_commitment
Benchmarking pedersen_3_validate_commitment: Warming up for 3.0000 s
Benchmarking pedersen_3_validate_commitment: Collecting 1000 samples in estimated 5.0148 s (4000 iterations)
Benchmarking pedersen_3_validate_commitment: Analyzing
Benchmarking pointchevalsanders_1_generate_key_pair
Benchmarking pointchevalsanders_1_generate_key_pair: Warming up for 3.0000 s

Warning: Unable to complete 1000 samples in 5.0s. You may wish to increase target time to 9.2s, or reduce sample count to 540.
Benchmarking pointchevalsanders_1_generate_key_pair: Collecting 1000 samples in estimated 9.2017 s (1000 iterations)
Benchmarking pointchevalsanders_1_generate_key_pair: Analyzing

...
```


