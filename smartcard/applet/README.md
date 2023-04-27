# `applet` directory

This directory contains source code of the various applets, and the corresponding unit tests.

## Applets

### `basic`

`SimpleApplet` implements very basic functionalities to test cap installation on physical cards and communication with physical cards.

### `jcmathlib`

`ECExample` is the example applet from [JCMathLib](https://github.com/OpenCryptoProject/JCMathLib). Also used for debugging jcml operations.

### `protocol`

`ProtocolApplet` implements pedersen commitment scheme (using [JCMathLib](https://github.com/OpenCryptoProject/JCMathLib)) and message signing (using `javacard.security`) to be used for aid requests.

### `protocoljcml`

`ProtocolApplet` implements pedersen commitment scheme and message signing (both using [JCMathLib](https://github.com/OpenCryptoProject/JCMathLib)) to be used for aid requests. NOTE: development halted, it does not reflect the correct protocol.

### `bench`

`BenchApplet` implements commands to benchmark various card operations, such as transfer speed and key gen.

### `debug`

Playground to test support of functionalities on physical cards

## Tests

The unit tests are based on a base test class included in the [javacard gradle template](https://github.com/crocs-muni/javacard-gradle-template-edu) and adapted to our use case. The class is then extended by the various files testing the different applets.