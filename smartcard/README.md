# Implementation and Evaluation of the Smart-card Prototype

We first describe how to implement a prototype of the smart-card-based solution in the paper, then provide instructions on how to reproduce the measurements on this implementation. We also explain some implementation details that can be helpful to understand the code. 

## A. Implementation of the Smart-card Prototype

To implement the prototype, we need to choose a card and a card reader that contains the necessary library. 
We then build an Applet in the card to run the protocol as described in our paper. 
Using the built Applet, we can run measurements to benchmark the computational cost of the prototype. 

### A.1 Prerequisites

#### Hardware

We implemented a prototype of the smart-card-based solution using the following materials: 

- a card NXP JCOP3 J3H145
- a card reader uTrust 4701 F


Theoretically, using any card model implementing JavaCard 3.0.4 API, supporting extended APDU and T=1 communication protocol *should* work.  However, there is no promise because some card models may not support the set of Javacard functionality required in this implementation.


#### Software

To build and run the protocol applet on the card, we use: 
1. `OpenJDK 11`, a Java Development Environment to compile the Java 11 code
2. `Oracle JavaCard SDK`, for calling the JavaCard libraries
3. `Ant`, for building the applet of our protocol 
4. `GlobalPlatformPro`, for installing the applet on the physical card and send commands (i.e., APDUs)
5. `Python3` version 3.9.2 or later, for running the scripts to generate the data to send to the card by calling `GlobalPlatformPro`
6. A compilation suite, as well as OpenSSL and its development files to build Python dependencies

For a Debian 11 system, 1, 3, 5, and 6 of the above dependencies can be installed using package repositories of the distribution using the command: 

```
apt-get install ant openjdk-11-jdk libssl-dev python3 python3-dev python3-pip python3-venv
```

To get 2, you can run the git clone command with the option `--recurse-submodules`: 

```
git clone --recurse-submodules https://github.com/spring-epfl/not-yet-another-id-code.git
```

If you do not run the git clone command with the option `--recurse-submodules`, use the following command to retrieve the SDKs: 

```
git submodule update --init
```

To get 4, first, go inside the directory where you cloned this repository, then retrieve the latest release of `GlobalPlatformPro` from [their GitHub](https://github.com/martinpaljak/GlobalPlatformPro) and set an environment variable `GP` to hold the command which will be called to execute the JAR by running:

```
export GP="java -jar /path/to/gp.jar"
```

This `GP` environment variable will be used by Python scripts to call the tool.

We finalize the preparation by setting up a Python virtual environment and install scripts dependencies in this virtual environment using the following commands:

```
python3 -m venv venv
. venv/bin/activate
pip install smartcard/python/requirements.txt
```

Do not forget to change your working directory to the `smartcard` directory at the root of this git repository: 
```
cd smartcard
```



### A.2 Building the Applet 

Once finishing the preparations in A.1, can build the applet. Before running the building command, make sure the card reader is connected to the machine, and the card is inserted in the reader. Then we can run: 

```
./gradlew buildJavaCard
```

### A.3 Installing the Applet

After building the applet as A.2 shows, we need to install the applet on the card before sending any commands to the applet. 

If there is already a previous installation of the applet on the card, we first uninstall it with:
```
$GP --uninstall ./applet/build/javacard/protocol.cap
```

To install the last build on the card, use: 
```
$GP --install ./applet/build/javacard/protocol.cap
```

#### A.4 Testing the Applet

To ensure that the applet is indeed computing correctly the tags, commitment and other cryptographic objects described in the protocol, we can: 
1. run the script `prototype.py` which will generate some data to send to the card,
2. do the same computations using the libraries PyCryptodome, cryptography, and petlib
3. compare both the output from GlobalPlatformPro and the expected result from the script `prototype.py`

If the outputs are identical, it means the cryptographic objects are computed correctly on the card. 

To get the output from the script `prototype.py`, we first activate the python virtual environment, go into the correct working directory, and ensure we are in the `python` directory to run these scripts: 
```
. venv/bin/activate
cd smartcard
cd python
```

We can then check most of the computations with a single run:

```
python prototype.py
```

The left checks are on the computation of the commitment and the signature. 
Using the output from the previous command, we verify the commitment by:
```
python prototype.py verify-commitment <g> <z> <m> <R+COMMITMENT>
```

Where `<R+COMMITMENT>` is the data returned by GlobalPlatformPro when running the APDU to compute the *show off proof* phase of the protocol, and the other arguments should already be provided.

To verify the signature, run:
```
python prototype.py verify-signature <pk> <tag> <period> <blocklist_hash> <R+COMMITMENT> <SIGNATURE>
```

Where `<R+COMMITMENT>` is the same as for the previous command, and where `<SIGNATURE>` is the data returned by GlobalPlatformPro when running the APDU to compute the signature in the *sending proof* phase of the protocol, and the other arguments should already be provided.




## B. Evaluation of the Smart-card Prototype

Using the implemented prototype, we could benchmark the following operations to evaluate the performance:

- the transfer speed, using the script `benchmark_blocklist.py`, 
- the time it takes to compute the tag given the period and household secret, using the script `benchmark_tags.py`, 
- the time it takes to hash blocklists of different sizes, using the script `benchmark_transfer.py`.

The results can be retrieved from the GlobalPlatformPro output.





#### C. Implementation Details

We explain one interesting tweak we used to implement cryptographic functions using limited support of the JavaCard API on the chosen card model. 

While the JavaCard API offers a reasonable range of cryptographic functions, it does not offer support nor for large integer operations nor for basic point operations on elliptic curves. In particular, it does not offer a way to do point multiplication with the cryptographic co-processor, hence, it is not possible to compute a commitment in an efficient manner. To work around this problem, instead of computing a traditional commitment:

$$ C = H^m G^r $$

where $H$ and $G$ are points on the elliptic curve, we tweak $H$ by defining it such as:

$$ H = G^v $$

Which simplifies the computation of the commitment as:

$$ C = G^{mv} G ^r = G^{mv + r} $$

Then we used JCMathlib to compute the remaining large integers operations. Also because the multiplication is much more costly in term of computation than addition, we pre-compute the computation of $mv$ when we are setting the household entitlement $m$. This allow to improve the performance of commitment computation, by offloading the multiplication cost.


### D. Acknowledgement 
This implementation uses code from [JCMathlib](https://github.com/OpenCryptoProject/JCMathLib), as well as a template written by Dusan Klinec, Martin Paljak, and Petr Svenda which can be found at this [link](https://github.com/ph4r05/javacard-gradle-template).
