# Implementation and Evaluation of the Smart-card Prototype

This directory contains the implementation of the smart-card prototype described in the paper. We describe how to compile the smart-card applet, and how to reproduce the measurements on this implementation.

The implementation relies partially on code from JCMathLib for some of the cryptographic operations. At the end of this README we explain an optimization to facilitate computing Pedersen commitments faster.

## A. Implementation of the Smart-card Prototype

To implement the prototype, we need to choose a card and a card reader that supports the necessary operations. 
We then build an Applet for the card to run the protocol as described in our paper. 
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
4. *GlobalPlatformPro*, for installing the applet on the physical card and send commands (i.e., APDUs)
5. `Python3` version 3.9 or later, for running the scripts to generate the data to send to the card by calling `GlobalPlatformPro`.
6. `pip`, a compilation suite, as well as OpenSSL and its development files to build Python dependencies, and the necessary tools to build a python virtual environment (like the module venv from the standard library).

For a Debian 11 system, 1, 3, 5, and 6 of the above dependencies can be installed using package repositories of the distribution using the command: 

```
# apt-get install ant openjdk-11-jdk python3 gcc g++ make cmake libssl-dev python3-dev python3-pip python3-venv
```

To get 2, you can run the git clone command with the option `--recurse-submodules`: 

```
$ git clone --recurse-submodules https://github.com/spring-epfl/not-yet-another-id-code.git
```

If you did not run the git clone command with the option `--recurse-submodules`, use the following command to retrieve the SDKs:

```
$ git submodule update --init --recursive
```

To get GlobalPlatformPro, first, go inside the directory where you cloned this repository, then retrieve the latest release of GlobalPlatformPro from [their GitHub](https://github.com/martinpaljak/GlobalPlatformPro), in our case the version 20.01.23 ([link to download](https://github.com/martinpaljak/GlobalPlatformPro/releases/download/v20.01.23/gp.jar)) and set an environment variable `GP` to hold the command which will be called to execute the JAR by running:

```
$ export GP="java -jar /path/to/gp.jar"
```

This `GP` environment variable will be used by Python scripts to call the tool.

We finalize the preparation by setting up a Python virtual environment and install scripts dependencies in this virtual environment using the following commands:

```
$ python3 -m venv venv
(venv) $ . venv/bin/activate
(venv) $ pip install -r smartcard/python/requirements.txt
```

Do not forget to change your working directory to the `smartcard` directory at the root of this git repository:
```
(venv) $ cd smartcard
```



### A.2 Building the Applet

Once we've installed all the dependencies from the previous section, we can build the applet. Before running the build command, make sure the card reader is connected to the machine, and the card is inserted in the reader. Then we can run:

```
$ ./gradlew buildJavaCard
tarting a Gradle Daemon, 1 incompatible and 1 stopped Daemons could not be reused, use --status for details
[ant:convert] [ INFO: ] Converter [v3.0.4]

...

BUILD SUCCESSFUL in 8s
1 actionable task: 1 executed
```

### A.3 Installing the Applet

After building the applet as A.2 shows, we need to install the applet on the card before sending any commands to the applet.

If there is already a previous installation of the applet on the card, we first uninstall it with:
```
$ $GP --uninstall ./applet/build/javacard/protocol.cap
03F1FF55DE deleted.
```

You might get some warnings like the following that you can safely ignore:
```
Warning: no keys given, using default test key 404142434445464748494A4B4C4D4E4F
```

To install the last build on the card, use:
```
$ $GP --install ./applet/build/javacard/protocol.cap
CAP loaded
```

#### A.4 Testing the Applet

To ensure that the applet is indeed computing correctly the tags, commitment and other cryptographic objects described in the protocol, we can: 
1. run the script `prototype.py` which will generate some data to send to the card,
2. do the same computations using the libraries PyCryptodome, cryptography, and petlib
3. (manually) compare both the output from GlobalPlatformPro and the expected result from the script `prototype.py`

If the outputs are identical, it means the cryptographic objects are computed correctly on the card. 

**Generating commands for the card together with expected results**

To get the output from the script `prototype.py`, we first activate the python virtual environment that should be at the root of this git repository, go into the correct working directory, and ensure we are in the `python` directory to run these scripts:
```
$ . venv/bin/activate
(venv) $ cd smartcard/python
```

Then we run `prototype.py` to generate some command inputs (with the corresponding expected output) to later feed into the card:

```
(venv) $ python prototype.py
Initialization phase at distribution station.
${GP} -d -a 00A404000B03F1FF55DE16074A09012600 -a 8011000020e743c8959d66c36d2c86ecf03f019995b7adb606072df8555e7eb1866033ef4d -a 8012000020d101a45137bddb35872a7e9cdea2af424a7aefc774b45139d625e2b91d799a18 -a 80130000410406094f1717b0c6eb9843884c982b9b9eadd39b050318cda56b00e5db5c1171e052c0f0ed03e3931fc78ae0e0bd3d54e6dd0ac54b3cac50380dd5efb85f854992 -a 8014000020e57dfdd27a543ac5120582c37636b20a3825e7378e873a5920a4a3f9508e170a -a 80150000200272e0323283e246dc8fa94830cc708a44b91a898c59ea260c47002ef12f7d97
Set entitlement.
${GP} -d -a 00A404000B03F1FF55DE16074A09012600 -a 8016000020a54a42b51e310ae953e006df7fd1a625bff8a7532b3da350852e42e5bc5c10a5

Hash blocklist
${GP} -d -a 00A404000B03F1FF55DE16074A09012600 -a 8021010080b1c820396969fb4a2cb3b2aba73d937367d33fd5c354cbaed396d2ea61ed25562d64208fdec0df014443b4a0cf335d802a3399188864f89d44784367e5a0f0d922532508df883f4fee8823dcda471934fe0dca4347e726c738c35f3cbb12eabd27241d843f6ee61c96983f7fb16f7f05e6a02fffdc7791782bce617626c9ddca -a 80210200807def6c4937250aa6a0373df373fbc2cadf381f19022f7cdaf42a159941769743ffa9a9578c19ea25e568cfcd7517d2eff9b6f7d5fe8a05f4bbfb47c386f8d4d8fd8382b0d5a9288a3628e850fb094e6388be2843efbfe90ce8ab89030cb99ba722364a8d7a55b4657c6e7fb847e32661ebf7ba2581ac95edc79e857f128cc9a1 -a 8021030080eb82ae3d9922001c00750136d8f656a04b36d6f7e1309a77a51d4d92b47528da00e1279d7d073865a8a4b6968e3f12085ae4136f6a0e818e6a3eeb99a4a61cdb735c241627ecf1c1f9cdbd18ed514caa99941591ac893c8009111440a046930da3c0e8853473a3f16a018f6f9092bed66efb5574dfdda222cb8bcc50365c18a3
Expected result
9151dcc690778e1f860eff4a321d1442b9af3c30f2705511173424cbeeb27347

Set period
${GP} -d -a 00A404000B03F1FF55DE16074A09012600 -a 8022000008000000006492ee9c
Expected result
6c98d0a80123d3e3ed66b61b5fe6438b9ae4b31dd116c6b967172967ea4f1fe2

Compute showing off proof
${GP} -d -a 00A404000B03F1FF55DE16074A09012600 -a 80230000
Verification
python prototype.py verify-commitment 0406094f1717b0c6eb9843884c982b9b9eadd39b050318cda56b00e5db5c1171e052c0f0ed03e3931fc78ae0e0bd3d54e6dd0ac54b3cac50380dd5efb85f854992 e57dfdd27a543ac5120582c37636b20a3825e7378e873a5920a4a3f9508e170a a54a42b51e310ae953e006df7fd1a625bff8a7532b3da350852e42e5bc5c10a5 R+COMMITMENT

Sending proof
${GP} -d -a 00A404000B03F1FF55DE16074A09012600 -a 8021010080b1c820396969fb4a2cb3b2aba73d937367d33fd5c354cbaed396d2ea61ed25562d64208fdec0df014443b4a0cf335d802a3399188864f89d44784367e5a0f0d922532508df883f4fee8823dcda471934fe0dca4347e726c738c35f3cbb12eabd27241d843f6ee61c96983f7fb16f7f05e6a02fffdc7791782bce617626c9ddca -a 80210200807def6c4937250aa6a0373df373fbc2cadf381f19022f7cdaf42a159941769743ffa9a9578c19ea25e568cfcd7517d2eff9b6f7d5fe8a05f4bbfb47c386f8d4d8fd8382b0d5a9288a3628e850fb094e6388be2843efbfe90ce8ab89030cb99ba722364a8d7a55b4657c6e7fb847e32661ebf7ba2581ac95edc79e857f128cc9a1 -a 8021030080eb82ae3d9922001c00750136d8f656a04b36d6f7e1309a77a51d4d92b47528da00e1279d7d073865a8a4b6968e3f12085ae4136f6a0e818e6a3eeb99a4a61cdb735c241627ecf1c1f9cdbd18ed514caa99941591ac893c8009111440a046930da3c0e8853473a3f16a018f6f9092bed66efb5574dfdda222cb8bcc50365c18a3 -a 80230000 -a 80240000
Verification (use result of previous command)
python prototype.py verify-signature 0451c1e2cb9976467bbb138642f26e57ccb4c771fdc725a91a85878ca511dbde9b84da505f8eae290821859e699b0a35f65238ea16b68d674110b82694297f501f 6c98d0a80123d3e3ed66b61b5fe6438b9ae4b31dd116c6b967172967ea4f1fe2 000000006492ee9c 9151dcc690778e1f860eff4a321d1442b9af3c30f2705511173424cbeeb27347 R+COMMITMENT SIGNATURE
```

From the above output, we see the commands (always starting with `${GP}`) to pass to the card for the following operations: 
- Initialization phase at distribution station
- Set entitlement
- Hash blocklist
- Set period
- Compute showing off proof
- Sending proof
- Verification

**Running commands on the card to get output**

We will run these commands one by one manually, and replacing the `R+COMMITMENT` and `SIGNATURE` variables by the values from the card output (see below for more details).

The outputs of GlobalPlatformPro are quite verbose, here is an example of output produced by the first command for initialization phase at distribution station:
```
{GP} -d -a 00A404000B03F1FF55DE16074A09012600 -a 8011000020e743c8959d66c36d2c86ecf03f019995b7adb606072df8555e7eb1866033ef4d -a 8012000020d101a45137bddb35872a7e9cdea2af424a7aefc774b45139d625e2b91d799a18 -a 80130000410406094f1717b0c6eb9843884c982b9b9eadd39b050318cda56b00e5db5c1171e052c0f0ed03e3931fc78ae0e0bd3d54e6dd0ac54b3cac50380dd5efb85f854992 -a 8014000020e57dfdd27a543ac5120582c37636b20a3825e7378e873a5920a4a3f9508e170a -a 80150000200272e0323283e246dc8fa94830cc708a44b91a898c59ea260c47002ef12f7d97
GlobalPlatformPro v20.01.23-0-g5ad373b
Running on Linux 5.10.0-23-amd64 amd64, Java 11.0.18 by Debian
# Detected readers from JNA2PCSC
[*] Identiv Identiv uTrust 4701 F Dual Interface Reader [uTrust 4701 F Contact Reader] (55041930208215) 00 00
[ ] Identiv Identiv uTrust 4701 F Dual Interface Reader [uTrust 4701 F CL Reader] (55041930208215) 01 00
[ ] Broadcom Corp 5880 [Contacted SmartCard] (0123456789ABCD) 02 00
[ ] Broadcom Corp 5880 [Contactless SmartCard] (0123456789ABCD) 03 00
SCardConnect("Identiv Identiv uTrust 4701 F Dual Interface Reader [uTrust 4701 F Contact Reader] (55041930208215) 00 00", T=*) -> T=1, 3BDC18FF8191FE1FC38073C821136605036351000250
SCardBeginTransaction("Identiv Identiv uTrust 4701 F Dual Interface Reader [uTrust 4701 F Contact Reader] (55041930208215) 00 00")
A>> T=1 (4+0011) 00A40400 0B 03F1FF55DE16074A090126 00
A<< (0000+2) (21ms) 9000
A>> T=1 (4+0032) 80110000 20 E743C8959D66C36D2C86ECF03F019995B7ADB606072DF8555E7EB1866033EF4D
A<< (0000+2) (116ms) 9000
A>> T=1 (4+0032) 80120000 20 D101A45137BDDB35872A7E9CDEA2AF424A7AEFC774B45139D625E2B91D799A18
A<< (0000+2) (27ms) 9000
A>> T=1 (4+0065) 80130000 41 0406094F1717B0C6EB9843884C982B9B9EADD39B050318CDA56B00E5DB5C1171E052C0F0ED03E3931FC78AE0E0BD3D54E6DD0AC54B3CAC50380DD5EFB85F854992
A<< (0000+2) (22ms) 9000
A>> T=1 (4+0032) 80140000 20 E57DFDD27A543AC5120582C37636B20A3825E7378E873A5920A4A3F9508E170A
A<< (0000+2) (26ms) 9000
A>> T=1 (4+0032) 80150000 20 0272E0323283E246DC8FA94830CC708A44B91A898C59EA260C47002EF12F7D97
A<< (0000+2) (18ms) 9000
A>> T=1 (4+0000) 00A40400 00 
A<< (0018+2) (14ms) 6F108408A000000151000000A5049F6501FF 9000
[TRACE] GPSession -  [6F]
[TRACE] GPSession -      [84] A000000151000000
[TRACE] GPSession -      [A5]
[TRACE] GPSession -          [9F65] FF
[DEBUG] GPSession - Auto-detected ISD: A000000151000000
SCardEndTransaction("Identiv Identiv uTrust 4701 F Dual Interface Reader [uTrust 4701 F Contact Reader] (55041930208215) 00 00")
SCardDisconnect("Identiv Identiv uTrust 4701 F Dual Interface Reader [uTrust 4701 F Contact Reader] (55041930208215) 00 00", true) tx:240/rx:32
```
Notice that the code `9000` means the command is executed successfully and the last line of output labeled by `9000` is from the card rest APDU (which will always be the last output no matter which command we run). Hence, the interesting output (i.e., the result of computation) will be the second last one for the commands that computed something. 

Next, we present three examples: hash blocklist, commitment, and signature, in order to explain how to check the output of the card with the expected output. 

For checking the hash of the blocklist, run:
```
${GP} -d -a 00A404000B03F1FF55DE16074A09012600 -a 8021010080b1c820396969fb4a2cb3b2aba73d937367d33fd5c354cbaed396d2ea61ed25562d64208fdec0df014443b4a0cf335d802a3399188864f89d44784367e5a0f0d922532508df883f4fee8823dcda471934fe0dca4347e726c738c35f3cbb12eabd27241d843f6ee61c96983f7fb16f7f05e6a02fffdc7791782bce617626c9ddca -a 80210200807def6c4937250aa6a0373df373fbc2cadf381f19022f7cdaf42a159941769743ffa9a9578c19ea25e568cfcd7517d2eff9b6f7d5fe8a05f4bbfb47c386f8d4d8fd8382b0d5a9288a3628e850fb094e6388be2843efbfe90ce8ab89030cb99ba722364a8d7a55b4657c6e7fb847e32661ebf7ba2581ac95edc79e857f128cc9a1 -a 8021030080eb82ae3d9922001c00750136d8f656a04b36d6f7e1309a77a51d4d92b47528da00e1279d7d073865a8a4b6968e3f12085ae4136f6a0e818e6a3eeb99a4a61cdb735c241627ecf1c1f9cdbd18ed514caa99941591ac893c8009111440a046930da3c0e8853473a3f16a018f6f9092bed66efb5574dfdda222cb8bcc50365c18a3
GlobalPlatformPro v20.01.23-0-g5ad373b
Running on Linux 5.10.0-23-amd64 amd64, Java 11.0.18 by Debian
# Detected readers from JNA2PCSC
[*] Identiv Identiv uTrust 4701 F Dual Interface Reader [uTrust 4701 F Contact Reader] (55041930208215) 00 00
[ ] Identiv Identiv uTrust 4701 F Dual Interface Reader [uTrust 4701 F CL Reader] (55041930208215) 01 00
[ ] Broadcom Corp 5880 [Contacted SmartCard] (0123456789ABCD) 02 00
[ ] Broadcom Corp 5880 [Contactless SmartCard] (0123456789ABCD) 03 00
SCardConnect("Identiv Identiv uTrust 4701 F Dual Interface Reader [uTrust 4701 F Contact Reader] (55041930208215) 00 00", T=*) -> T=1, 3BDC18FF8191FE1FC38073C821136605036351000250
SCardBeginTransaction("Identiv Identiv uTrust 4701 F Dual Interface Reader [uTrust 4701 F Contact Reader] (55041930208215) 00 00")
A>> T=1 (4+0011) 00A40400 0B 03F1FF55DE16074A090126 00
A<< (0000+2) (20ms) 9000
A>> T=1 (4+0128) 80210100 80 B1C820396969FB4A2CB3B2ABA73D937367D33FD5C354CBAED396D2EA61ED25562D64208FDEC0DF014443B4A0CF335D802A3399188864F89D44784367E5A0F0D922532508DF883F4FEE8823DCDA471934FE0DCA4347E726C738C35F3CBB12EABD27241D843F6EE61C96983F7FB16F7F05E6A02FFFDC7791782BCE617626C9DDCA
A<< (0000+2) (24ms) 9000
A>> T=1 (4+0128) 80210200 80 7DEF6C4937250AA6A0373DF373FBC2CADF381F19022F7CDAF42A159941769743FFA9A9578C19EA25E568CFCD7517D2EFF9B6F7D5FE8A05F4BBFB47C386F8D4D8FD8382B0D5A9288A3628E850FB094E6388BE2843EFBFE90CE8AB89030CB99BA722364A8D7A55B4657C6E7FB847E32661EBF7BA2581AC95EDC79E857F128CC9A1
A<< (0000+2) (24ms) 9000
A>> T=1 (4+0128) 80210300 80 EB82AE3D9922001C00750136D8F656A04B36D6F7E1309A77A51D4D92B47528DA00E1279D7D073865A8A4B6968E3F12085AE4136F6A0E818E6A3EEB99A4A61CDB735C241627ECF1C1F9CDBD18ED514CAA99941591AC893C8009111440A046930DA3C0E8853473A3F16A018F6F9092BED66EFB5574DFDDA222CB8BCC50365C18A3
A<< (0032+2) (31ms) 9151DCC690778E1F860EFF4A321D1442B9AF3C30F2705511173424CBEEB27347 9000
A>> T=1 (4+0000) 00A40400 00 
A<< (0018+2) (13ms) 6F108408A000000151000000A5049F6501FF 9000
[TRACE] GPSession -  [6F]
[TRACE] GPSession -      [84] A000000151000000
[TRACE] GPSession -      [A5]
[TRACE] GPSession -          [9F65] FF
[DEBUG] GPSession - Auto-detected ISD: A000000151000000
SCardEndTransaction("Identiv Identiv uTrust 4701 F Dual Interface Reader [uTrust 4701 F Contact Reader] (55041930208215) 00 00")
SCardDisconnect("Identiv Identiv uTrust 4701 F Dual Interface Reader [uTrust 4701 F Contact Reader] (55041930208215) 00 00", true) tx:421/rx:60
```

In this example, the interesting output line is:
```
A<< (0032+2) (31ms) 9151DCC690778E1F860EFF4A321D1442B9AF3C30F2705511173424CBEEB27347 9000
```

which match the expected value produced by the Python script:
```
Hash blocklist
${GP} -d -a 00A404000B03F1FF55DE16074A09012600 -a 80 ... a3
Expected result
9151dcc690778e1f860eff4a321d1442b9af3c30f2705511173424cbeeb27347
```

For checking the computation of the commitment, use the output from the *showing off proof* command, we verify the commitment by running:
```
(venv) $ python prototype.py verify-commitment <g> <z> <m> <R+COMMITMENT>
```

where `<R+COMMITMENT>` is the data returned by GlobalPlatformPro when running the APDU to compute the *show off proof* phase of the protocol, and the other arguments should already be provided. In our case, the output from GlobalPlatformPro was:

```
A>> T=1 (4+0000) 80230000
A<< (0064+2) (541ms) 511CE498CDD24E2D1384D65FC774564F3D834F9992508F36E7A25E1B494728F423CB1EB049917132C10ABD95E4A69F575384298EE041C7553F63C90854282512 9000
```

Therefore, the verification command we run in the terminal is:
```
(venv) $ python prototype.py verify-commitment 0406094f1717b0c6eb9843884c982b9b9eadd39b050318cda56b00e5db5c1171e052c0f0ed03e3931fc78ae0e0bd3d54e6dd0ac54b3cac50380dd5efb85f854992 e57dfdd27a543ac5120582c37636b20a3825e7378e873a5920a4a3f9508e170a a54a42b51e310ae953e006df7fd1a625bff8a7532b3da350852e42e5bc5c10a5 511CE498CDD24E2D1384D65FC774564F3D834F9992508F36E7A25E1B494728F423CB1EB049917132C10ABD95E4A69F575384298EE041C7553F63C90854282512
valid commitment
```
**TO CONTINUE HERE**

Last, to verify the signature, run:
```
python prototype.py verify-signature <pk> <tag> <period> <blocklist_hash> <R+COMMITMENT> <SIGNATURE>
```

Where both `<R+COMMITMENT>` and `<SIGNATURE>` is are returned by GlobalPlatformPro when running the APDU to compute the signature in the *sending proof* phase of the protocol, and the other arguments should already be provided.

In our case, GlobalPlatformPro reported that the `R+COMMITMENT` and `SIGNATURE` were:
```
A>> T=1 (4+0000) 80230000
A<< (0064+2) (484ms) 29E3D06D43AB718686779E2537C3387123B6044C14CC863E39670B73B299322B580CF3C4D80C484D8A65B966583A4B7261BB344F0E24B26E1A7C59E4FBA821A9 9000
A>> T=1 (4+0000) 80240000
A<< (0070+2) (378ms) 304402206F1AD65D9C54A0A0CF440C589AC3F0C99370456F62782FD498AD5218638DF51A0220751C5F9D571131BEAE391C2123A3F072290C1CE95C461D4D68CEB76C12F05565 9000
```

Therefore, the command we had to use to verify that the signature was correct was:

```
(venv) $ python prototype.py verify-signature 0451c1e2cb9976467bbb138642f26e57ccb4c771fdc725a91a85878ca511dbde9b84da505f8eae290821859e699b0a35f65238ea16b68d674110b82694297f501f 6c98d0a80123d3e3ed66b61b5fe6438b9ae4b31dd116c6b967172967ea4f1fe2 000000006492ee9c 9151dcc690778e1f860eff4a321d1442b9af3c30f2705511173424cbeeb27347 29E3D06D43AB718686779E2537C3387123B6044C14CC863E39670B73B299322B580CF3C4D80C484D8A65B966583A4B7261BB344F0E24B26E1A7C59E4FBA821A9 304402206F1AD65D9C54A0A0CF440C589AC3F0C99370456F62782FD498AD5218638DF51A0220751C5F9D571131BEAE391C2123A3F072290C1CE95C461D4D68CEB76C12F05565
Verification successful!
```


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

(Knowing the discrete logarithm of `H` with respect to `G` is normally not secure, but in this case, we are trusting the card to act as a TEE anyway.)

Which simplifies the computation of the commitment as:

$$ C = G^{mv} G ^r = G^{mv + r} $$

Then we used JCMathlib to compute the remaining large integers operations. Also because the multiplication is much more costly in term of computation than addition, we pre-compute the computation of $mv$ when we are setting the household entitlement $m$. This allow to improve the performance of commitment computation, by offloading the multiplication cost.


### D. Acknowledgement 
This implementation uses code from [JCMathlib](https://github.com/OpenCryptoProject/JCMathLib), as well as a template written by Dusan Klinec, Martin Paljak, and Petr Svenda which can be found at this [link](https://github.com/ph4r05/javacard-gradle-template).
