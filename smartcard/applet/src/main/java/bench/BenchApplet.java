package bench;

import javacard.framework.*;
import javacard.security.*;
import javacardx.apdu.ExtendedLength;
import javacardx.crypto.Cipher;

/**
 * Applet used to benchmark latency of data transfer:
 * - receiving data from host and copying to card
 * - sending to host
 *
 * The applet implements command chaining for APDUs of extended length using protocol T=0.
 */
public class BenchApplet extends Applet implements ExtendedLength {

    private static final byte APP_CLA = (byte) 0x80;

    private static final byte INS_DUMMY = (byte) 0x10;

    private static final byte INS_RECEIVE = (byte) 0x30;
    private static final byte INS_CHND_RECEIVE = (byte) 0x31;
    private static final byte INS_CHND_RECEIVE_ON_MEMORY = (byte) 0x33;
    private static final byte INS_RECEIVE_ON_MEMORY = (byte) 0x32;
    private static final byte INS_SEND = (byte) 0x40;
    private static final byte INS_KEYGEN = (byte) 0x50;
    private static final byte INS_HASH = (byte) 0x55;

    private static final byte INS_INIT_SIG = (byte) 0x60;
    private static final byte INS_SIGN_128 = (byte) 0x61;
    private static final byte INS_SIGN_256 = (byte) 0x62;
    private static final byte INS_SIGN_512 = (byte) 0x63;
    private static final byte INS_SIGN_1024 = (byte) 0x64;
    private static final byte INS_SIGN_2048 = (byte) 0x65;
    private static final byte INS_SIGN_4096 = (byte) 0x66;
    private static final byte INS_SIGN_8192 = (byte) 0x67;
    private static final byte INS_SIGN_16384 = (byte) 0x68;

    private static final byte INS_INIT_PRF = (byte) 0x70;
    private static final byte INS_PRF_128 = (byte) 0x71;
    private static final byte INS_PRF_256 = (byte) 0x72;
    private static final byte INS_PRF_512 = (byte) 0x73;
    private static final byte INS_PRF_1024 = (byte) 0x74;
    private static final byte INS_PRF_2048 = (byte) 0x75;
    private static final byte INS_PRF_4096 = (byte) 0x76;
    private static final byte INS_PRF_8192 = (byte) 0x77;
    private static final byte INS_PRF_16384 = (byte) 0x78;

    // PRF-related constants.
    private static final short PRF_BLOCK_SIZE = (short) 16;

    // Signature-related constants.
    private static final short SIG_SIGNATURE_MAX_SIZE = (short) 72;

    private static final byte[] DATA_ARRAY = {
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
    };
    private static final byte[] AES_KEY_DATA = {
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
            (byte) 0x63, (byte) 0xFF, (byte) 0xA0, (byte) 0x1E,
    };

    private static final byte[] SIG_PK_DATA = {
        (byte) 0x04, (byte) 0xd3, (byte) 0xad, (byte) 0x4a, (byte) 0x3e, (byte) 0x3e, (byte) 0x51, (byte) 0xf3,
        (byte) 0x9a, (byte) 0x67, (byte) 0xdc, (byte) 0xe2, (byte) 0xc8, (byte) 0x8b, (byte) 0x7a, (byte) 0x1f,
        (byte) 0x42, (byte) 0xe2, (byte) 0x2d, (byte) 0xe5, (byte) 0xaa, (byte) 0x32, (byte) 0xb4, (byte) 0x0f,
        (byte) 0xb9, (byte) 0x04, (byte) 0xf7, (byte) 0x7d, (byte) 0x6c, (byte) 0xfb, (byte) 0xc7, (byte) 0xe8,
        (byte) 0x9c, (byte) 0x04, (byte) 0x2d, (byte) 0x67, (byte) 0xdc, (byte) 0xd3, (byte) 0x9f, (byte) 0xe4,
        (byte) 0x34, (byte) 0xa4, (byte) 0x17, (byte) 0x24, (byte) 0x49, (byte) 0x5a, (byte) 0xea, (byte) 0x72,
        (byte) 0x90, (byte) 0x0c, (byte) 0x24, (byte) 0xbc, (byte) 0xc9, (byte) 0x99, (byte) 0xc6, (byte) 0x87,
        (byte) 0xaf, (byte) 0x7f, (byte) 0xbe, (byte) 0x35, (byte) 0xcd, (byte) 0x91, (byte) 0xdf, (byte) 0x43,
        (byte) 0x3f
    };

    private static final byte[] SIG_SK_DATA = {
        (byte) 0xd2, (byte) 0x58, (byte) 0x68, (byte) 0xf8, (byte) 0x48, (byte) 0xf5, (byte) 0x59, (byte) 0x49,
        (byte) 0xa6, (byte) 0x75, (byte) 0x7a, (byte) 0xca, (byte) 0xe4, (byte) 0x91, (byte) 0xb4, (byte) 0xcb,
        (byte) 0x59, (byte) 0x44, (byte) 0xd9, (byte) 0x29, (byte) 0x28, (byte) 0xd0, (byte) 0xa2, (byte) 0x1d,
        (byte) 0x24, (byte) 0x0a, (byte) 0x2b, (byte) 0x19, (byte) 0x63, (byte) 0xa7, (byte) 0x2f, (byte) 0x6a
    };

    byte[] persistentArray;
    byte[] transientArray;
    short receiveIdx;
    short receiveChainLength;
    byte currentChainINS;
    ECPublicKey pk;
    ECPrivateKey sk;
    KeyPair keys;
    Signature sig;
    MessageDigest hash;

    AESKey aesKey;
    Cipher aes;

    // PRF stack
    AESKey prf_key;
    Cipher prf_cipher;
    byte[] prf_input;


    // Signature stack
    ECPrivateKey sig_sk;
    ECPublicKey sig_pk;
    KeyPair sig_key_pair;
    byte[] sig_output;


    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new BenchApplet(bArray, bOffset, bLength).register();
    }

    public BenchApplet(byte[] buffer, short offset, byte length) {
        super();
        persistentArray = new byte[256];
        Util.arrayFillNonAtomic(persistentArray, (short) 0, (short) 256, (byte) 0x42);
        transientArray = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
        receiveIdx = 0;
        receiveChainLength = 0;
        currentChainINS = 0x00;
        pk = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
        sk = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        keys = new KeyPair(pk, sk);
        sig = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        hash = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        aesKey.setKey(AES_KEY_DATA, (short) 0);
        aes = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

        // Initialize PRF stack
        this.prf_input = JCSystem.makeTransientByteArray(
            BenchApplet.PRF_BLOCK_SIZE,
            JCSystem.CLEAR_ON_DESELECT
        );
        this.prf_key = (AESKey) KeyBuilder.buildKey(
            KeyBuilder.ALG_TYPE_AES,
            JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT,
            KeyBuilder.LENGTH_AES_128,
            false
        );
        this.prf_cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);

        // Initialize signature stack
        this.sig_sk = (ECPrivateKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PRIVATE,
            KeyBuilder.LENGTH_EC_FP_256,
            false
        );
        setPrivateKeyParameters(this.sig_sk);
        this.sig_sk.setS(SIG_SK_DATA, (short) 0, (short) SIG_SK_DATA.length);

        this.sig_pk = (ECPublicKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PUBLIC,
            KeyBuilder.LENGTH_EC_FP_256,
            false
        );
        setPublicKeyParameters(this.sig_pk);
        this.sig_pk.setW(SIG_PK_DATA, (short) 0, (short) SIG_PK_DATA.length);

        this.sig_key_pair = new KeyPair(this.sig_pk, this.sig_sk);
        this.sig_output = JCSystem.makeTransientByteArray(
            BenchApplet.SIG_SIGNATURE_MAX_SIZE,
            JCSystem.CLEAR_ON_DESELECT
        );
    }

    public void process(APDU apdu)
    {
        if (selectingApplet())
            return;
        byte[] apduBuffer = apdu.getBuffer();
        // Get the CLA; mask out the logical-channel info.
        apduBuffer[ISO7816.OFFSET_CLA] = (byte)(apduBuffer[ISO7816.OFFSET_CLA] & (byte)0xFC);

        if (apduBuffer[ISO7816.OFFSET_CLA] != APP_CLA)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        // case where the apdu is part of a chain of commands
        if (apduBuffer[ISO7816.OFFSET_INS] == INS_CHND_RECEIVE ||
            apduBuffer[ISO7816.OFFSET_INS] == INS_CHND_RECEIVE_ON_MEMORY){
            processChaining(apdu);
            return;
        }

        switch (apduBuffer[ISO7816.OFFSET_INS]){
            case INS_DUMMY:
                processDummy();
                break;
            case INS_RECEIVE:
                processReceive(apdu);
                break;
            case INS_RECEIVE_ON_MEMORY:
                processTransientReceive(apdu);
                break;
            case INS_SEND:
                processSend(apdu);
                break;
            case INS_KEYGEN:
                processKeyGen();
                break;
            case INS_HASH:
                processHash(apdu);
                break;
            case INS_INIT_SIG:
                processInitSign();
                break;
            case INS_SIGN_128:
                processSign128();
                break;
            case INS_SIGN_256:
                processSign256();
                break;
            case INS_SIGN_512:
                processSign512();
                break;
            case INS_SIGN_1024:
                processSign1024();
                break;
            case INS_SIGN_2048:
                processSign2048();
                break;
            case INS_SIGN_4096:
                processSign4096();
                break;
            case INS_SIGN_8192:
                processSign8192();
                break;
            case INS_SIGN_16384:
                processSign16384();
                break;
            case INS_INIT_PRF:
                processInitPrf();
                break;
            case INS_PRF_128:
                processPrf128();
                break;
            case INS_PRF_256:
                processPrf256();
                break;
            case INS_PRF_512:
                processPrf512();
                break;
            case INS_PRF_1024:
                processPrf1024();
                break;
            case INS_PRF_2048:
                processPrf2048();
                break;
            case INS_PRF_4096:
                processPrf4096();
                break;
            case INS_PRF_8192:
                processPrf8192();
                break;
            case INS_PRF_16384:
                processPrf16384();
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /** Does nothing, used to measure baseline. */
    private void processDummy() {}

    /*
     * copies the received data to a transientArray array
     */
    private void processReceive(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();

        while ( bytesRead > 0 ) {
            Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, transientArray, (short) 0, bytesRead);
            bytesRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
        }
    }

    /*
     * copies the received data to a temp array
     */
    private void processTransientReceive(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();

        while ( bytesRead > 0 ) {
            Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, transientArray, (short) 0, bytesRead);
            bytesRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
        }
    }

    /*
     * sends data back to host
     *
     * NOTE simplification of READ_BINARY: it does not take into account offset in the data array.
     */
    private void processSend(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        apdu.setOutgoing();
        short expected = Util.makeShort(buffer[ISO7816.OFFSET_P1], buffer[ISO7816.OFFSET_P2]);

        if (expected <= (short) 256){
            apdu.setOutgoingLength(expected);
            Util.arrayFillNonAtomic(buffer, (short) 0, expected, (byte) 0x42);
            apdu.sendBytes((short) 0, expected);
        } else {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
    }

    /*
     * Benchmark time required to generate private and public keys
     */
    private void processKeyGen() {
        setKeysParameters();
        keys.genKeyPair();
    }

    private void processInitSign(){
        sig.init(this.sig_sk, Signature.MODE_SIGN);
    }

    private void processSign128(){
        for (short i = (short) 128; i != (short) 0; --i) {
            sig.sign(DATA_ARRAY, (short) 0, (short) 128, transientArray, (short) 0);
        }
    }

    private void processSign256(){
        for (short i = (short) 256; i != (short) 0; --i) {
            sig.sign(DATA_ARRAY, (short) 0, (short) 128, transientArray, (short) 0);
        }
    }

    private void processSign512(){
        for (short i = (short) 512; i != (short) 0; --i) {
            sig.sign(DATA_ARRAY, (short) 0, (short) 128, transientArray, (short) 0);
        }
    }

    private void processSign1024(){
        for (short i = (short) 1024; i != (short) 0; --i) {
            sig.sign(DATA_ARRAY, (short) 0, (short) 128, transientArray, (short) 0);
        }
    }

    private void processSign2048(){
        for (short i = (short) 2048; i != (short) 0; --i) {
            sig.sign(DATA_ARRAY, (short) 0, (short) 128, transientArray, (short) 0);
        }
    }

    private void processSign4096(){
        for (short i = (short) 4096; i != (short) 0; --i) {
            sig.sign(DATA_ARRAY, (short) 0, (short) 128, transientArray, (short) 0);
        }
    }

    private void processSign8192(){
        for (short i = (short) 8192; i != (short) 0; --i) {
            sig.sign(DATA_ARRAY, (short) 0, (short) 128, transientArray, (short) 0);
        }
    }

    private void processSign16384(){
        for (short i = (short) 16384; i != (short) 0; --i) {
            sig.sign(DATA_ARRAY, (short) 0, (short) 128, transientArray, (short) 0);
        }
    }

    private void processInitPrf(){
        this.prf_key.setKey(BenchApplet.AES_KEY_DATA, (short) 0);
        this.prf_cipher.init(this.prf_key, Cipher.MODE_ENCRYPT);
    }

    private void processPrf128() {
        for (short i = (short) 128; i != (short) 0; --i) {
            this.prf_cipher.doFinal(
                BenchApplet.DATA_ARRAY, (short) 0, BenchApplet.PRF_BLOCK_SIZE,
                transientArray, (short) 0
            );
        }
    }

    private void processPrf256() {
        for (short i = (short) 256; i != (short) 0; --i) {
            this.prf_cipher.doFinal(
                BenchApplet.DATA_ARRAY, (short) 0, BenchApplet.PRF_BLOCK_SIZE,
                transientArray, (short) 0
            );
        }
    }

    private void processPrf512() {
        for (short i = (short) 512; i != (short) 0; --i) {
            this.prf_cipher.doFinal(
                BenchApplet.DATA_ARRAY, (short) 0, BenchApplet.PRF_BLOCK_SIZE,
                transientArray, (short) 0
            );
        }
    }

    private void processPrf1024() {
        for (short i = (short) 1024; i != (short) 0; --i) {
            this.prf_cipher.doFinal(
                BenchApplet.DATA_ARRAY, (short) 0, BenchApplet.PRF_BLOCK_SIZE,
                transientArray, (short) 0
            );
        }
    }

    private void processPrf2048() {
        for (short i = (short) 2048; i != (short) 0; --i) {
            this.prf_cipher.doFinal(
                BenchApplet.DATA_ARRAY, (short) 0, BenchApplet.PRF_BLOCK_SIZE,
                transientArray, (short) 0
            );
        }
    }

    private void processPrf4096() {
        for (short i = (short) 4096; i != (short) 0; --i) {
            this.prf_cipher.doFinal(
                BenchApplet.DATA_ARRAY, (short) 0, BenchApplet.PRF_BLOCK_SIZE,
                transientArray, (short) 0
            );
        }
    }

    private void processPrf8192() {
        for (short i = (short) 8192; i != (short) 0; --i) {
            this.prf_cipher.doFinal(
                BenchApplet.DATA_ARRAY, (short) 0, BenchApplet.PRF_BLOCK_SIZE,
                transientArray, (short) 0
            );
        }
    }

    private void processPrf16384() {
        for (short i = (short) 16384; i != (short) 0; --i) {
            this.prf_cipher.doFinal(
                BenchApplet.DATA_ARRAY, (short) 0, BenchApplet.PRF_BLOCK_SIZE,
                transientArray, (short) 0
            );
        }
    }

    private void processHash(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        short n_blocks = (short) ((short) ((short) buffer[ISO7816.OFFSET_P1] << (short) 8) + (short) buffer[ISO7816.OFFSET_P2]);
        if (n_blocks > 0) {
            --n_blocks;
            for (;n_blocks > 0; --n_blocks) {
                hash.update(DATA_ARRAY, (short) 0, (short) 128);
            }
            hash.doFinal(DATA_ARRAY, (short) 0, (short) 128, transientArray, (short) 0);
        }
    }

    public boolean select(boolean b) {
        return true;
    }

    public void deselect(boolean b) {

    }

    /* ####################################################
       ################# CHAINED COMMANDS #################
       #################################################### */

    /*
     * processes a command which is part of a chain
     */
    private void processChaining(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        short idx = Util.makeShort(buffer[ISO7816.OFFSET_P1], buffer[ISO7816.OFFSET_P2]);
        if (idx == (short) 0){
            // first message of the chain
            if (receiveIdx < receiveChainLength) {
                // starting a new chain when previous one is not finished is not allowed
                resetStatus();
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            }
            currentChainINS = INS_CHND_RECEIVE;
            receiveIdx = 0;
            apdu.setIncomingAndReceive();
            if (apdu.getIncomingLength() != (short) 2)
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            receiveChainLength = Util.makeShort(
                    buffer[ISO7816.OFFSET_CDATA], buffer[(short)(ISO7816.OFFSET_CDATA + 1)]);
        } else if (idx < receiveChainLength &&  idx == (short) (receiveIdx + 1)){
            // process next chain message
            if (buffer[ISO7816.OFFSET_INS] != currentChainINS){
                resetStatus();
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            }
            receiveIdx = idx;
            short incomingBytes = apdu.setIncomingAndReceive();
            if (buffer[ISO7816.OFFSET_INS] == INS_CHND_RECEIVE)
                Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, persistentArray, (short) 0, incomingBytes);
            else
                Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, transientArray, (short) 0, incomingBytes);
            if (receiveIdx == (short) (receiveChainLength - 1))
                // if it is last chain message, reset status
                resetStatus();
        } else {
            resetStatus();
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    /*
     * resets the chain status
     */
    private void resetStatus(){
        receiveChainLength = 0;
        receiveIdx = 0;
        currentChainINS = 0x00;
    }

    private void setKeysParameters(){
        sk.setFieldFP(SecP256r1.p, (short) 0, (short) 32);
        sk.setA(SecP256r1.a, (short) 0, (short) 32);
        sk.setB(SecP256r1.b, (short) 0, (short) 32);
        sk.setR(SecP256r1.r, (short) 0, (short) 32);
        sk.setG(SecP256r1.G, (short) 0, (short) 65);
        pk.setFieldFP(SecP256r1.p, (short) 0, (short) 32);
        pk.setA(SecP256r1.a, (short) 0, (short) 32);
        pk.setB(SecP256r1.b, (short) 0, (short) 32);
        pk.setR(SecP256r1.r, (short) 0, (short) 32);
        pk.setG(SecP256r1.G, (short) 0, (short) 65);
    }

    private static void setPrivateKeyParameters(ECPrivateKey sk) {
        sk.setFieldFP(SecP256r1.p, (short) 0, (short) 32);
        sk.setA(SecP256r1.a, (short) 0, (short) 32);
        sk.setB(SecP256r1.b, (short) 0, (short) 32);
        sk.setR(SecP256r1.r, (short) 0, (short) 32);
        sk.setG(SecP256r1.G, (short) 0, (short) 65);
    }
    private static void setPublicKeyParameters(ECPublicKey pk) {
        pk.setFieldFP(SecP256r1.p, (short) 0, (short) 32);
        pk.setA(SecP256r1.a, (short) 0, (short) 32);
        pk.setB(SecP256r1.b, (short) 0, (short) 32);
        pk.setR(SecP256r1.r, (short) 0, (short) 32);
        pk.setG(SecP256r1.G, (short) 0, (short) 65);
    }
}
