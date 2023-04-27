package protocol;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.apdu.ExtendedLength;
import javacardx.crypto.Cipher;


/**
 * Applet implementing our protocol.
 */
public class ProtocolApplet extends Applet implements ExtendedLength  {

    // The byte to identify our applet
    private static final byte APP_CLA = (byte) 0x80;

    // The different instructions supported by our applet.
    private static final byte INS_SET_SECRET_KEY = (byte) 0x11;
    private static final byte INS_SET_HOUSEHOLD_REVOCATION_VALUE = (byte) 0x12;
    private static final byte INS_SET_COMMITMENT_EC_POINT = (byte) 0x13;
    private static final byte INS_SET_COMMITMENT_Z_FACTOR = (byte) 0x14;
    private static final byte INS_SET_HOUSEHOLD_SECRET = (byte) 0x15;
    private static final byte INS_SET_HOUSEHOLD_ENTITLEMENT = (byte) 0x16;

    private static final byte INS_RECEIVE_BLOCKLIST_FROM_DISTRIBUTION_STATION = (byte) 0x21;
    private static final byte INS_RECEIVE_PERIOD_FROM_DISTRIBUTION_STATION = (byte) 0x22;
    private static final byte INS_COMPUTE_SHOWING_OFF_PROOF = (byte) 0x23;
    private static final byte INS_SENDING_PROOF_TO_DISTRIBUTION_STATION = (byte) 0x24;

    // Error to return if the card is revocated
    private static final short SW_IS_REVOCATED = (short) 0x8000;

    // The different states in which the card could be.
    private static final byte STATE_DISABLED = (byte) 0x00;
    private static final byte STATE_REGISTRATION = (byte) 0x01;
    private static final byte STATE_DISTRIBUTION = (byte) 0x02;

    // Flags to ensure the operations were done corrctly (currently unused).
    private static final byte FUNCTION_FLAG_INIT = (byte) 0x00;
    private static final byte FUNCTION_FLAG_HASH_DONE = (byte) 0x01;
    private static final byte FUNCTION_FLAG_PERIOD_CHECKED = (byte) 0x02;
    private static final byte FUNCTION_FLAG_PROOF_CHECKED = (byte) 0x03;
    private static final byte FUNCTION_FLAG_PROOF_SENT = (byte) 0x04;

    // Global values used in our implementation (mostly payload sizes).
    private static final short LAST_PERIOD_LENGTH = (short) 8;
    private static final short SHARED_SECRET_KEY_LENGTH = (short) 32;
    private static final short HOUSEHOLD_SECRET_LENGTH = (short) 32;
    private static final short HOUSEHOLD_ENTITLEMENT_LENGTH = (short) 32;
    private static final short HOUSEHOLD_REVOCATION_VALUE_LENGTH = (short) 32;
    private static final short BLOCKLIST_HASH_LENGTH = (short) 32;
    private static final short HOUSEHOLD_TAG_LENGTH = (short) 32;
    private static final short ENTITLEMENT_COMMITMENT_LENGTH = (short) 32;
    private static final short AUDIT_SIGNATURE_LENGTH = (short) 72;
    private static final short COMMITMENT_RANDOM_LENGTH = (short) 32;
    private static final short SIGNATURE_BUFFER_SIZE = (short) 104;


    // Variables stored in permanent memory
    private byte state;
    private byte[] last_period;
    private byte[] household_secret;
    private byte[] household_entitlement;
    private byte[] household_revocation_value;

    // Variables stored in transient memory
    private byte[] function_flag;
    private byte[] blocklist_hash;
    private byte[] entitlement_commitment;
    private byte[] audit_signature;
    private byte[] commitment_random;

    // Function "stacks"

    // Blocklist hashing stack
    private static final short BLOCKLIST_ELEMENT_SIZE = (short) 32;
    private static final short BLOCKLIST_ELEMENT_SIZE_LOG2 = (short) 5;
    private static final short BLOCKLIST_BUFFER_SIZE = (short) 128;
    private static final byte P1_BLOCKLIST_START = (byte) 0x01;
    private static final byte P1_BLOCKLIST_MIDDLE = (byte) 0x02;
    private static final byte P1_BLOCKLIST_END = (byte) 0x03;
    MessageDigest bl_hash_digest;
    private byte[] bl_buffer;

    // PRF stack
    private static final short PRF_BLOCK_SIZE = (short) 16;
    private static final short PRF_KEY_SIZE = (short) 16;
    AESKey prf_key;
    Cipher prf_cipher;
    byte[] prf_input;

    // Commitment computation stack
    private static final short COM_BIGNAT_SIZE = (short) 32;
    private static final short COM_POINT_SIZE = (short) 65;
    private static final short MODULO_RSA_ENGINE_MAX_LENGTH_BITS = (short) 512;
    private static final short MULT_RSA_ENGINE_MAX_LENGTH_BITS = (short) 768;
    private static final short MAX_BIGNAT_SIZE = (short) 65; // ((short) (MODULO_ENGINE_MAX_LENGTH_BITS / 8) + 1);
    private static final short MAX_POINT_SIZE = (short) 64;
    private static final short MAX_COORD_SIZE = (short) 32; // MAX_POINT_SIZE / 2
    RandomData rng;
    ResourceManager com_rm;
    Bignat_Helper com_bnh;
    Bignat com_p;
    Bignat com_z;
    Bignat com_m;
    Bignat com_mz;
    Bignat com_mz2;
    Bignat com_r;
    Bignat com_exp;
    byte[] com_z_raw;
    byte[] com_mz_raw;
    byte[] com_g;
    byte[] com_exp_internal;
    byte[] com_exp_output;
    ECPrivateKey exp_sk;
    byte[] exp_output;

    // Signature stack
    Signature sig_signer;
    ECPrivateKey sig_sk;
    byte[] signature_buffer;

    public static void install(byte[] b_array, short b_offset, byte b_length) {
        new ProtocolApplet(b_array, b_offset, b_length).register();
    }

    public ProtocolApplet(byte[] buffer, short offset, byte length) {
        super();

        //
        // Initialize the variables stored in teh card or in memory to perform the operations.
        //
        this.state = ProtocolApplet.STATE_DISABLED;
        this.last_period = new byte[ProtocolApplet.LAST_PERIOD_LENGTH];
        this.household_secret = new byte[ProtocolApplet.HOUSEHOLD_SECRET_LENGTH];
        this.household_entitlement = new byte[ProtocolApplet.HOUSEHOLD_ENTITLEMENT_LENGTH];
        this.household_revocation_value = new byte[ProtocolApplet.HOUSEHOLD_REVOCATION_VALUE_LENGTH];

        this.function_flag = JCSystem.makeTransientByteArray(
            (short) 1,
            JCSystem.CLEAR_ON_RESET
        );

        this.blocklist_hash = JCSystem.makeTransientByteArray(
            ProtocolApplet.BLOCKLIST_HASH_LENGTH,
            JCSystem.CLEAR_ON_RESET
        );

        this.entitlement_commitment = JCSystem.makeTransientByteArray(
            ProtocolApplet.ENTITLEMENT_COMMITMENT_LENGTH,
            JCSystem.CLEAR_ON_RESET
        );

        this.audit_signature = JCSystem.makeTransientByteArray(
            ProtocolApplet.AUDIT_SIGNATURE_LENGTH,
            JCSystem.CLEAR_ON_RESET
        );

        this.commitment_random = JCSystem.makeTransientByteArray(
            ProtocolApplet.COMMITMENT_RANDOM_LENGTH,
            JCSystem.CLEAR_ON_RESET
        );

        //
        // Initialize Blocklist hashing stack
        //
        this.bl_hash_digest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        this.bl_buffer = JCSystem.makeTransientByteArray(
            ProtocolApplet.BLOCKLIST_BUFFER_SIZE,
            JCSystem.CLEAR_ON_DESELECT
        );

        //
        // Initialize PRF stack
        //
        this.prf_input = JCSystem.makeTransientByteArray(
            ProtocolApplet.HOUSEHOLD_TAG_LENGTH,
            JCSystem.CLEAR_ON_DESELECT
        );
        this.prf_key = (AESKey) KeyBuilder.buildKey(
            KeyBuilder.ALG_TYPE_AES,
            JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT,
            KeyBuilder.LENGTH_AES_128,
            false
        );
        this.prf_cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);

        //
        // Initialize commitment stack.
        //

        // Set the card model globals for JCMathlib, and initialize JCMathlib's helpers
        OperationSupport.getInstance().setCard(OperationSupport.J3H145);
        this.com_rm = new ResourceManager();
        this.com_bnh = new Bignat_Helper(this.com_rm);

        this.com_rm.initialize(MAX_POINT_SIZE, MAX_COORD_SIZE, MAX_BIGNAT_SIZE, MULT_RSA_ENGINE_MAX_LENGTH_BITS, this.com_bnh);
        this.com_bnh.initialize(MODULO_RSA_ENGINE_MAX_LENGTH_BITS, MULT_RSA_ENGINE_MAX_LENGTH_BITS);

        // Initialize the big numbers that we will use for our computations.
        this.com_p = new Bignat(ProtocolApplet.COM_BIGNAT_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT, this.com_bnh);
        this.com_p.from_byte_array(SecP256r1.r);

        this.com_g = new byte[ProtocolApplet.COM_POINT_SIZE];

        this.com_m = new Bignat(ProtocolApplet.COM_BIGNAT_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, this.com_bnh);
        this.com_mz = new Bignat(ProtocolApplet.COM_BIGNAT_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, this.com_bnh);
        this.com_mz2 = new Bignat(ProtocolApplet.COM_BIGNAT_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, this.com_bnh);
        this.com_z = new Bignat(ProtocolApplet.COM_BIGNAT_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, this.com_bnh);
        this.com_r = new Bignat(ProtocolApplet.COM_BIGNAT_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, this.com_bnh);

        this.com_z_raw = new byte[ProtocolApplet.COM_BIGNAT_SIZE];
        this.com_mz_raw = new byte[ProtocolApplet.COM_BIGNAT_SIZE];

        this.com_exp = new Bignat(ProtocolApplet.COM_BIGNAT_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, this.com_bnh);

        this.com_exp_internal = JCSystem.makeTransientByteArray(
            (short)(2*ProtocolApplet.COM_BIGNAT_SIZE),
            JCSystem.CLEAR_ON_DESELECT
        );
        this.com_exp_output = JCSystem.makeTransientByteArray(
            ProtocolApplet.COM_BIGNAT_SIZE,
            JCSystem.CLEAR_ON_DESELECT
        );

        //
        // Initialize exp stack
        //
        this.exp_sk = (ECPrivateKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PRIVATE, // This card only supports private keys stored in EEPROM.
            KeyBuilder.LENGTH_EC_FP_256,
            false
        );
        setPrivateKeyParameters(this.exp_sk);
        this.exp_output = JCSystem.makeTransientByteArray(
            (short)(2*ProtocolApplet.COM_POINT_SIZE),
            JCSystem.CLEAR_ON_DESELECT
        );
        this.rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        //
        // Initialize signature stack
        //
        this.sig_signer = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        this.sig_sk = (ECPrivateKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PRIVATE,
            KeyBuilder.LENGTH_EC_FP_256,
            false
        );
        setPrivateKeyParameters(this.sig_sk);
        this.signature_buffer = JCSystem.makeTransientByteArray(
            ProtocolApplet.SIGNATURE_BUFFER_SIZE,
            JCSystem.CLEAR_ON_DESELECT
        );
    }

    public void process(APDU apdu) {
        if (this.selectingApplet()) {
            return;
        }

        byte[] apduBuffer = apdu.getBuffer();
        // Get the CLA; mask out the logical-channel info.
        apduBuffer[ISO7816.OFFSET_CLA] = (byte) (apduBuffer[ISO7816.OFFSET_CLA] & (byte) 0xFC);

        if (apduBuffer[ISO7816.OFFSET_CLA] != APP_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (apduBuffer[ISO7816.OFFSET_INS]) {
            case ProtocolApplet.INS_SET_SECRET_KEY:
                this.setSecretKey(apdu);
                break;
            case ProtocolApplet.INS_SET_HOUSEHOLD_REVOCATION_VALUE:
                this.setHouseholdRevocationValue(apdu);
                break;
            case ProtocolApplet.INS_SET_COMMITMENT_EC_POINT:
                this.setCommitmentEcPoint(apdu);
                break;
            case ProtocolApplet.INS_SET_COMMITMENT_Z_FACTOR:
                this.setCommitmentZFactor(apdu);
                break;
            case ProtocolApplet.INS_SET_HOUSEHOLD_SECRET:
                this.setHouseholdSecret(apdu);
                break;
            case ProtocolApplet.INS_SET_HOUSEHOLD_ENTITLEMENT:
                this.setHouseholdEntitlement(apdu);
                break;
            case ProtocolApplet.INS_RECEIVE_BLOCKLIST_FROM_DISTRIBUTION_STATION:
                this.receiveBlocklistFromDistributionStation(apdu);
                break;
            case ProtocolApplet.INS_RECEIVE_PERIOD_FROM_DISTRIBUTION_STATION:
                this.receivePeriodFromDistributionStation(apdu);
                break;
            case ProtocolApplet.INS_COMPUTE_SHOWING_OFF_PROOF:
                this.computeShowingOffProof(apdu);
                break;
            case ProtocolApplet.INS_SENDING_PROOF_TO_DISTRIBUTION_STATION:
                this.sendProofToDistributionStation(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /**
     * Set the secret key used to sign the commitment from the APDU input.
     * @param apdu The APDU recived by the card.
     */
    private void setSecretKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short bytes_read = apdu.setIncomingAndReceive();
        if (bytes_read != ProtocolApplet.SHARED_SECRET_KEY_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        this.sig_sk.setS(buffer, ISO7816.OFFSET_CDATA, ProtocolApplet.SHARED_SECRET_KEY_LENGTH);
    }

    /**
     * Set the revocation value of the household.
     * @param apdu The APDU recived by the card.
     */
    private void setHouseholdRevocationValue(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short bytes_read = apdu.setIncomingAndReceive();
        if (bytes_read != ProtocolApplet.HOUSEHOLD_REVOCATION_VALUE_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayCopyNonAtomic(
            buffer, ISO7816.OFFSET_CDATA,
            this.household_revocation_value, (short) 0,
            ProtocolApplet.HOUSEHOLD_REVOCATION_VALUE_LENGTH
        );
    }

    /**
     * A typical commitment is computed such as:
     *   C = h^m * g^r
     * where g and h are points on an elliptic curve,
     * m is the household entitlement,
     * and r a pseudo-randomly generated number.
     *
     * Because of JavaCard API limitations, we replace h by:
     *   h = g^z
     *
     * And therefore the commitment is:
     *   C = g^(z * m (mod p)) * g^r = g^(m * z + r (mod p))
     * where p is the order of the elliptic curve's group.
     *
     * This method set the elliptic point g used in that equation.
     * @param apdu The APDU recived by the card.
     */
    private void setCommitmentEcPoint(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short bytes_read = apdu.setIncomingAndReceive();
        if (bytes_read != ProtocolApplet.COM_POINT_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayCopyNonAtomic(
            buffer, ISO7816.OFFSET_CDATA,
            this.com_g, (short) 0,
            bytes_read
        );
    }

    /**
     * A typical commitment is computed such as:
     *   C = h^m * g^r
     * where g and h are points on an elliptic curve,
     * m is the household entitlement,
     * and r a pseudo-randomly generated number.
     *
     * Because of JavaCard API limitations, we replace h by:
     *   h = g^z
     *
     * And therefore the commitment is:
     *   C = g^(z * m (mod p)) * g^r = g^(m * z + r (mod p))
     * where p is the order of the elliptic curve's group.
     *
     * This method sets the factor z used in that equation.
     * @param apdu The APDU recived by the card.
     */
    private void setCommitmentZFactor(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short bytes_read = apdu.setIncomingAndReceive();
        if (bytes_read > ProtocolApplet.COM_BIGNAT_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayCopyNonAtomic(
            buffer, ISO7816.OFFSET_CDATA,
            this.com_z_raw, (short) (ProtocolApplet.COM_BIGNAT_SIZE - bytes_read),
            bytes_read
        );
    }

    /**
     * Set the household's secret.
     * @param apdu The APDU recived by the card.
     */
    private void setHouseholdSecret(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short bytes_read = apdu.setIncomingAndReceive();
        if (bytes_read != ProtocolApplet.HOUSEHOLD_SECRET_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayCopyNonAtomic(
            buffer, ISO7816.OFFSET_CDATA,
            this.household_secret, (short) 0,
            ProtocolApplet.HOUSEHOLD_SECRET_LENGTH
        );
    }

    /**
     * Set the household's entitlement, and pre-compute the m*z value to speed up the computation of the commitment.
     * @param apdu The APDU recived by the card.
     */
    private void setHouseholdEntitlement(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short bytes_read = apdu.setIncomingAndReceive();
        if (bytes_read != ProtocolApplet.COM_BIGNAT_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayCopyNonAtomic(
            buffer, ISO7816.OFFSET_CDATA,
            this.household_entitlement, (short) 0,
            bytes_read
        );
        this.utilPreComputeMZ();
    }

    /**
     * A typical commitment is computed such as:
     *   C = h^m * g^r
     * where g and h are points on an elliptic curve,
     * m is the household entitlement,
     * and r a pseudo-randomly generated number.
     *
     * Because of JavaCard API limitations, we replace h by:
     *   h = g^z
     *
     * And therefore the commitment is:
     *   C = g^(z * m (mod p)) * g^r = g^(m * z + r (mod p))
     * where p is the order of the elliptic curve's group.
     *
     * This method pre-compute the factor m * z (mod p) in that equation.
     * @param apdu The APDU recived by the card.
     */
    private void utilPreComputeMZ() {
        this.com_m.from_byte_array(ProtocolApplet.COM_BIGNAT_SIZE, (short) 0, this.household_entitlement, (short) 0);
        this.com_z.from_byte_array(ProtocolApplet.COM_BIGNAT_SIZE, (short) 0, this.com_z_raw, (short) 0);

        this.com_exp.mod_mult(this.com_m, this.com_z, this.com_p);

        // JCMathLib's Bignat can have a variable size, we ensure its is represented as a fixed N bytes number in big endian representation.
        short exp_length = this.com_exp.copy_to_buffer(this.com_exp_internal, (short) 0);
        Util.arrayFillNonAtomic(this.com_mz_raw, (short) 0, (short) (ProtocolApplet.COM_BIGNAT_SIZE - exp_length), (byte) 0);

        Util.arrayCopyNonAtomic(
            this.com_exp_internal, (short) 0,
            this.com_mz_raw, (short) (ProtocolApplet.COM_BIGNAT_SIZE - exp_length),
            exp_length
        );
    }

    /**
     * Receive the blocklist,
     * check if the household revocation value stored in that card is in the blocklist,
     * if the revocation value is in the blocklist, throw an error
     * otherwise return the hash of the blocklist.
     * @param apdu The APDU recived by the card.
     */
    private void receiveBlocklistFromDistributionStation(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short bytes_read = apdu.setIncomingAndReceive();
        short offset = apdu.getOffsetCdata();
        short length = apdu.getIncomingLength();

        if (length > ProtocolApplet.BLOCKLIST_BUFFER_SIZE || (length & (short) 0x1F) != (short) 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short bl_buffer_offset = (short) 0;
        while (bytes_read != (short) 0) {
            Util.arrayCopyNonAtomic(buffer, offset, this.bl_buffer, bl_buffer_offset, bytes_read);
            bl_buffer_offset += bytes_read;
            bytes_read = apdu.receiveBytes(offset);
        }

        checkBlocklistForRevocation(this.bl_buffer, (short) 0, length);

        switch(buffer[ISO7816.OFFSET_P1]) {
            case P1_BLOCKLIST_START:
                // If we start to hash the blocklist, we ensure the hashing function is initialized.
                this.bl_hash_digest.reset();
                this.bl_hash_digest.update(this.bl_buffer, (short) 0, length);
                break;
            case P1_BLOCKLIST_MIDDLE:
                this.bl_hash_digest.update(this.bl_buffer, (short) 0, length);
                break;
            case P1_BLOCKLIST_END:
                // Once we finished processing the blocklist, we send back the hash of the full blocklist.
                apdu.setOutgoing();
                apdu.setOutgoingLength(ProtocolApplet.BLOCKLIST_HASH_LENGTH);
                this.bl_hash_digest.doFinal(this.bl_buffer, (short) 0, length, this.blocklist_hash, (short) 0);
                Util.arrayCopyNonAtomic(this.blocklist_hash, (short) 0, buffer, (short) 0, ProtocolApplet.BLOCKLIST_HASH_LENGTH);
                apdu.sendBytes((short) 0, ProtocolApplet.BLOCKLIST_HASH_LENGTH);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
    }

    /**
     * Check if the household's revocation value is in the blocklist.
     * if the revocation value is in the blocklist, throw an error
     * otherwise return
     * @param buffer buffer containing the blocklist
     * @param offset offset where the blocklist starts in the buffer
     * @param total_length length of the blocklist in bytes
     */
    private void checkBlocklistForRevocation(byte[] buffer, short offset, short total_length) {
        short blocks = (short) (total_length >> ProtocolApplet.BLOCKLIST_ELEMENT_SIZE_LOG2);

        for (short i = (short) 0; i < blocks; ++i) {
            short block_offset = (short) (offset + i * ProtocolApplet.BLOCKLIST_ELEMENT_SIZE);
            short cmp = Util.arrayCompare(
                buffer, block_offset,
                this.household_revocation_value, (short) 0,
                ProtocolApplet.BLOCKLIST_ELEMENT_SIZE
            );
            if (cmp == (short) 0) {
                ISOException.throwIt(ProtocolApplet.SW_IS_REVOCATED);
            }
        }
    }

    /**
     * Receive the period we are currently in from the distribution station.
     * Sends back a tag from the new period and the household secret if the period received is after the last period registered on the card,
     * Otherwise throw an error.
     * @param apdu The APDU recived by the card.
     */
    private void receivePeriodFromDistributionStation(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        // Retrieve data sent by the user, a seed of 16 bytes.
        short bytes_read = apdu.setIncomingAndReceive();
        if (bytes_read != ProtocolApplet.LAST_PERIOD_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // The period must be strictly increasing.
        if (this.compareBytes(buffer, ISO7816.OFFSET_CDATA, this.last_period, (short) 0, ProtocolApplet.LAST_PERIOD_LENGTH) < (short) 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        Util.arrayCopyNonAtomic(
            buffer, ISO7816.OFFSET_CDATA,
            this.last_period, (short) 0,
            ProtocolApplet.LAST_PERIOD_LENGTH
        );

        // Compute teh tag and send it back.
        apdu.setOutgoing();
        apdu.setOutgoingLength(ProtocolApplet.HOUSEHOLD_TAG_LENGTH);

        this.utilPrf(
            this.household_secret, (short) 0,
            this.last_period, (short) 0, ProtocolApplet.LAST_PERIOD_LENGTH,
            buffer, (short) 0
        );

        apdu.sendBytes((short) 0, ProtocolApplet.HOUSEHOLD_TAG_LENGTH);
    }

    /**
     * Compare big integers a and b in big-endian format and return.
     * Similar to JavaCard's Util.arrayCompare but without sign shenanigans.
     *
     * @param a buffer containing the first big number
     * @param a_offset offset at which the first big number starts
     * @param b buffer containing the second big number
     * @param b_offset offset at which the second big number starts
     * @param length length of the big numbers in bytes
     * @return -1 if a < b, 1 if a > b, 0 otherwise
     */
    private short compareBytes(byte[] a, short a_offset, byte[] b, short b_offset, short length) {
        for (short i = (short) 0; i < length; ++i) {
            short a_byte = Util.makeShort((byte) 0, a[(short) (a_offset + i)]);
            short b_byte = Util.makeShort((byte) 0, b[(short) (b_offset + i)]);

            if (a_byte != b_byte) {
                if (a_byte < b_byte) {
                    return (short) -1;
                }
                else { //if (a_byte > b_byte) {
                    return (short) 1;
                }
            }
        }
        return (short) 0;
    }

    /**
     * Deterministic pseudo-random method to generate a tag from an AES key, and an input.
     *
     * TODO: this is not the most efficient (nor obvious) way to extend the PRF to several blocks.
     * The problem is that there is a lot of overhead in computing the AES key schedule
     * (which we now have to do twice), better use the same key, but diversified data.
     *
     * @param key AES keys data
     * @param key_offset offset where the AES keys start
     * @param input input data from which the pseudo-random data is generated
     * @param input_offset offset at which the input data starts
     * @param input_length length of the input data
     * @param output buffer where to write the pseudo-generated data
     * @param output_offset offset where to write the pseudo-generated data
     */

    private void utilPrf(
            byte[] key, short key_offset,
            byte[] input, short input_offset, short input_length,
            byte[] output, short output_offset
        ) {
        // The PRF is computed by encrypting the household tag with two different AES keys in ECB mode.
        // Each encryption produces 16 bytes of pseudo-random data.
        Util.arrayCopyNonAtomic(
            input, input_offset,
            this.prf_input, (short) 0,
            input_length
        );
        Util.arrayFillNonAtomic(this.prf_input, input_length, (short) (ProtocolApplet.HOUSEHOLD_TAG_LENGTH - input_length), (byte) 0);

        this.prf_key.setKey(key, key_offset);
        this.prf_cipher.init(this.prf_key, Cipher.MODE_ENCRYPT);

        this.prf_cipher.doFinal(
            this.prf_input, (short) 0, ProtocolApplet.PRF_BLOCK_SIZE,
            output, output_offset
        );

        this.prf_key.setKey(key, (short) (key_offset + ProtocolApplet.PRF_KEY_SIZE));
        this.prf_cipher.init(this.prf_key, Cipher.MODE_ENCRYPT);
        this.prf_cipher.doFinal(
            this.prf_input, (short) 0, ProtocolApplet.PRF_BLOCK_SIZE,
            output, (short) (output_offset + ProtocolApplet.PRF_BLOCK_SIZE)
        );
    }

    /**
     * Compute the commitment and send back the random number generated to compute the commitment, and the commitemnt.
     * @param apdu The APDU recived by the card.
     */
    private void computeShowingOffProof(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        this.rng.generateData(this.commitment_random, (short) 0, ProtocolApplet.COM_BIGNAT_SIZE);

        // we drop the first bit to ensure r is always smaller than Order(G).
        this.commitment_random[0] = (byte) (this.commitment_random[0] & 0x7f);

        short r_offset = (short) 0;
        short ecpt_offset = (short) (r_offset +  ProtocolApplet.COM_BIGNAT_SIZE);
        short output_size = (short) (ecpt_offset + ProtocolApplet.ENTITLEMENT_COMMITMENT_LENGTH);

        apdu.setOutgoing();
        apdu.setOutgoingLength(output_size);

        // copy r to the output buffer
        Util.arrayCopyNonAtomic(
            this.commitment_random, (short) 0,
            buffer, r_offset,
            ProtocolApplet.COM_BIGNAT_SIZE
        );

        // Compute the exponent exp used in the computation of the commitment C = g^exp .
        this.utilComputeExponent(
            this.com_mz_raw, (short) 0,
            this.commitment_random, (short) 0,
            this.com_exp_output, (short) 0
        );

        // Compute the commitment C = g^exp .
        this.utilEcPointPower(
            this.com_g, (short) 0,
            this.com_exp_output, (short) 0,
            this.entitlement_commitment, (short) 0
        );

        // Copy the commitment G^(m+zr (mod p)) to the output buffer.
        Util.arrayCopyNonAtomic(
            this.entitlement_commitment, (short) 0,
            buffer, ecpt_offset,
            ProtocolApplet.ENTITLEMENT_COMMITMENT_LENGTH
        );

        apdu.sendBytes((short) 0, output_size);
    }

    /**
     * A typical commitment is computed such as:
     *   C = h^m * g^r
     * where g and h are points on an elliptic curve,
     * m is the household entitlement,
     * and r a pseudo-randomly generated number.
     *
     * Because of JavaCard API limitations, we replace h by:
     *   h = g^z
     *
     * And therefore the commitment is:
     *   C = g^(z * m (mod p)) * g^r = g^(m * z + r (mod p))
     * where p is the order of the elliptic curve's group.
     *
     * This method compute the exponent m * z + r (mod p) in that equation.
     *
     * @param mz bugger containg the precomputed m*z
     * @param mz_offset offset where the precomputed m*z starts
     * @param r buffer containing r
     * @param r_offset offset where r starts
     * @param output output where to write the computed exponent
     * @param output_offset offset where to start to write the exponent
     */
    private void utilComputeExponent(
            byte[] mz, short mz_offset,
            byte[] r, short r_offset,
            byte[] output, short output_offset
        ) {
        this.com_mz.from_byte_array(ProtocolApplet.COM_BIGNAT_SIZE, (short) 0, mz, mz_offset);
        this.com_r.from_byte_array(ProtocolApplet.COM_BIGNAT_SIZE, (short) 0, r, r_offset);

        this.com_mz.mod_add(this.com_r, this.com_p);

        short exp_length = this.com_mz.copy_to_buffer(this.com_exp_internal, (short) 0);

        Util.arrayFillNonAtomic(output, output_offset, (short) (ProtocolApplet.COM_BIGNAT_SIZE - exp_length), (byte) 0);

        Util.arrayCopyNonAtomic(
            this.com_exp_internal, (short) 0,
            output, (short) (output_offset + ProtocolApplet.COM_BIGNAT_SIZE - exp_length),
            exp_length
        );
    }

    /**
     * A typical commitment is computed such as:
     *   C = h^m * g^r
     * where g and h are points on an elliptic curve,
     * m is the household entitlement,
     * and r a pseudo-randomly generated number.
     *
     * Because of JavaCard API limitations, we replace h by:
     *   h = g^z
     *
     * And therefore the commitment is:
     *   C = g^(z * m (mod p)) * g^r = g^(m * z + r (mod p))
     * where p is the order of the elliptic curve's group.
     *
     * We can rewrite it as:
     *   C = g^exp
     * where exp = m * z + r (mod p)
     *
     * This method compute the point exponentiation g^exp in that equation.
     * @param point buffer containg the x,y coordinates of the point on the elliptic curve g
     * @param point_offset offset where the point's data starts
     * @param exp buffer containing the exponent
     * @param exp_offset offset where the exponent starts
     * @param result buffer where to write g^exp as an x coordinate
     * @param result_offset offset where to write g^exp
     * @return the size of the x cordinate of g^exp in bytes
     */
    private short utilEcPointPower(
            byte[] point, short point_offset,
            byte[] exp, short exp_offset,
            byte[] result, short result_offset
        ) {
        this.exp_sk.setS(exp, exp_offset, ProtocolApplet.COM_BIGNAT_SIZE);
        KeyAgreement dh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        dh.init(this.exp_sk);
        short output_length = dh.generateSecret(
            point, point_offset, ProtocolApplet.COM_POINT_SIZE,
            result, result_offset
        );
        return output_length;
    }

    /**
     * Sign the current period, the commitment, and the blocklist hash, and send back the signature.
     * @param apdu The APDU recived by the card.
     */
    private void sendProofToDistributionStation(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        // Add tag to signature.
        this.utilPrf(
            this.household_secret, (short) 0,
            this.last_period, (short) 0, ProtocolApplet.LAST_PERIOD_LENGTH,
            this.signature_buffer, (short) 0
        );

        // Add last period to signature.
        short last_period_offset = ProtocolApplet.HOUSEHOLD_TAG_LENGTH;
        Util.arrayCopyNonAtomic(
            this.last_period, (short) 0,
            this.signature_buffer, last_period_offset,
            ProtocolApplet.LAST_PERIOD_LENGTH
        );

        // Add commitment to signature.
        short entitlement_commitment_offset = (short) (
            last_period_offset + ProtocolApplet.LAST_PERIOD_LENGTH
        );
        Util.arrayCopyNonAtomic(
            this.entitlement_commitment, (short) 0,
            this.signature_buffer, entitlement_commitment_offset,
            ProtocolApplet.ENTITLEMENT_COMMITMENT_LENGTH
        );

        // Add blocklist hash to signature.
        short blocklist_hash_offset = (short) (
            entitlement_commitment_offset + ProtocolApplet.ENTITLEMENT_COMMITMENT_LENGTH
        );
        Util.arrayCopyNonAtomic(
            this.blocklist_hash, (short) 0,
            this.signature_buffer, blocklist_hash_offset,
            ProtocolApplet.BLOCKLIST_HASH_LENGTH
        );

        // Sign the data.
        short sig_offset = (short) 0;
        short sig_length = this.utilSign(this.signature_buffer, (short) 0, ProtocolApplet.SIGNATURE_BUFFER_SIZE, this.audit_signature, (short) 0);

        short output_length = sig_length;

        // Prepare to send the signature back.
        apdu.setOutgoing();
        apdu.setOutgoingLength(output_length);

        // Copy the signature in the sending buffer.
        Util.arrayCopyNonAtomic(
            this.audit_signature, (short) 0,
            buffer, sig_offset,
            sig_length
        );

        // Finally send back the signature.
        apdu.sendBytes((short) 0, output_length);
    }

    /**
     * Sign the data in the buffer and write the signature in an output buffer.
     * @param to_sign data to sign
     * @param to_sign_offset offset where the data to sign starts
     * @param to_sign_length length of the data to sign in bytes
     * @param output buffer where to write the signature
     * @param output_offset offset where to start to write the signature
     * @return size of the signature in bytes
     */
    private short utilSign(byte[] to_sign, short to_sign_offset, short to_sign_length, byte[] output, short output_offset) {
        sig_signer.init(this.sig_sk, Signature.MODE_SIGN);
        return sig_signer.sign(to_sign, to_sign_offset, to_sign_length, output, output_offset);
    }

    /**
     * Set the private key parameters for the curve secp256r1
     * @param sk private key that we need to parametrize
     */
    private static void setPrivateKeyParameters(ECPrivateKey sk) {
        sk.setFieldFP(SecP256r1.p, (short) 0, (short) 32);
        sk.setA(SecP256r1.a, (short) 0, (short) 32);
        sk.setB(SecP256r1.b, (short) 0, (short) 32);
        sk.setR(SecP256r1.r, (short) 0, (short) 32);
        sk.setG(SecP256r1.G, (short) 0, (short) 65);
    }
}
