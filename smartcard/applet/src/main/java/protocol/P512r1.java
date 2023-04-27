package protocol;

public class P512r1 {

    public final static short KEY_LENGTH = 512; //Bits
    public final static short POINT_SIZE = 129; //Bytes
    public final static short COORD_SIZE = 64; //Bytes

    public final static byte[] p = {(byte) 0xAA, (byte) 0xDD, (byte) 0x9D, (byte) 0xB8, (byte) 0xDB, (byte) 0xE9, (byte) 0xC4, (byte) 0x8B, (byte) 0x3F, (byte) 0xD4, (byte) 0xE6, (byte) 0xAE, (byte) 0x33, (byte) 0xC9, (byte) 0xFC, (byte) 0x07, (byte) 0xCB, (byte) 0x30, (byte) 0x8D, (byte) 0xB3, (byte) 0xB3, (byte) 0xC9, (byte) 0xD2, (byte) 0x0E, (byte) 0xD6, (byte) 0x63, (byte) 0x9C, (byte) 0xCA, (byte) 0x70, (byte) 0x33, (byte) 0x08, (byte) 0x71, (byte) 0x7D, (byte) 0x4D, (byte) 0x9B, (byte) 0x00, (byte) 0x9B, (byte) 0xC6, (byte) 0x68, (byte) 0x42, (byte) 0xAE, (byte) 0xCD, (byte) 0xA1, (byte) 0x2A, (byte) 0xE6, (byte) 0xA3, (byte) 0x80, (byte) 0xE6, (byte) 0x28, (byte) 0x81, (byte) 0xFF, (byte) 0x2F, (byte) 0x2D, (byte) 0x82, (byte) 0xC6, (byte) 0x85, (byte) 0x28, (byte) 0xAA, (byte) 0x60, (byte) 0x56, (byte) 0x58, (byte) 0x3A, (byte) 0x48, (byte) 0xF3};

    public final static byte[] a = {(byte) 0x78, (byte) 0x30, (byte) 0xA3, (byte) 0x31, (byte) 0x8B, (byte) 0x60, (byte) 0x3B, (byte) 0x89, (byte) 0xE2, (byte) 0x32, (byte) 0x71, (byte) 0x45, (byte) 0xAC, (byte) 0x23, (byte) 0x4C, (byte) 0xC5, (byte) 0x94, (byte) 0xCB, (byte) 0xDD, (byte) 0x8D, (byte) 0x3D, (byte) 0xF9, (byte) 0x16, (byte) 0x10, (byte) 0xA8, (byte) 0x34, (byte) 0x41, (byte) 0xCA, (byte) 0xEA, (byte) 0x98, (byte) 0x63, (byte) 0xBC, (byte) 0x2D, (byte) 0xED, (byte) 0x5D, (byte) 0x5A, (byte) 0xA8, (byte) 0x25, (byte) 0x3A, (byte) 0xA1, (byte) 0x0A, (byte) 0x2E, (byte) 0xF1, (byte) 0xC9, (byte) 0x8B, (byte) 0x9A, (byte) 0xC8, (byte) 0xB5, (byte) 0x7F, (byte) 0x11, (byte) 0x17, (byte) 0xA7, (byte) 0x2B, (byte) 0xF2, (byte) 0xC7, (byte) 0xB9, (byte) 0xE7, (byte) 0xC1, (byte) 0xAC, (byte) 0x4D, (byte) 0x77, (byte) 0xFC, (byte) 0x94, (byte) 0xCA};

    public final static byte[] b = {(byte) 0x3D, (byte) 0xF9, (byte) 0x16, (byte) 0x10, (byte) 0xA8, (byte) 0x34, (byte) 0x41, (byte) 0xCA, (byte) 0xEA, (byte) 0x98, (byte) 0x63, (byte) 0xBC, (byte) 0x2D, (byte) 0xED, (byte) 0x5D, (byte) 0x5A, (byte) 0xA8, (byte) 0x25, (byte) 0x3A, (byte) 0xA1, (byte) 0x0A, (byte) 0x2E, (byte) 0xF1, (byte) 0xC9, (byte) 0x8B, (byte) 0x9A, (byte) 0xC8, (byte) 0xB5, (byte) 0x7F, (byte) 0x11, (byte) 0x17, (byte) 0xA7, (byte) 0x2B, (byte) 0xF2, (byte) 0xC7, (byte) 0xB9, (byte) 0xE7, (byte) 0xC1, (byte) 0xAC, (byte) 0x4D, (byte) 0x77, (byte) 0xFC, (byte) 0x94, (byte) 0xCA, (byte) 0xDC, (byte) 0x08, (byte) 0x3E, (byte) 0x67, (byte) 0x98, (byte) 0x40, (byte) 0x50, (byte) 0xB7, (byte) 0x5E, (byte) 0xBA, (byte) 0xE5, (byte) 0xDD, (byte) 0x28, (byte) 0x09, (byte) 0xBD, (byte) 0x63, (byte) 0x80, (byte) 0x16, (byte) 0xF7, (byte) 0x23};

    public final static byte[] G = {(byte) 0x04, (byte) 0x81, (byte) 0xAE, (byte) 0xE4, (byte) 0xBD, (byte) 0xD8, (byte) 0x2E, (byte) 0xD9, (byte) 0x64, (byte) 0x5A, (byte) 0x21, (byte) 0x32, (byte) 0x2E, (byte) 0x9C, (byte) 0x4C, (byte) 0x6A, (byte) 0x93, (byte) 0x85, (byte) 0xED, (byte) 0x9F, (byte) 0x70, (byte) 0xB5, (byte) 0xD9, (byte) 0x16, (byte) 0xC1, (byte) 0xB4, (byte) 0x3B, (byte) 0x62, (byte) 0xEE, (byte) 0xF4, (byte) 0xD0, (byte) 0x09, (byte) 0x8E, (byte) 0xFF, (byte) 0x3B, (byte) 0x1F, (byte) 0x78, (byte) 0xE2, (byte) 0xD0, (byte) 0xD4, (byte) 0x8D, (byte) 0x50, (byte) 0xD1, (byte) 0x68, (byte) 0x7B, (byte) 0x93, (byte) 0xB9, (byte) 0x7D, (byte) 0x5F, (byte) 0x7C, (byte) 0x6D, (byte) 0x50, (byte) 0x47, (byte) 0x40, (byte) 0x6A, (byte) 0x5E, (byte) 0x68, (byte) 0x8B, (byte) 0x35, (byte) 0x22, (byte) 0x09, (byte) 0xBC, (byte) 0xB9, (byte) 0xF8, (byte) 0x22,
        (byte) 0x7D, (byte) 0xDE, (byte) 0x38, (byte) 0x5D, (byte) 0x56, (byte) 0x63, (byte) 0x32, (byte) 0xEC, (byte) 0xC0, (byte) 0xEA, (byte) 0xBF, (byte) 0xA9, (byte) 0xCF, (byte) 0x78, (byte) 0x22, (byte) 0xFD, (byte) 0xF2, (byte) 0x09, (byte) 0xF7, (byte) 0x00, (byte) 0x24, (byte) 0xA5, (byte) 0x7B, (byte) 0x1A, (byte) 0xA0, (byte) 0x00, (byte) 0xC5, (byte) 0x5B, (byte) 0x88, (byte) 0x1F, (byte) 0x81, (byte) 0x11, (byte) 0xB2, (byte) 0xDC, (byte) 0xDE, (byte) 0x49, (byte) 0x4A, (byte) 0x5F, (byte) 0x48, (byte) 0x5E, (byte) 0x5B, (byte) 0xCA, (byte) 0x4B, (byte) 0xD8, (byte) 0x8A, (byte) 0x27, (byte) 0x63, (byte) 0xAE, (byte) 0xD1, (byte) 0xCA, (byte) 0x2B, (byte) 0x2F, (byte) 0xA8, (byte) 0xF0, (byte) 0x54, (byte) 0x06, (byte) 0x78, (byte) 0xCD, (byte) 0x1E, (byte) 0x0F, (byte) 0x3A, (byte) 0xD8, (byte) 0x08, (byte) 0x92};

    public final static byte[] r = {(byte) 0xAA, (byte) 0xDD, (byte) 0x9D, (byte) 0xB8, (byte) 0xDB, (byte) 0xE9, (byte) 0xC4, (byte) 0x8B, (byte) 0x3F, (byte) 0xD4, (byte) 0xE6, (byte) 0xAE, (byte) 0x33, (byte) 0xC9, (byte) 0xFC, (byte) 0x07, (byte) 0xCB, (byte) 0x30, (byte) 0x8D, (byte) 0xB3, (byte) 0xB3, (byte) 0xC9, (byte) 0xD2, (byte) 0x0E, (byte) 0xD6, (byte) 0x63, (byte) 0x9C, (byte) 0xCA, (byte) 0x70, (byte) 0x33, (byte) 0x08, (byte) 0x70, (byte) 0x55, (byte) 0x3E, (byte) 0x5C, (byte) 0x41, (byte) 0x4C, (byte) 0xA9, (byte) 0x26, (byte) 0x19, (byte) 0x41, (byte) 0x86, (byte) 0x61, (byte) 0x19, (byte) 0x7F, (byte) 0xAC, (byte) 0x10, (byte) 0x47, (byte) 0x1D, (byte) 0xB1, (byte) 0xD3, (byte) 0x81, (byte) 0x08, (byte) 0x5D, (byte) 0xDA, (byte) 0xDD, (byte) 0xB5, (byte) 0x87, (byte) 0x96, (byte) 0x82, (byte) 0x9C, (byte) 0xA9, (byte) 0x00, (byte) 0x69};
}