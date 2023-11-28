package dev.wobbegong.kmsca.utils;

import java.math.BigInteger;

public class DERNumberUtils {

    public static boolean moreBit(byte aByte) {
        return ((aByte & 0xff) >> 7) == 1;
    }

    /**
     * OID numbers in DER encoding are encoded 7 bits at a time. We need to shift our bits over to fill in the gaps.
     *
     * EG:
     *
     * @param array
     * @param offset
     * @param length
     * @return
     */
    public static BigInteger oidNumberForBytes(byte[] array, int offset, int length) {

        /*
         * We need to shift our bits over to the next byte to compress our 7 bit numbers into 8-bit numbers
         */
        byte[] shiftedBuffer = new byte[length];
        int shift = 0;
        for (int index = (offset + length) - 1; index >= offset; index--) {

            // Calculate the remainder (Bits shifted off of the left neighboring byte)
            if (index != offset) {
                // Shift our current byte
                int currentByteShifted = (array[index] & 0b0111_1111) >> shift;

                // Pull the N + 1 most significant bits from our left neighbor byte
                int leftByte = array[index - 1] & 0xFF;
                final int remainder = (leftByte << (7 - shift)) & 0xFF;
                // OR the shifted byte with the remainder.
                shiftedBuffer[index - offset] = (byte) ((currentByteShifted) | remainder);
            } else {
                // Remove the leftmost bit and shift our current byte
                int leftByteNoMoreDigit = array[index] & 0b0111_1111;
                int currentByteShifted = (leftByteNoMoreDigit >> shift) & 0xFF;

                // Leftmost byte will always have a remainder of 0
                shiftedBuffer[index - offset] = (byte) ((currentByteShifted));
            }
            shift++;

        }
        return new BigInteger(1, shiftedBuffer);
    }
}
