package dev.wobbegong.kmsca.entities.asn1.charsets;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;

public class IA5CharsetDecoder extends CharsetDecoder {
    /**
     * Initializes a new decoder.  The new decoder will have the given
     * chars-per-byte values and its replacement will be the
     * string <code>"&#92;uFFFD"</code>.
     *
     * @param cs                  The charset that created this decoder
     * @throws IllegalArgumentException If the preconditions on the parameters do not hold
     */
    protected IA5CharsetDecoder(Charset cs) {
        super(cs, 1, 1);
    }

    @Override
    protected CoderResult decodeLoop(ByteBuffer in, CharBuffer out) {
        while(in.hasRemaining()) {
            if(!out.hasRemaining()) {
                return CoderResult.OVERFLOW;
            }

            byte nextByte = in.get();
            if((nextByte & 0b1000_0000) != 0) {
                throw new RuntimeException("Invalid byte for IA5 Charset: " + nextByte);
            }
            out.put((char) nextByte);
        }
        return CoderResult.UNDERFLOW;
    }
}
