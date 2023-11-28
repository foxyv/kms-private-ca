package dev.wobbegong.kmsca.entities.asn1.charsets;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CoderResult;

public class IA5CharsetEncoder extends CharsetEncoder {
    /**
     * Initializes a new decoder.  The new decoder will have the given
     * chars-per-byte values and its replacement will be the
     * string <code>"&#92;uFFFD"</code>.
     *
     * @param cs                  The charset that created this decoder
     * @throws IllegalArgumentException If the preconditions on the parameters do not hold
     */
    protected IA5CharsetEncoder(Charset cs) {
        super(cs, 1, 1);
    }

    @Override
    protected CoderResult encodeLoop(CharBuffer in, ByteBuffer out) {
        while(in.hasRemaining()) {
            if(out.hasRemaining()) {
                return CoderResult.OVERFLOW;
            }

            char nextChar = in.get();
            if(nextChar > 127) {
                throw new RuntimeException("IA5 format does not support character: " + nextChar);
            }

            out.put((byte) nextChar);
        }
        return CoderResult.UNDERFLOW;
    }
}
