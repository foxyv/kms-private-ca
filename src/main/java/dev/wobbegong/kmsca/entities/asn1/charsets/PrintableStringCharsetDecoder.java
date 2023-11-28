package dev.wobbegong.kmsca.entities.asn1.charsets;

import org.bouncycastle.util.encoders.Hex;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;

public class PrintableStringCharsetDecoder extends CharsetDecoder {

    /**
     * Initializes a new decoder.  The new decoder will have the given
     * chars-per-byte values and its replacement will be the
     * string <code>"&#92;uFFFD"</code>.
     *
     * @param cs                  The charset that created this decoder
     * @throws IllegalArgumentException If the preconditions on the parameters do not hold
     */
    protected PrintableStringCharsetDecoder(Charset cs) {
        super(cs, 1, 1);
    }

    @Override
    protected CoderResult decodeLoop(ByteBuffer in, CharBuffer out) {
        while(in.hasRemaining()) {
            if(!out.hasRemaining()) {
                return CoderResult.OVERFLOW;
            }

            byte b = in.get();
            char nextChar = (char) (b & 0xff);
            if(!PrintableStringCharset.VALID_CHARACTERS.contains(nextChar)) {
                throw new RuntimeException("Illegal byte for PrintableString Charset: " + Hex.toHexString(new byte[]{b}));
            }
            out.put(nextChar);
        }
        return CoderResult.UNDERFLOW;
    }
}
