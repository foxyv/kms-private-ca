package dev.wobbegong.kmsca.entities.asn1.charsets;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CoderResult;

public class PrintableStringCharsetEncoder extends CharsetEncoder {



    protected PrintableStringCharsetEncoder(Charset cs) {
        super(cs, 1, 1);
    }

    @Override
    protected CoderResult encodeLoop(CharBuffer in, ByteBuffer out) {
        while(in.hasRemaining()) {
            if(!out.hasRemaining()) {
                return CoderResult.OVERFLOW;
            }
            char nextCharacter = in.get();

            if(PrintableStringCharset.VALID_CHARACTERS.contains(nextCharacter)) {
                out.put((byte) nextCharacter);
            }
        }

        return CoderResult.UNDERFLOW;
    }
}
