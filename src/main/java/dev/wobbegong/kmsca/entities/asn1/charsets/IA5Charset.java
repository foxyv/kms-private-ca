package dev.wobbegong.kmsca.entities.asn1.charsets;

import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;

public class IA5Charset extends Charset {
    private static Charset SINGLETON;
    static {
        SINGLETON = new IA5Charset();
    }

    public static Charset singleton() {
        return SINGLETON;
    }

    protected IA5Charset() {
        super("IA5", new String[0]);
    }

    @Override
    public boolean contains(Charset cs) {
        return false;
    }

    @Override
    public CharsetDecoder newDecoder() {
        return new IA5CharsetDecoder(this);
    }

    @Override
    public CharsetEncoder newEncoder() {
        return new IA5CharsetEncoder(this);
    }
}
