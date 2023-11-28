package dev.wobbegong.kmsca.entities.asn1.charsets;

import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class PrintableStringCharset extends Charset {

    // Mapping of characters
    public static final Set<Character> VALID_CHARACTERS;

    static {
        Set<Character> validCharacters = new HashSet<>();

        for (int i = 'A'; i <= 'Z'; i++) {
            validCharacters.add((char) i);
        }

        for (int i = 'a'; i <= 'z'; i++) {
            validCharacters.add((char) i);
        }

        for (int i = '0'; i <= '9'; i++) {
            validCharacters.add((char) i);
        }

        validCharacters.add(' ');
        validCharacters.add('\'');
        validCharacters.add('(');
        validCharacters.add(')');
        validCharacters.add('+');
        validCharacters.add(',');
        validCharacters.add('-');
        validCharacters.add('.');
        validCharacters.add('/');
        validCharacters.add(':');
        validCharacters.add('=');
        validCharacters.add('?');
        VALID_CHARACTERS = Collections.unmodifiableSet(validCharacters);
    }

    private static final PrintableStringCharset SINGLETON = new PrintableStringCharset();

    public static PrintableStringCharset singleton() {
        return SINGLETON;
    }

    /**
     * Initializes a new charset with the given canonical name and alias
     * set.
     *
     */
    protected PrintableStringCharset() {
        super("ASN1_PRINTABLE_STRING", new String[0]);
    }

    @Override
    public boolean contains(Charset cs) {
        return false;
    }

    @Override
    public CharsetDecoder newDecoder() {
        return new PrintableStringCharsetDecoder(this);
    }

    @Override
    public CharsetEncoder newEncoder() {
        return new PrintableStringCharsetEncoder(this);
    }
}
