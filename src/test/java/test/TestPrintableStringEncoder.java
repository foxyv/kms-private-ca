package test;

import dev.wobbegong.kmsca.entities.asn1.charsets.PrintableStringCharset;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class TestPrintableStringEncoder {
    @Test
    public void test() {
        String allLegalCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 '()+,-./:=?";
        byte[] encoded = allLegalCharacters.getBytes(PrintableStringCharset.singleton());
        String decoded = new String(encoded, PrintableStringCharset.singleton());
        Assertions.assertEquals(allLegalCharacters, decoded);
    }
}
