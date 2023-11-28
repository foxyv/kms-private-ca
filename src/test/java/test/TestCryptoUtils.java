package test;

import dev.wobbegong.kmsca.utils.CryptoUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class TestCryptoUtils {
    @Test
    public void test() {
        byte[] key = CryptoUtils.randomKey();
        byte[] iv = CryptoUtils.randomIV();
        byte[] data = CryptoUtils.randomBytes(3200);

        byte[] ciphertext = CryptoUtils.aesGCMEncrypt(data, key, iv);
        Assertions.assertNotNull(ciphertext);

        byte[] plaintext = CryptoUtils.aesGCMDecrypt(ciphertext, key, iv);
        Assertions.assertNotNull(plaintext);
        Assertions.assertArrayEquals(data, plaintext);

    }
}
