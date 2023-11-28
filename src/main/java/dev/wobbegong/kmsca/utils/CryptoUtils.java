package dev.wobbegong.kmsca.utils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class CryptoUtils {

    public static final SecureRandom SRAND = new SecureRandom();

    /**
     * The size of the initialization vector for AES GCM. This is a constant in the AES GCM specification.
     */
    public static final int GCM_IV_SIZE = 12;

    /**
     * Generate a random AES 256 key.
     * @return The random key.
     */
    public static byte[] randomKey() {
        return randomBytes(32);
    }

    /**
     * Generate a random AES GCM initialization vector.
     * @return The random initialization vector.
     */
    public static byte[] randomIV() {
        return randomBytes(GCM_IV_SIZE);
    }

    /**
     * Generate a random byte array of the specified size.
     * @param size The size of the byte array to generate.
     * @return The random byte array.
     */
    public static byte[] randomBytes(int size) {
        if(size < 0) {
            throw new IllegalArgumentException("Size must be greater than 0.");
        }

        byte[] bytes = new byte[size];
        SRAND.nextBytes(bytes);
        return bytes;
    }

    /**
     * Encrypt data using AES GCM.
     *
     * @param data The data to encrypt.
     * @param key The key to use for encryption.
     * @param iv The initialization vector to use for encryption.
     * @return The encrypted data.
     */
    public static byte[] aesGCMEncrypt(byte[] data, byte[] key, byte[] iv) {
        if(data.length > 2_147_483_390) {
            throw new IllegalArgumentException("Data is too large to encrypt. Max size is 2,147,483,390 bytes.");
        }

        // Create the AESGCM cipher
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("Could not get instance of AES/GCM/NoPadding cipher.", e);
        }

        try {
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Could not initialize cipher using key and initialization vector.", e);
        }

        try {
            return cipher.doFinal(data);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Could not doFinal on the data.", e);
        }
    }

    public static byte[] aesGCMDecrypt(byte[] ciphertext, byte[] key, byte[] iv) {
        // Create the Cipher
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("Could not find an instance of AES/GCM/NoPadding", e);
        }

        // Initialize the Cipher for decryption
        try {
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Invalid key for AES GCM algorithm.", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Invalid initialization vector for AES GCM algorithm.", e);
        }

        // Decrypt the ciphertext
        try {
            return cipher.doFinal(ciphertext);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Could not decrypt ciphertext using key/iv.", e);
        }
    }
}
