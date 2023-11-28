package dev.wobbegong.kmsca.entities;

/**
 * Represents an encrypted key. Safe to be stored or transmitted. Requires access to the CA root key in KMS to decrypt.
 *
 * @param kmsEncryptedAESKey The secret encrypted with the AWS KMS Master Key. Used to generate the AES256 key when decrypting the private key.
 * @param iv The initialization vector used to encrypt the private key.
 * @param privateKey The private key encrypted with the encrypted key.
 */
public record EncryptedPrivateKey(String kmsEncryptedAESKey, byte[] iv, String privateKey) {

}
