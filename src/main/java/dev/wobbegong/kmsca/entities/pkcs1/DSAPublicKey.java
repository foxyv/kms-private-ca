package dev.wobbegong.kmsca.entities.pkcs1;

import java.math.BigInteger;

/**
 * @param y The public integer for the DSA key.
 */
public record DSAPublicKey(BigInteger y) {

}
