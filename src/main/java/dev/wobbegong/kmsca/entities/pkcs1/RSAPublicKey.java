package dev.wobbegong.kmsca.entities.pkcs1;

import java.math.BigInteger;

/**
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc3447#appendix-A.1.1">RFC-3447</a>
 * @param modulus
 * @param publicExponent
 */
public record RSAPublicKey(BigInteger modulus, BigInteger publicExponent) {

}
