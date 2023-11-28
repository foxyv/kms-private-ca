package dev.wobbegong.kmsca.entities.pkcs1;

import java.math.BigInteger;

public record ECPublicKey(ECPoint w, ECParameters parameters, BigInteger n, int h) {
    public record ECPoint(BigInteger x, BigInteger y) {

    }

    /**
     *
     * @param p
     * @param a
     * @param b
     * @param generator AKA: G
     * @param generatorOrder AKA: n
     * @param h
     */
    public record ECParameters(BigInteger p, BigInteger a, BigInteger b, ECPoint generator, BigInteger generatorOrder, BigInteger h) {

    }

    public record EllipticCurve(ECParameters parameters, ECPoint point) {

    }
}
