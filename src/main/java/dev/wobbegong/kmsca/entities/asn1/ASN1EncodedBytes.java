package dev.wobbegong.kmsca.entities.asn1;

import org.bouncycastle.util.encoders.Hex;

public record ASN1EncodedBytes(ASN1Identifier identifier, ASN1LengthOctet lengthOctets, int length, byte[] contents) {
    @Override
    public String toString() {
        return "{ identifier=" + identifier.toString() + ", lengthOctets=" + lengthOctets.toString() + ", length=" + length + ", contents=\"" + Hex.toHexString(contents) + "\" }";
    }
}
