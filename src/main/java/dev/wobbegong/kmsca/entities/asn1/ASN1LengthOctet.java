package dev.wobbegong.kmsca.entities.asn1;

public record ASN1LengthOctet(boolean longForm, int lengthOctets) {
    @Override
    public String toString() {
        return "{" +
                "longForm=" + longForm +
                ", lengthOctets=" + lengthOctets +
                '}';
    }
}
