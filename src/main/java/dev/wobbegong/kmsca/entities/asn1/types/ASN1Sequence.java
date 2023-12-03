package dev.wobbegong.kmsca.entities.asn1.types;

import dev.wobbegong.kmsca.entities.asn1.ASN1TagType;
import dev.wobbegong.kmsca.utils.DEREncodingUtils;

import java.util.List;
import java.util.stream.Collectors;

public class ASN1Sequence extends ASN1Item {

    public final List<ASN1Item> asn1ItemList;

    public ASN1Sequence(int length, int start, List<ASN1Item> asn1ItemList, byte[] contents) {
        super(length, start, ASN1TagType.SEQUENCE, contents);
        this.asn1ItemList = List.copyOf(asn1ItemList);
    }

    public ASN1Sequence(List<ASN1Item> asn1ItemList) {
        super( 0, ASN1TagType.SEQUENCE, DEREncodingUtils.encodeSequenceContents(asn1ItemList));
        this.asn1ItemList = List.copyOf(asn1ItemList);
    }

    @Override
    public String toString() {
        return "[" +
                asn1ItemList.stream().map(Object::toString).collect(Collectors.joining(", ")) +
                "]";

    }
}
