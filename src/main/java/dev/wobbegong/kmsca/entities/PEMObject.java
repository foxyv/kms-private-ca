package dev.wobbegong.kmsca.entities;

/**
 * @param type    The type of the PEM object as specified in it's BEGIN and END tags. EG: BEGIN RSA PUBLIC KEY -> RSA PUBLIC KEY.
 * @param content The decoded Base64 data from the PEM contents.
 */
public record PEMObject(String type, byte[] content) {

}
