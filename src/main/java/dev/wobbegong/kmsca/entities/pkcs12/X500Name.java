package dev.wobbegong.kmsca.entities.pkcs12;

import java.util.Map;

/**
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc1779">RFC-1779</a>
 * @param oidValues A map of OIDs and their corresponding values. EG: Country Name, Org Name, Common Name, etc...
 */
public record X500Name(Map<String, String> oidValues) {

}
