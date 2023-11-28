package dev.wobbegong.kmsca.entities.oid;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@SuppressWarnings("unused")
public enum KnownOids {
    objectClass("2.5.4.0", "Object classes"),
    aliasedEntryName("2.5.4.1", "Attribute type Aliased entry name"),
    knowledgeInformation("2.5.4.2", "knowledgeInformation attribute type"),
    commonName("2.5.4.3", "Common name"),
    surname("2.5.4.4", "Attribute surname"),
    serialNumber("2.5.4.5", "Serial number attribute type"),
    countryName("2.5.4.6", "Country name"),
    localityName("2.5.4.7", "Locality Name"),
    stateOrProvinceName("2.5.4.8", "State or Province name"),
    streetAddress("2.5.4.9", "Street address"),
    organizationName("2.5.4.10", "Organization name"),
    organizationUnitName("2.5.4.11", "Organization unit name"),
    title("2.5.4.12", "Title attribute type"),
    description("2.5.4.13", "Description attribute type"),
    searchGuide("2.5.4.14", "Search guide attribute type"),
    businessCategory("2.5.4.15", "Business category attribute type"),
    postalAddress("2.5.4.16", "Postal address attribute type"),
    postalCode("2.5.4.17", "Postal code attribute type"),
    postOfficeBox("2.5.4.18", "Post office box attribute type"),
    physicalDeliveryOfficeName("2.5.4.19", "physicalDeliveryOfficeName attribute type"),
    telephoneNumber("2.5.4.20", "Telephone number attribute type"),
    telexNumber("2.5.4.21", "Telex number attribute type"),
    teletexTerminalIdentifier("2.5.4.22", "Teletex terminal identifier attribute type"),
    facsimileTelephoneNumber("2.5.4.23", "Facsimile telephone number attribute type"),
    x121Address("2.5.4.24", "X121 address attribute type"),
    internationalISDNNumber("2.5.4.25", "International ISDN (Integrated Services Digital Network) number attribute type"),
    registeredAddress("2.5.4.26", "Registered address attribute type"),
    destinationIndicator("2.5.4.27", "Destination indicator attribute type"),
    preferredDeliveryMethod("2.5.4.28", "Preferred delivery method attribute type"),
    presentationAddress("2.5.4.29", "Presentation address attribute type"),
    supportedApplicationContext("2.5.4.30", "Supported application context attribute type"),
    member("2.5.4.31", "Member attribute type"),
    owner("2.5.4.32", "Owner attribute type"),
    roleOccupant("2.5.4.33", "Role occupant attribute type"),
    seeAlso("2.5.4.34", "seeAlso attribute type"),
    userPassword("2.5.4.35", "userPassword attribute type"),
    userCertificate("2.5.4.36", "userCertificate attribute type"),
    cACertificate("2.5.4.37", "cAcertificate attribute type"),
    authorityRevocationList("2.5.4.38", "authorityRevocationList attribute type"),
    certificateRevocationList("2.5.4.39", "certificateRevocationList attribute type"),
    crossCertificatePair("2.5.4.40", "crossCertificatePair attribute type"),
    name("2.5.4.41", "Name attribute type"),
    givenName("2.5.4.42", "Given name attribute type"),
    initials("2.5.4.43", "Initials attribute type"),
    generationQualifier("2.5.4.44", "generationQualifier attribute type"),
    uniqueIdentifier("2.5.4.45", "uniqueIdentifier attribute type"),
    dnQualifier("2.5.4.46", "dnQualifier attribute type"),
    enhancedSearchGuide("2.5.4.47", "enhancedSearchGuide attribute type"),
    protocolInformation("2.5.4.48", "protocolInformation attribute type"),
    distinguishedName("2.5.4.49", "distinguishedName attribute type"),
    uniqueMember("2.5.4.50", "uniqueMember attribute type"),
    houseIdentifier("2.5.4.51", "houseIdentifier attribute type"),
    supportedAlgorithms("2.5.4.52", "supportedAlgorithms attribute type"),
    deltaRevocationList("2.5.4.53", "deltaRevocationList attribute type"),
    dmdName("2.5.4.54", "DMD Name attribute type"),
    clearance("2.5.4.55", "Attribute type \"Clearance\""),
    defaultDirQop("2.5.4.56", "Attribute type \"Default Dir Qop\""),
    attributeIntegrityInfo("2.5.4.57", "Attribute type \"Attribute integrity info\""),
    attributeCertificate("2.5.4.58", "attributeCertificate attribute type"),
    attributeCertificateRevocationList("2.5.4.59", "attributeCertificateRevocationList attribute type"),
    confKeyInfo("2.5.4.60", "Attribute type \"Conf key info\""),
    aACertificate("2.5.4.61", "aACertificate attribute type"),
    attributeDescriptorCertificate("2.5.4.62", "attributeDescriptorCertificate attribute type"),
    attributeAuthorityRevocationList("2.5.4.63", "attributeAuthorityRevocationList attribute type"),
    family_information("2.5.4.64", "Family-information attribute type"),
    pseudonym("2.5.4.65", "Pseudonym attribute type"),
    communicationsService("2.5.4.66", "communicationsService attribute type"),
    communicationsNetwork("2.5.4.67", "communicationsNetwork attribute type"),
    certificationPracticeStmt("2.5.4.68", "certificationPracticeStmt attribute type (Certification practice statement attribute)"),
    certificatePolicy("2.5.4.69", "certificatePolicy attribute type"),
    pkiPath("2.5.4.70", "pkiPath attribute type"),
    privPolicy("2.5.4.71", "privPolicy attribute type"),
    role("2.5.4.72", "role attribute type"),
    delegationPath("2.5.4.73", "delegationPath attribute type"),
    xmlPrivPolicy("2.5.4.76", "None"),
    uuidpair("2.5.4.77", "uUIDPair"),

    // ANSI X9.62 standard (1998) "Public Key Cryptography for the Financial Services Industry: The Elliptic Curve Digital Signature Algorithm (ECDSA)"
    // Public key types
    ecPublicKey("1.2.840.10045.2.1", "Elliptic curve public key cryptography"),
    dsa("1.2.840.10040.4.1", "Digital Signature Algorithm (DSA) subject public key"),

    // Named Curves
    characteristicTwo("1.2.840.10045.3.0", "Characteristic two curve"),
    c2pnb163v1("1.2.840.10045.3.0.1", "PNB 163 V1"),
    c2pnb163v2("1.2.840.10045.3.0.2", "PNB 163 V2"),
    c2pnb163v3("1.2.840.10045.3.0.3", "PNB 163 V3"),
    c2pnb176w1("1.2.840.10045.3.0.4", "PNB 176 W1"),
    c2tnb191v1("1.2.840.10045.3.0.5", "TNB 191 V1"),
    c2tnb191v2("1.2.840.10045.3.0.6", "TNB 191 V2"),
    c2tnb191v3("1.2.840.10045.3.0.7", "TNB 191 V3"),
    c2onb191v4("1.2.840.10045.3.0.8", "ONB 191 V4"),
    c2onb191v5("1.2.840.10045.3.0.9", "ONB 191 V5"),
    c2pnb208w1("1.2.840.10045.3.0.10", "PNB 208 W1"),
    c2tnb239v1("1.2.840.10045.3.0.11", "TNB 239 V1"),
    c2tnb239v2("1.2.840.10045.3.0.12", "TNB 239 V2"),
    c2tnb239v3("1.2.840.10045.3.0.13", "TNB 239 V3"),
    c2onb239v4("1.2.840.10045.3.0.14", "ONB 239 V4"),
    c2onb239v5("1.2.840.10045.3.0.15", "ONB 239 V5"),
    c2pnb272W1("1.2.840.10045.3.0.16", "PNB 272 W1"),
    c2pnb304W1("1.2.840.10045.3.0.17", "PNB 304 W1"),
    c2tnb359v1("1.2.840.10045.3.0.18", "TNB 359 V1"),
    c2pnb368w1("1.2.840.10045.3.0.19", "PNB 368 W1"),
    c2tnb431r1("1.2.840.10045.3.0.20", "TNB 431 R1"),


    primeCurve("1.2.840.10045.3.1", "Prime curve "),
    prime192v1("1.2.840.10045.3.1.1", "Elliptic curve domain \"secp192r1\" listed in \"SEC 2\" recommended elliptic curve domain"),
    prime192v2("1.2.840.10045.3.1.2", "Prime 192 V2"),
    prime192v3("1.2.840.10045.3.1.3", "Prime 192 V3"),
    prime239v1("1.2.840.10045.3.1.4", "Prime 239 V1"),
    prime239v2("1.2.840.10045.3.1.5", "Prime 239 V2"),
    prime239v3("1.2.840.10045.3.1.6", "Prime 239 V3"),
    prime256v1("1.2.840.10045.3.1.7", "256 bit elliptic curve (szOID_ECC_CURVE_P256)"),

    secgCurve("1.3.132.0", "secgCurve"),
    ansit163k1("1.3.132.0.1", "\"SEC 2\" recommended elliptic curve domain - sect163k1"),
    ansit163r1("1.3.132.0.2", "\"SEC 2\" recommended elliptic curve domain - sect163r1"),
    ansit239k1("1.3.132.0.3", "\"SEC 2\" recommended elliptic curve domain - sect239k1"),
    sect113r1("1.3.132.0.4", "\"SEC 2\" recommended elliptic curve domain - sect113r1"),
    sect113r2("1.3.132.0.5", "\"SEC 2\" recommended elliptic curve domain - sect113r2"),
    secp112r1("1.3.132.0.6", "\"SEC 2\" recommended elliptic curve domain - secp112r1"),
    secp112r2("1.3.132.0.7", "\"SEC 2\" recommended elliptic curve domain - secp112r2"),
    ansip160r1("1.3.132.0.8", "\"SEC 2\" recommended elliptic curve domain - secp160r1"),
    ansip160k1("1.3.132.0.9", "\"SEC 2\" recommended elliptic curve domain - secp160k1"),
    ansip256k1("1.3.132.0.10", "\"SEC 2\" recommended elliptic curve domain - secp256k1"),
    ansit163r2("1.3.132.0.15", "\"SEC 2\" recommended elliptic curve domain - sect163r2"),
    ansit283k1("1.3.132.0.16", "\"SEC 2\" recommended elliptic curve domain - sect283k1"),
    ansit283r1("1.3.132.0.17", "\"SEC 2\" recommended elliptic curve domain - sect283r1"),
    sect131r1("1.3.132.0.22", "\"SEC 2\" recommended elliptic curve domain - sect131r1"),
    sect131r2("1.3.132.0.23", "\"SEC 2\" recommended elliptic curve domain - sect131r2"),
    ansit193r1("1.3.132.0.24", "\"SEC 2\" recommended elliptic curve domain - sect193r1"),
    ansit193r2("1.3.132.0.25", "\"SEC 2\" recommended elliptic curve domain - sect193r2"),
    ansit233k1("1.3.132.0.26", "\"SEC 2\" recommended elliptic curve domain - sect233k1"),
    ansit233r1("1.3.132.0.27", "\"SEC 2\" recommended elliptic curve domain - sect233r1"),
    secp128r1("1.3.132.0.28", "\"SEC 2\" recommended elliptic curve domain"),
    secp128r2("1.3.132.0.29", "\"SEC 2\" recommended elliptic curve domain - secp128r2"),
    ansip160r2("1.3.132.0.30", "\"SEC 2\" recommended elliptic curve domain - secp160r2"),
    ansip192k1("1.3.132.0.31", "\"SEC 2\" recommended elliptic curve domain - secp192k1"),
    ansip224k1("1.3.132.0.32", "\"SEC 2\" recommended elliptic curve domain - secp224k1"),
    ansip224r1("1.3.132.0.33", "\"SEC 2\" recommended elliptic curve domain - secp224r1"),
    ansip384r1("1.3.132.0.34", "National Institute of Standards and Technology (NIST) 384-bit elliptic curve"),
    ansip521r1("1.3.132.0.35", "National Institute of Standards and Technology (NIST) 512-bit elliptic curve"),
    ansit409k1("1.3.132.0.36", "\"SEC 2\" recommended elliptic curve domain - sect409k1"),
    ansit409r1("1.3.132.0.37", "\"SEC 2\" recommended elliptic curve domain - sect409r1"),
    ansit571k1("1.3.132.0.38", "\"SEC 2\" recommended elliptic curve domain - sect571k1"),
    ansit571r1("1.3.132.0.39", "\"SEC 2\" recommended elliptic curve domain - sect571r1"),

    // Signing algorithms
    rsaEncryption("1.2.840.113549.1.1.1", "Rivest, Shamir and Adleman (RSA) encryption (and signing)"),
    md2WithRSAEncryption("1.2.840.113549.1.1.2", "Message Digest 2 (MD2) checksum with Rivest, Shamir and Adleman (RSA) encryption"),
    md4withRSAEncryption("1.2.840.113549.1.1.3", "Message Digest 4 (MD4) checksum with Rivest, Shamir and Adleman (RSA) encryption"),
    md5WithRSAEncryption("1.2.840.113549.1.1.4", "Rivest, Shamir and Adleman (RSA) encryption with Message Digest 5 (MD5) signature"),
    sha1_with_rsa_signature("1.2.840.113549.1.1.5", "Rivest, Shamir and Adleman (RSA) with Secure Hash Algorithm (SHA-1) signature"),
    rsaOAEPEncryptionSET("1.2.840.113549.1.1.6", "Rivest, Shamir and Adleman (RSA) Optimal Asymmetric Encryption Padding (OAEP) encryption set"),
    id_RSAES_OAEP("1.2.840.113549.1.1.7", "Public-key encryption scheme combining Optimal Asymmetric Encryption Padding (OAEP) with the Rivest, Shamir and Adleman Encrypt"),
    id_mgf1("1.2.840.113549.1.1.8", "Rivest, Shamir and Adleman (RSA) algorithm that uses the Mask Generator Function 1 (MGF1)"),
    id_pSpecified("1.2.840.113549.1.1.9", "Rivest, Shamir and Adleman (RSA) algorithm (szOID_RSA_PSPECIFIED)"),
    rsassa_pss("1.2.840.113549.1.1.10", "Rivest, Shamir, Adleman (RSA) Signature Scheme with Appendix - Probabilistic Signature Scheme (RSASSA-PSS)"),
    sha256WithRSAEncryption("1.2.840.113549.1.1.11", "Secure Hash Algorithm 256 (SHA256) with Rivest, Shamir and Adleman (RSA) encryption"),
    sha384WithRSAEncryption("1.2.840.113549.1.1.12", "Secure Hash Algorithm 384 (SHA384) with Rivest, Shamir and Adleman (RSA) Encryption"),
    sha512WithRSAEncryption("1.2.840.113549.1.1.13", "Secure Hash Algorithm (SHA) 512 with Rivest, Shamir and Adleman (RSA) encryption"),
    sha224WithRSAEncryption("1.2.840.113549.1.1.14", "Secure Hash Algorithm (SHA) 224 with Rivest, Shamir and Adleman (RSA) encryption"),
    ecdsa_with_SHA1("1.2.840.10045.4.1", "ANSI X9.62 Elliptic Curve Digital Signature Algorithm (ECDSA) coupled with the Secure Hash Algorithm (SHA) 1 algorithm"),
    ecdsa_with_Recommended("1.2.840.10045.4.2", "ANSI X9.62 EC-DSA algorithm with Recommended"),
    ecdsa_with_SHA224("1.2.840.10045.4.3.1", "ECDSA with SHA-224 signature values"),
    ecdsa_with_SHA256("1.2.840.10045.4.3.2", "Elliptic Curve Digital Signature Algorithm (DSA) coupled with the Secure Hash Algorithm 256 (SHA256) algorithm"),
    ecdsa_with_SHA384("1.2.840.10045.4.3.3", "Elliptic curve Digital Signature Algorithm (DSA) coupled with the Secure Hash Algorithm 384 (SHA384) algorithm"),
    ecdsa_with_SHA512("1.2.840.10045.4.3.4", "Elliptic curve Digital Signature Algorithm (DSA) coupled with the Secure Hash Algorithm 512 (SHA512) algorithm"),

    // ORG
    jurisdictionOfIncorporationLocalityName("1.3.6.1.4.1.311.60.2.1.1", "Jurisdiction Locality Name"),
    jurisdictionOfIncorporationStateOrProvinceName("1.3.6.1.4.1.311.60.2.1.2", "Jurisdiction State or Province Name"),
    jurisdictionOfIncorporationCountryName("1.3.6.1.4.1.311.60.2.1.3", "Jurisdiction Country Name"),

    // PKCS 9 Email OID
    pkcs_9_email("1.2.840.113549.1.9.1", "PKCS #9 Email Address attribute for use in signatures "),
    ;
    public final String oid;
    public final String desc;

    KnownOids(String oid, String desc) {
        this.oid = oid;
        this.desc = desc;
    }

    private static Map<String, KnownOids> MAP;

    static {
        MAP = Arrays.stream(KnownOids.values()).collect(Collectors.toMap(
                v -> v.oid,
                v -> v
        ));
    }

    public static Optional<KnownOids> forOID(String oid) {
        return Optional.ofNullable(MAP.get(oid));
    }
}
