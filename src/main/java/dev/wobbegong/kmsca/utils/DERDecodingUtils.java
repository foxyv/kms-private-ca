package dev.wobbegong.kmsca.utils;

import dev.wobbegong.kmsca.entities.BitString;
import dev.wobbegong.kmsca.entities.asn1.ASN1Identifier;
import dev.wobbegong.kmsca.entities.asn1.ASN1LengthOctet;
import dev.wobbegong.kmsca.entities.asn1.ASN1TagType;
import dev.wobbegong.kmsca.entities.asn1.charsets.IA5Charset;
import dev.wobbegong.kmsca.entities.asn1.types.ASN1Item;
import dev.wobbegong.kmsca.entities.asn1.types.ASN1Sequence;
import dev.wobbegong.kmsca.entities.asn1.types.ASN1Set;

import java.math.BigInteger;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * DER (Distinguished Encoding Rules) is a restricted variant of BER for producing unequivocal transfer syntax for
 * data structures described by ASN.1. Like CER, DER encodings are valid BER encodings. DER is the same thing as BER
 * with all but one sender's options removed.
 *
 * @see <a href="https://en.wikipedia.org/wiki/X.690">https://en.wikipedia.org/wiki/X.690</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7468">RFC-7468</a>
 * @see <a href="https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-null">Microsoft Documentation on DER</a>
 */
public class DERDecodingUtils {

    private static final List<Pattern> UTC_DATE_PATTERNS;
    private static final Pattern YY_MM_DD_HH_MM_Z = Pattern.compile("(\\d{10})Z");
    private static final Pattern YY_MM_DD_HH_MM_SS_Z = Pattern.compile("(\\d{12})Z");
    private static final Pattern YY_MM_DD_HH_MM_PLUS_HH_MM = Pattern.compile("(\\d{10})\\+(\\d{4})Z");
    private static final Pattern YY_MM_DD_HH_MM_MINUS_HH_MM = Pattern.compile("(\\d{10})-(\\d{4})Z");
    private static final Pattern YY_MM_DD_HH_MM_SS_PLUS_HH_MM = Pattern.compile("(\\d{12})\\+(\\d{4})Z");
    private static final Pattern YY_MM_DD_HH_MM_SS_MINUS_HH_MM = Pattern.compile("(\\d{12})-(\\d{4})Z");

    static {
        UTC_DATE_PATTERNS = new ArrayList<>();
        UTC_DATE_PATTERNS.add(YY_MM_DD_HH_MM_Z);
        UTC_DATE_PATTERNS.add(YY_MM_DD_HH_MM_SS_Z);
        UTC_DATE_PATTERNS.add(YY_MM_DD_HH_MM_PLUS_HH_MM);
        UTC_DATE_PATTERNS.add(YY_MM_DD_HH_MM_MINUS_HH_MM);
        UTC_DATE_PATTERNS.add(YY_MM_DD_HH_MM_SS_PLUS_HH_MM);
        UTC_DATE_PATTERNS.add(YY_MM_DD_HH_MM_SS_MINUS_HH_MM);
    }

    /**
     * 0001 1111 -> 31 -> 1F
     */
    public static final int FIVE_BIT_MASK = 0x1F;


    public static ASN1Item parseNextASN1(ByteBuffer buffer) {
        return parseNextASN1(0, buffer);
    }

    public static ASN1Item parseNextASN1(int offset, ByteBuffer buffer) {
        int start = buffer.position() + offset;
        ASN1Identifier identifier = nextIdentifierFrom(buffer);

        return switch (identifier.tagType()) {
            case SEQUENCE -> parseNextSequence(start, buffer);
            case SET -> parseNextSet(start, buffer);
            default -> {
                byte[] contents = parseNextBytes(buffer);
                yield new ASN1Item(contents.length, start, identifier.tagType(), contents);
            }
        };
    }

    private static byte[] parseNextBytes(ByteBuffer buffer) {
        int length = parseNextLength(buffer).intValueExact();
        byte[] contents = new byte[length];
        buffer.get(contents);
        return contents;
    }


    public static String decodeUTF8(ASN1Item item) {
        return new String(item.contents(), StandardCharsets.UTF_8);
    }

    public static BitString decodeBitString(ASN1Item item) {
        ByteBuffer buffer = ByteBuffer.wrap(item.contents());
        int unusedBits = buffer.get() & 0xff;
        byte[] data = new byte[item.contents().length - 1];
        buffer.get(data);
        return new BitString(unusedBits, data);
    }

    public static Instant decodeUTCTime(ASN1Item item) {
        String utcTimeString = new String(item.contents(), StandardCharsets.UTF_8);
        for (Pattern pattern :
                UTC_DATE_PATTERNS) {
            Matcher matcher = pattern.matcher(utcTimeString);
            if(!matcher.matches()) {
                continue;
            }

            /*
            yymmddhhmmZ yymmddhhmmssZ yymmddhhmm+hhmm yymmddhhmm-hhmm yymmddhhmmss+hhmm yymmddhhmmss-hhmm
             */
            String date = matcher.group(1);
            int year = nearestYearFor(Integer.parseInt(date.substring(0, 2)), ZonedDateTime.now(ZoneId.of("UTC")).getYear());
            int month = Integer.parseInt(date.substring(2, 4));
            int day = Integer.parseInt(date.substring(4, 6));
            int hour = Integer.parseInt(date.substring(6, 8));
            int minute = Integer.parseInt(date.substring(8, 10));
            int second;
            if(date.length() >= 12) {
                second = Integer.parseInt(date.substring(10, 12));
            } else {
                second = 0;
            }

            ZonedDateTime zonedDateTime;
            if(matcher.groupCount() == 2) {
                String offset = matcher.group(2);
                int offsetHour = Integer.parseInt(offset.substring(0, 2));
                int offsetMinute = Integer.parseInt(offset.substring(2, 4));
                ZoneOffset offsetObj = ZoneOffset.ofHoursMinutes(offsetHour, offsetMinute);
                ZoneId zoneID = ZoneId.ofOffset("UTC", offsetObj);
                zonedDateTime = ZonedDateTime.of(year, month, day, hour, minute, second, 0, zoneID);
            } else {
                ZoneId zoneID = ZoneId.of("UTC");
                zonedDateTime = ZonedDateTime.of(year, month, day, hour, minute, second, 0, zoneID);
            }

            return zonedDateTime.toInstant();

        }
        throw new RuntimeException("Cannot parse TIME: " + utcTimeString);
    }

    public static int nearestYearFor(int twoDigitYear, int currentYear) {

        int currentTwoDigitYear = currentYear % 100;

        // Interpret any 2-digit year that matches the bottom two digits of the current year as the current year.
        if(currentTwoDigitYear == twoDigitYear) {
            return currentYear;
        }

        // Get three possible years, the current century, the previous century and the next century.
        int currentCentury = (currentYear / 100 * 100) + twoDigitYear;
        int lastCentury = currentCentury - 100;
        int nextCentury = currentCentury + 100;

        // Find which one is in the +-50 year interval near our current year.
        if(currentCentury >= currentYear - 50 && currentCentury <= currentYear + 50) {
            return currentCentury;
        }

        if(lastCentury >= currentYear - 50 && lastCentury <= currentYear + 50) {
            return lastCentury;
        }

        if(nextCentury >= currentYear - 50 && nextCentury <= currentYear + 50) {
            return nextCentury;
        }

        throw new RuntimeException("Cannot find year for: " + twoDigitYear);
    }

    public static String decodeIA5(ASN1Item item) {
        return new String(item.contents(), IA5Charset.singleton());
    }

    public static BigInteger decodeInteger(ASN1Item item) {
        // DER uses a two's complement integer where the leftmost bit is the sign. This matches Java BigInteger.
        return new BigInteger(item.contents());
    }

    public static String decodeOID(ASN1Item item) {
        ByteBuffer oidBuffer = ByteBuffer.wrap(item.contents());

        // The first two nodes of the OID are encoded onto a single byte. The first node is multiplied by the
        // decimal 40 and the result is added to the value of the second node.
        byte firstByte = oidBuffer.get();
        int arc1 = firstByte / 40;
        int arc2 = firstByte % 40;

        List<Long> nodes = new ArrayList<>();
        nodes.add((long) arc1);
        nodes.add((long) arc2);

        while (oidBuffer.hasRemaining()) {
            nodes.add(parseNextOIDNode(oidBuffer));
        }

        return nodes.stream().map(l -> Long.toString(l)).collect(Collectors.joining("."));
    }

    private static long parseNextOIDNode(ByteBuffer oidBuffer) {

        // Pull up to 6 bytes of 7-bit data. (8-bits minus a "More" bit)
        ByteBuffer buffer = ByteBuffer.allocate(6);
        while (true) {
            if (!buffer.hasRemaining()) {
                throw new RuntimeException("Cannot decode OID. Integer overflow. According to RFC 4181, an OID can only have 4 bytes per digit.");
            }

            byte nextByte = oidBuffer.get();
            buffer.put((byte) (nextByte & 0b0111_1111));

            // Keep pulling bytes until we don't get a "more" bit.
            if (!DERNumberUtils.moreBit(nextByte)) {
                break;
            }
        }
        buffer.flip();
        return DERNumberUtils.oidNumberForBytes(buffer.array(), 0, buffer.remaining()).longValueExact();
    }

    private static ASN1Set parseNextSet(int start, ByteBuffer buffer) {
        int bufferInitialPosition = buffer.position();
        final int length = parseNextLength(buffer).intValueExact();

        if (length < 0) {
            throw new RuntimeException("Unexpected negative length.");
        }

        if (length == 0) {
            return new ASN1Set(0, 0, Collections.emptySet(), new byte[0]);
        }

        if (buffer.remaining() < length) {
            throw new RuntimeException("Not enough bytes remaining for the sequence. Need " + length + " but we only have " + buffer.remaining());
        }

        // Pull the byte data from the buffer for the sequence.
        int bytesRead = buffer.position() - bufferInitialPosition;
        int startOfSetBytes = start + bytesRead;
        byte[] setBytes = new byte[length];
        try {
            buffer.get(setBytes);
        } catch (BufferOverflowException e) {
            throw new RuntimeException("Could not finish parsing sequence bytes. Ran out of bytes in the input buffer. Expected length: " + length);
        }

        // Parse the items inside the sequence
        ByteBuffer setBuffer = ByteBuffer.wrap(setBytes);
        Set<ASN1Item> asn1Itemset = new HashSet<>();
        while (setBuffer.hasRemaining()) {
            int position = startOfSetBytes + setBuffer.position();
            asn1Itemset.add(parseNextASN1(position, setBuffer));
        }

        // Return the sequence
        return new ASN1Set(length, start, asn1Itemset, setBytes);
    }

    private static ASN1Sequence parseNextSequence(int start, ByteBuffer buffer) {
        final int startBufferPosition = buffer.position();
        final int length = parseNextLength(buffer).intValueExact();

        if (length < 0) {
            throw new RuntimeException("Unexpected negative length.");
        }

        if (length == 0) {
            return new ASN1Sequence(length, start, Collections.emptyList(), new byte[0]);
        }

        if (buffer.remaining() < length) {
            throw new RuntimeException("Not enough bytes remaining for the sequence. Need " + length + " but we only have " + buffer.remaining());
        }

        // Pull the byte data from the buffer for the sequence.
        int positionOfSequenceBytesStart = start + (buffer.position() - startBufferPosition);
        byte[] sequenceBytes = new byte[length];
        try {
            buffer.get(sequenceBytes);
        } catch (BufferOverflowException e) {
            throw new RuntimeException("Could not finish parsing sequence bytes. Ran out of bytes in the input buffer. Expected length: " + length);
        }

        // Parse the items inside the sequence
        ByteBuffer sequenceBuffer = ByteBuffer.wrap(sequenceBytes);
        List<ASN1Item> asn1ItemList = new ArrayList<>();
        while (sequenceBuffer.hasRemaining()) {
            int itemStartIndex = positionOfSequenceBytesStart + sequenceBuffer.position();
            asn1ItemList.add(parseNextASN1(itemStartIndex, sequenceBuffer));
        }

        // Return the sequence
        return new ASN1Sequence(length, start, asn1ItemList, sequenceBytes);
    }

    public static BigInteger parseNextLength(ByteBuffer buffer) {
        ASN1LengthOctet lengthOctet = readLengthOctet(buffer);

        final BigInteger length;
        if (lengthOctet.longForm()) {
            if(lengthOctet.lengthOctets() > buffer.remaining()) {
                throw new RuntimeException("Byte buffer does not have " + lengthOctet.lengthOctets() + " bytes remaining. Instead it has: " + buffer.remaining());
            }
            // For length greater than 127 we use a byte array
            byte[] lengthBytes = new byte[lengthOctet.lengthOctets()];
            buffer.get(lengthBytes);
            length = new BigInteger(1, lengthBytes);
        } else {
            length = BigInteger.valueOf(lengthOctet.lengthOctets());
        }
        return length;
    }

    public static ASN1Identifier nextIdentifierFrom(ByteBuffer buffer) {
        byte firstByte = buffer.get();

        // First two bits is the tag class
        ASN1Identifier.TagClass tagClass = ASN1Identifier.TagClass.forValue((firstByte >> 6) & 0b00000011);

        // The third bit is the PC flag
        int primitiveConstructed = (firstByte >> 5) & FIVE_BIT_MASK;

        // The last 5 bits is the tag type
        int tagType = firstByte & FIVE_BIT_MASK;

        return new ASN1Identifier(
                tagClass,
                primitiveConstructed == 0,
                ASN1TagType.fromOrdinal(tagType)
        );
    }

    public static ASN1LengthOctet readLengthOctet(ByteBuffer buffer) {
        int unsignedByte = buffer.get() & 0xff;
        boolean longForm = (unsignedByte >> 7) == 1;
        int lengthOctets = unsignedByte & 0x7F;
        return new ASN1LengthOctet(longForm, lengthOctets);
    }
}
