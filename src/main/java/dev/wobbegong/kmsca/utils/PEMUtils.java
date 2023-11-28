package dev.wobbegong.kmsca.utils;

import dev.wobbegong.kmsca.entities.PEMObject;
import dev.wobbegong.kmsca.exceptions.PEMFormatException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.nio.CharBuffer;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PEMUtils {

    public static final String LINE_SEPARATOR = System.lineSeparator();

    public static final Pattern BEGIN_PEM = Pattern.compile("-----BEGIN ([A-Z0-9 ]+)-----");
    public static final Pattern END_PEM = Pattern.compile("-----END ([A-Z0-9 ]+)-----");
    public static final Pattern BASE_64_REGEX = Pattern.compile("([A-Za-z0-9+/=]+)");

    public static final Pattern PEM_PATTERN = Pattern.compile(
            "-----BEGIN ([A-Z0-9 ]+)-----" + LINE_SEPARATOR +
                    "([A-Za-z0-9+/=\\r\\n]+)" + LINE_SEPARATOR +
                    "-----END ([A-Z0-9 ]+)-----" + LINE_SEPARATOR,
            Pattern.MULTILINE);

    /**
     * @param br The buffered reader to read lines of PEM data from.
     * @return A list of PEM objects, read from the buffered reader.
     * @throws IOException        If there is a problem reading from the buffered reader.
     * @throws PEMFormatException If the data from the BufferedReader is not a valid PEM file.
     */
    public static List<PEMObject> parsePEMs(BufferedReader br) throws IOException, PEMFormatException {
        List<PEMObject> pems = new ArrayList<>();
        PEMObject nextPEM;
        while ((nextPEM = readNextPEM(br)) != null) {
            pems.add(nextPEM);
        }
        return pems;
    }

    public static PEMObject readNextPEM(BufferedReader br) throws IOException, PEMFormatException {
        // Find the start tag
        String pemHeader = readToNextBeginTag(br);
        if (pemHeader == null) {
            return null;
        }

        // Read data until the end tag
        String base64 = readToEndTag(br, pemHeader);

        // Decode the Base64 data inside the tag
        byte[] contents = Base64.getDecoder().decode(base64);
        return new PEMObject(pemHeader, contents);

    }

    private static String readToEndTag(BufferedReader br, String pemHeader) throws IOException, PEMFormatException {
        // Accumulate Base64 data in this string builder.
        StringBuilder base64 = new StringBuilder();

        String nextLine;
        while ((nextLine = br.readLine()) != null) {
            if (nextLine.trim().isEmpty()) {
                throw new PEMFormatException("Blank line between PEM BEGIN and END tags.");
            }

            Matcher endMatcher = END_PEM.matcher(nextLine);
            if (endMatcher.matches()) {
                // Check that the end tag matches the start tag
                if (endMatcher.group(1).contentEquals(pemHeader)) {
                    return base64.toString();
                } else {
                    // EG: Check that END RSA PUBLIC KEY matches the BEGIN RSA PUBLIC KEY
                    throw new PEMFormatException("END tag " + endMatcher.group(1) + " does not match beginning tag " + pemHeader);
                }
            }

            // Match the line to a BASE64 regular expression
            Matcher base64Matcher = BASE_64_REGEX.matcher(nextLine);
            if (base64Matcher.matches()) {
                base64.append(base64Matcher.group(1));
            } else {
                throw new PEMFormatException("Unexpected data in the middle of a PEM.");
            }
        }

        // This happens when we reach the end of the file before finding the END tag.
        throw new PEMFormatException("Un-closed PEM tag. (Or possibly a malformed END tag)");
    }

    /**
     * Keep reading lines until we reach a BEGIN tag. Ignoring any content between PEM items. (Comments, etc...)
     *
     * @param br The buffered reader to read lines from.
     * @return The type of the PEM object showing in the PEM BEGIN tag. EG: BEGIN RSA PUBLIC KEY -> RSA PUBLIC KEY.
     * Or null if we reach the end of the file.
     * @throws IOException If the buffered reader throws an IO exception while reading from it.
     */
    private static String readToNextBeginTag(BufferedReader br) throws IOException {
        String nextLine;
        while ((nextLine = br.readLine()) != null) {
            // Skip empty lines
            if (nextLine.trim().isEmpty()) {
                continue;
            }

            Matcher matcher = BEGIN_PEM.matcher(nextLine);
            if (matcher.matches()) {
                return matcher.group(1);
            }

            // Skip over anything before the "BEGIN" tag. This matches what OpenSSL does.
        }
        // None found.
        return null;
    }

    /**
     * Read a PEM object from String data.
     * @param pem The PEM file as string data.
     * @return A "PEM
     */
    public static List<PEMObject> parsePEMBytes(String pem) throws PEMFormatException {
        try(StringReader sr = new StringReader(pem); BufferedReader br = new BufferedReader(sr)) {
            return parsePEMs(br);
        } catch (IOException e) {
            throw new RuntimeException("Unexpected IO exception throw by StringReader.", e);
        }
    }

    /**
     * Generate a PEM String for the given type and encoded bytes.
     *
     * @param type    The type of the PEM file. EG: RSA PRIVATE KEY
     * @param encoded The encoded bytes to be wrapped in the PEM file. This usually comes from a PrivateKey.getEncoded() call.
     * @return The PEM file as a string.
     */
    public static String pemFor(String type, byte[] encoded) {
        String base64 = Base64.getEncoder().encodeToString(encoded);
        CharBuffer buffer = CharBuffer.wrap(base64);

        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN ").append(type).append("-----").append(LINE_SEPARATOR);
        while (buffer.hasRemaining()) {
            char[] line = new char[Math.min(64, buffer.remaining())];
            buffer.get(line);
            sb.append(line);
            sb.append(LINE_SEPARATOR);
        }
        sb.append("-----END ").append(type).append("-----").append(LINE_SEPARATOR);
        return sb.toString();
    }

}
