package com.networknt.http.client;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

final class TlsPasswordFile {
    private static final int MAX_BYTES = 4096;

    private TlsPasswordFile() {
    }

    /** Returns an owned buffer. The caller must wipe it after the TLS provider call. */
    static char[] read(String file, String property) throws IOException {
        if (file.isBlank()) {
            throw new IOException("Missing TLS password file path for " + property);
        }

        byte[] bytes = new byte[MAX_BYTES + 1];
        char[] chars = new char[MAX_BYTES];
        try {
            int length;
            try (InputStream input = Files.newInputStream(Path.of(file))) {
                length = input.readNBytes(bytes, 0, bytes.length);
            }
            if (length > MAX_BYTES) {
                throw new IOException("TLS password file exceeds size limit for " + property);
            }
            CharBuffer decoded = CharBuffer.wrap(chars);
            var decoder = StandardCharsets.UTF_8.newDecoder();
            var result = decoder.decode(ByteBuffer.wrap(bytes, 0, length), decoded, true);
            if (result.isError()) {
                result.throwException();
            }
            return Arrays.copyOf(chars, decoded.position());
        } catch (IOException | IllegalArgumentException | SecurityException e) {
            throw new IOException("Unable to read TLS password file for " + property);
        } finally {
            Arrays.fill(bytes, (byte) 0);
            Arrays.fill(chars, '\0');
        }
    }
}
