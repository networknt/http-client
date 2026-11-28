package com.networknt.http.client;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
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

        ByteBuffer bytes = ByteBuffer.allocateDirect(MAX_BYTES + 1);
        char[] chars = new char[MAX_BYTES];
        try {
            // A direct destination avoids the JDK's cached per-thread read buffer.
            try (FileChannel channel = FileChannel.open(Path.of(file))) {
                while (bytes.hasRemaining() && channel.read(bytes) != -1) {
                    // Read up to the limit plus one byte to detect oversized files.
                }
            } catch (IOException | IllegalArgumentException | SecurityException e) {
                throw new IOException("Unable to read TLS password file for " + property
                        + " (" + e.getClass().getSimpleName() + ")");
            }
            if (bytes.position() > MAX_BYTES) {
                throw new IOException("TLS password file exceeds " + MAX_BYTES + " bytes for " + property);
            }
            CharBuffer decoded = CharBuffer.wrap(chars);
            var result = StandardCharsets.UTF_8.newDecoder().decode(bytes.flip(), decoded, true);
            if (result.isError()) {
                throw new IOException("Invalid UTF-8 in TLS password file for " + property);
            }
            return Arrays.copyOf(chars, decoded.position());
        } finally {
            bytes.clear();
            while (bytes.hasRemaining()) {
                bytes.put((byte) 0);
            }
            Arrays.fill(chars, '\0');
        }
    }
}
