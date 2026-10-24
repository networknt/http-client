package com.networknt.http.client;

import org.junit.jupiter.api.Test;
import tools.jackson.core.StreamWriteFeature;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.SerializationFeature;
import static org.junit.jupiter.api.Assertions.*;

/** The shared profile is frozen in config; this test verifies HTTP-specific overrides. */
class Jackson2FeatureDefaultsTest {
    @Test
    void retainsHttpOverridesOnSharedCompatibilityProfile() {
        var mapper = JsonMapper.objectMapper;
        assertFalse(mapper.isEnabled(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES));
        assertFalse(mapper.isEnabled(SerializationFeature.FAIL_ON_EMPTY_BEANS));
        assertTrue(mapper.isEnabled(StreamWriteFeature.WRITE_BIGDECIMAL_AS_PLAIN));
        assertEquals(1000, mapper.tokenStreamFactory().streamReadConstraints().getMaxNestingDepth());
        assertEquals(20_000_000, mapper.tokenStreamFactory().streamReadConstraints().getMaxStringLength());
        String nested = "[".repeat(600) + "0" + "]".repeat(600);
        assertEquals(nested, mapper.writeValueAsString(mapper.readTree(nested)));
    }
}
