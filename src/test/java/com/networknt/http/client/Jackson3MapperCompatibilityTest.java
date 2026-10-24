package com.networknt.http.client;

import java.math.BigDecimal;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

import static org.junit.jupiter.api.Assertions.*;

class Jackson3MapperCompatibilityTest {
    public static class Bean {
        public String z = "z";
        public String a = "a";
        public String absent;
        public int number = 7;
        private final List<String> list = new ArrayList<>();
        private final Map<String, String> map = new LinkedHashMap<>();
        public List<String> getList() { return list; }
        public Map<String, String> getMap() { return map; }
    }
    public static class Empty { }

    private List<ObjectMapper> mappers() {
        return List.of(JsonMapper.objectMapper);
    }

    @Test
    void retainsNullPrimitiveTrailingTokenAndGetterCollectionBinding() {
        for (ObjectMapper mapper : mappers()) {
            assertEquals(0, mapper.readValue("{\"number\":null}", Bean.class).number);
            assertEquals(7, mapper.readValue("{} {}", Bean.class).number);
            Bean bean = mapper.readValue("{\"list\":[\"x\"],\"map\":{\"k\":\"v\"}}", Bean.class);
            assertEquals(List.of("x"), bean.getList());
            assertEquals(Map.of("k", "v"), bean.getMap());
        }
    }

    @Test
    void retainsTemporalAndDecimalOutputWithBuiltInOptionalSupport() {
        for (ObjectMapper mapper : mappers()) {
            assertEquals("0.0", mapper.writeValueAsString(Instant.EPOCH));
            assertEquals("[2026,10,24]", mapper.writeValueAsString(LocalDate.of(2026, 10, 24)));
            assertEquals("90.000000000", mapper.writeValueAsString(Duration.ofSeconds(90)));
            assertEquals("\"x\"", mapper.writeValueAsString(Optional.of("x")));
        }
        assertEquals("1000000", JsonMapper.objectMapper.writeValueAsString(new BigDecimal("1E+6")));
    }

    @Test
    void retainsPropertyOrderAndSeparateNullInclusionPolicies() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("absent", null);
        assertEquals("{}", JsonMapper.objectMapper.writeValueAsString(map));
        assertEquals("{\"z\":\"z\",\"a\":\"a\",\"number\":7,\"list\":[],\"map\":{}}",
                JsonMapper.objectMapper.writeValueAsString(new Bean()));
    }

    @Test
    void retainsHelperErrorWrappingForUncheckedJacksonFailures() {
        RuntimeException error = assertThrows(RuntimeException.class, () -> JsonMapper.fromJson("{no}", Bean.class));
        assertInstanceOf(JacksonException.class, error.getCause());
        assertInstanceOf(JacksonException.class,
                assertThrows(RuntimeException.class, () -> JsonMapper.string2Map("{no}")).getCause());
        assertInstanceOf(JacksonException.class,
                assertThrows(RuntimeException.class, () -> JsonMapper.string2List("[no]")).getCause());
    }
}
