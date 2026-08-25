package au.gov.nehta.common.utils;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Collections;
import java.util.List;
import org.junit.Test;

public class ArgumentUtilsTest {

    @Test
    public void isNullOrBlank_treatsNullEmptyAndWhitespaceAsBlank() {
        assertTrue(ArgumentUtils.isNullOrBlank(null));
        assertTrue(ArgumentUtils.isNullOrBlank(""));
        assertTrue(ArgumentUtils.isNullOrBlank("   "));
        assertFalse(ArgumentUtils.isNullOrBlank("a"));
    }

    @Test
    public void isNullOrEmpty_treatsNullAndEmptyCollection() {
        assertTrue(ArgumentUtils.isNullOrEmpty(null));
        assertTrue(ArgumentUtils.isNullOrEmpty(Collections.emptyList()));
        assertFalse(ArgumentUtils.isNullOrEmpty(List.of("x")));
    }

    @Test
    public void isEqual_matchesObjectsEqualsSemantics() {
        assertTrue(ArgumentUtils.isEqual(null, null));
        assertFalse(ArgumentUtils.isEqual(null, "a"));
        assertTrue(ArgumentUtils.isEqual("a", "a"));
    }
}
