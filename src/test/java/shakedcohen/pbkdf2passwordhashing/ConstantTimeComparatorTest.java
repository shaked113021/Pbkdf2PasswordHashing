package shakedcohen.pbkdf2passwordhashing;

import org.junit.jupiter.api.Test;

import java.nio.charset.Charset;

import static org.junit.jupiter.api.Assertions.*;

class ConstantTimeComparatorTest {
    private final static byte[] FIRST_CANDIDATE = "This is first hash".getBytes(Charset.defaultCharset());
    private final static byte[] FIRST_CANDIDATE_COPY = "This is first hash".getBytes(Charset.defaultCharset());
    private final static byte[] SECOND_CANDIDATE = "This is flrst hash".getBytes(Charset.defaultCharset());
    private final static byte[] THIRD_CANDIDATE = "This is a very long hash for such a password".getBytes(Charset.defaultCharset());

    @Test
    public void compareCopies_ShouldBeTrue() {
        assertTrue(ConstantTimeComparator.getInstance().secureEquals(FIRST_CANDIDATE, FIRST_CANDIDATE_COPY));
    }

    @Test
    public void compareHashesWithSameLengths_ShouldBeFalse() {
        assertFalse(ConstantTimeComparator.getInstance().secureEquals(FIRST_CANDIDATE, SECOND_CANDIDATE));
    }

    @Test
    public void compareHashesWithDifferentLengths_ShouldBeFalse() {
        assertFalse(ConstantTimeComparator.getInstance().secureEquals(FIRST_CANDIDATE, THIRD_CANDIDATE));
    }
}