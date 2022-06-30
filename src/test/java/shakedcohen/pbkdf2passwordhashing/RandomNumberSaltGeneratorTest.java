package shakedcohen.pbkdf2passwordhashing;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class RandomNumberSaltGeneratorTest {

    public static final int SALT_SIZE = 16;

    @Test
    public void checkSaltIsInLength_ShouldEqualSpecifiedLength() {
        RandomNumberSaltGenerator randomNumberSaltGenerator = new RandomNumberSaltGenerator(SALT_SIZE);

        byte[] salt1 = randomNumberSaltGenerator.nextSalt();
        byte[] salt2 = randomNumberSaltGenerator.nextSalt();

        assertEquals(SALT_SIZE, salt1.length);
        assertEquals(SALT_SIZE, salt2.length);
    }

    @Test
    public void checkTwoSaltsAreDifferent_ShouldNotEqual() {
        RandomNumberSaltGenerator randomNumberSaltGenerator = new RandomNumberSaltGenerator(SALT_SIZE);

        byte[] salt1 = randomNumberSaltGenerator.nextSalt();
        byte[] salt2 = randomNumberSaltGenerator.nextSalt();

        assertFalse(Arrays.equals(salt1, salt2));
    }
}