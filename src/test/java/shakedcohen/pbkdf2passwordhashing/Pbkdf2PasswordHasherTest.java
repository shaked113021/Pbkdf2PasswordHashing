package shakedcohen.pbkdf2passwordhashing;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class Pbkdf2PasswordHasherTest {

    private static final int HASH_SIZE = 64;
    private static final int SALT_SIZE = 32;
    private static final int ITERATIONS = 5400;

    private static final String FIRST_PASSWORD = "This is a first password. how original";
    private static final String FIRST_PASSWORD_COPY = "This is a first password. how original";
    private static final String SECOND_PASSWORD = "Please don't reuse passwords";
    private static final String THIRD_PASSWORD = "Please don't reuse pazzwords";

    @Test
    public void checkTwoCopies_ShouldVerity() {
        Pbkdf2PasswordHasher pbkdf2PasswordHasher = new Pbkdf2PasswordHasher(HASH_SIZE, SALT_SIZE, ITERATIONS);

        String firstPasswordHash = pbkdf2PasswordHasher.hashPassword(FIRST_PASSWORD);

        assertTrue(pbkdf2PasswordHasher.verifyPassword(FIRST_PASSWORD_COPY, firstPasswordHash));
    }

    @Test
    public void checkTwoCopiesHashUnique_ShouldNotEqual() {
        Pbkdf2PasswordHasher pbkdf2PasswordHasher = new Pbkdf2PasswordHasher(HASH_SIZE, SALT_SIZE, ITERATIONS);

        String firstPasswordHash = pbkdf2PasswordHasher.hashPassword(FIRST_PASSWORD);
        String firstPasswordCopyHash = pbkdf2PasswordHasher.hashPassword(FIRST_PASSWORD_COPY);

        assertNotEquals(firstPasswordHash, firstPasswordCopyHash);
    }

    @Test
    public void checkTwoDifferentLengthsPassword_ShouldNotVerify() {
        Pbkdf2PasswordHasher pbkdf2PasswordHasher = new Pbkdf2PasswordHasher(HASH_SIZE, SALT_SIZE, ITERATIONS);

        String firstPasswordHash = pbkdf2PasswordHasher.hashPassword(FIRST_PASSWORD);

        assertFalse(pbkdf2PasswordHasher.verifyPassword(SECOND_PASSWORD, firstPasswordHash));
    }

    @Test
    public void checkHashLengthsOfDifferentLengthsPasswords_ShouldEqual() {
        Pbkdf2PasswordHasher pbkdf2PasswordHasher = new Pbkdf2PasswordHasher(HASH_SIZE, SALT_SIZE, ITERATIONS);

        String firstPasswordHash = pbkdf2PasswordHasher.hashPassword(FIRST_PASSWORD);
        String secondPasswordHash = pbkdf2PasswordHasher.hashPassword(SECOND_PASSWORD);

        assertEquals(firstPasswordHash.length(), secondPasswordHash.length());
    }

    @Test
    public void checkSameLengthPassword_ShouldNotVerify() {
        Pbkdf2PasswordHasher pbkdf2PasswordHasher = new Pbkdf2PasswordHasher(HASH_SIZE, SALT_SIZE, ITERATIONS);

        String secondPasswordHash = pbkdf2PasswordHasher.hashPassword(SECOND_PASSWORD);

        assertFalse(pbkdf2PasswordHasher.verifyPassword(THIRD_PASSWORD, secondPasswordHash));
    }
}