package shakedcohen.pbkdf2passwordhashing;

import java.security.SecureRandom;

class RandomNumberSaltGenerator {

    private final int saltSize;
    private final SecureRandom secureRandom;

    public RandomNumberSaltGenerator(int saltSize) {
        this.saltSize = saltSize;
        this.secureRandom = new SecureRandom();
    }

    public byte[] nextSalt() {
        byte[] salt = new byte[this.saltSize];
        this.secureRandom.nextBytes(salt);
        return salt;
    }
}
