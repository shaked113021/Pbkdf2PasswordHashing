package shakedcohen.pbkdf2passwordhashing;

class SaltExtractor {

    private final int saltSize;

    SaltExtractor(int saltSize) {
        this.saltSize = saltSize;
    }

    byte[] extractSalt(byte[] hashAndSalt) {
        byte[] salt = new byte[saltSize];
        System.arraycopy(hashAndSalt, 0, salt, 0, saltSize);

        return salt;
    }
}
