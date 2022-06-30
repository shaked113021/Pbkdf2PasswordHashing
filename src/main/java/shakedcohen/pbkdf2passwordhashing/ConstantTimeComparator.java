package shakedcohen.pbkdf2passwordhashing;

class ConstantTimeComparator {

    private static ConstantTimeComparator instance = null;

    private ConstantTimeComparator() { }

    static ConstantTimeComparator getInstance() {
        if (instance == null) {
            instance = new ConstantTimeComparator();
        }
        return instance;
    }

    boolean secureEquals(byte[] first, byte[] second) {
        int xorBinaryDiff = first.length ^ second.length;

        for (int i = 0; i < first.length && i < second.length; i++) {
            xorBinaryDiff |= first[i] ^ second[i];
        }
        return xorBinaryDiff == 0;
    }
}
