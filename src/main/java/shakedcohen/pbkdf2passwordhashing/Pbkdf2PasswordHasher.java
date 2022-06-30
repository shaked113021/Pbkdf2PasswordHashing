package shakedcohen.pbkdf2passwordhashing;

import org.jetbrains.annotations.NotNull;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import static shakedcohen.pbkdf2passwordhashing.PasswordHashingConstants.BITS_IN_A_BYTE;
import static shakedcohen.pbkdf2passwordhashing.PasswordHashingConstants.PBKDF2_ALGORITHM;

public class Pbkdf2PasswordHasher implements PasswordHasher {

    private final int hashSize;
    private final int iterations;
    private final int saltSize;
    private final SecretKeyFactory pbkdf2HashAlgorithm;
    private final RandomNumberSaltGenerator randomNumberSaltGenerator;
    private final SaltExtractor saltExtractor;

    public Pbkdf2PasswordHasher(final int hashSize, final int saltSize, final int iterations) {
        this.hashSize = hashSize;
        this.iterations = iterations;
        this.saltSize = saltSize;
        this.pbkdf2HashAlgorithm = getPbkdf2HashAlgorithmFromFactory();
        this.randomNumberSaltGenerator = new RandomNumberSaltGenerator(saltSize);
        this.saltExtractor = new SaltExtractor(saltSize);
    }

    @Override
    public final String hashPassword(@NotNull final String password) {
        byte[] salt = randomNumberSaltGenerator.nextSalt();
        byte[] hashedPassword = innerPasswordHash(password, salt);

        return Base64.getEncoder().encodeToString(hashedPassword);
    }

    @Override
    public final boolean verifyPassword(@NotNull final String passwordCandidate, @NotNull final String hashedPassword) {
        byte[] hashedPasswordBytes = Base64.getDecoder().decode(hashedPassword);

        byte[] salt = saltExtractor.extractSalt(hashedPasswordBytes);
        byte[] hashedCandidate = innerPasswordHash(passwordCandidate, salt);
        return ConstantTimeComparator.getInstance().secureEquals(hashedCandidate, hashedPasswordBytes);
    }

    private byte[] innerPasswordHash(@NotNull final String password, byte[] salt) {
        try {
            PBEKeySpec passwordKeyspec = new PBEKeySpec(password.toCharArray(), salt, this.iterations, this.hashSize * BITS_IN_A_BYTE);
            byte[] hash = this.pbkdf2HashAlgorithm.generateSecret(passwordKeyspec).getEncoded();

            byte[] hashAndSalt = new byte[this.saltSize + this.hashSize];
            System.arraycopy(salt, 0, hashAndSalt, 0, this.saltSize);
            System.arraycopy(hash, 0, hashAndSalt, this.saltSize, this.hashSize);

            return hashAndSalt;
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private SecretKeyFactory getPbkdf2HashAlgorithmFromFactory() {
        try {
            return SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
