package shakedcohen.pbkdf2passwordhashing;

import org.jetbrains.annotations.NotNull;

public interface PasswordHasher {

    /**
     * Hashes the password using the hashing algorithm
     * @param password the provided password
     * @return hash of the password encoded in base64
     */
    String hashPassword(@NotNull String password);

    /**
     * verifies the password against the hashed with salt password
     * @param passwordCandidate password to verify
     * @param hashedPassword stored hash of the correct password
     * @return true if passwordCandidate matches the original password, false otherwise
     */
    boolean verifyPassword(@NotNull String passwordCandidate, @NotNull String hashedPassword);
}
