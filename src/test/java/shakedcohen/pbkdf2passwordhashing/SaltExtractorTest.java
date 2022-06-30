package shakedcohen.pbkdf2passwordhashing;

import org.junit.jupiter.api.Test;

import java.nio.charset.Charset;

import static org.junit.jupiter.api.Assertions.*;

class SaltExtractorTest {

    @Test
    public void extractSaltFromHash_ShouldBeEqual() {
        String salt = "blahblahblah";
        String hash = "sosoksod";

        byte[] saltBytes = salt.getBytes(Charset.defaultCharset());
        SaltExtractor saltExtractor = new SaltExtractor(saltBytes.length);

        byte[] hashAndSalt = salt.concat(hash).getBytes(Charset.defaultCharset());

        byte[] extractedSalt = saltExtractor.extractSalt(hashAndSalt);
        assertArrayEquals(saltBytes, extractedSalt);
    }

}