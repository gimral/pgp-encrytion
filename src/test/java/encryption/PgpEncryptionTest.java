package encryption;

import org.bouncycastle.openpgp.PGPException;
import org.junit.Test;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Random;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class PgpEncryptionTest {

//    @Test
//    public void testEncryption() throws PGPException, IOException {
/////Users/gokhanimral/Projects/pgp-encrytion/keys/app2_public.pgp
//        PgpEncrytion pgpEncrytion = new PgpEncrytion();
//        String[] keyPaths = new String[] { "/Users/gokhanimral/Projects/pgp-encrytion/keys/app2_public.pgp",
//                "/Users/gokhanimral/Projects/pgp-encrytion/keys/app1_public.pgp"};;
//        String encryptedValue  = pgpEncrytion.encryptData("testData", keyPaths);
//
//        String decryptedNppValue = pgpEncrytion.decryptData(encryptedValue, "/Users/gokhanimral/Projects/pgp-encrytion/keys/app2_private.pgp");
//        String decryptedGtValue = pgpEncrytion.decryptData(encryptedValue, "/Users/gokhanimral/Projects/pgp-encrytion/keys/app1_private.pgp");
//
//        assertNotNull(encryptedValue);
//
//        assertEquals("testData", decryptedNppValue);
//        assertEquals("testData", decryptedGtValue);
//
//    }
//
//    public static String generateRandomWord(int minLength, int maxLength) {
//        Random random = new Random();
//        int wordLength = random.nextInt(maxLength - minLength + 1) + minLength;
//        StringBuilder word = new StringBuilder();
//
//        for (int i = 0; i < wordLength; i++) {
//            char randomChar = (char) ('a' + random.nextInt(26)); // Generate a random letter
//            word.append(randomChar);
//        }
//
//        return word.toString();
//    }
//    @Test
//    public void testPerformance() throws PGPException, IOException {
//        PgpEncrytion pgpEncrytion = new PgpEncrytion();
//        String[] keyPaths = new String[] { "/Users/gokhanimral/Projects/pgp-encrytion/keys/app2_public.pgp",
//                "/Users/gokhanimral/Projects/pgp-encrytion/keys/app1_public.pgp"};
//        for(int i = 0; i<100000;i++) {
//
//            String word = generateRandomWord(5, 100);
//            String encryptedValue = pgpEncrytion.encryptData(word, keyPaths);
//            String decryptedNppValue = pgpEncrytion.decryptData(encryptedValue, "/Users/gokhanimral/Projects/pgp-encrytion/keys/app2_private.pgp");
//        }
//    }
}
