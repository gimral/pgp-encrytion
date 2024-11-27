package encryption.bouncy;

import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;

public class PerformanceBouncyTest {

    public void testPerformance() throws Exception {

        PgpBouncyKeyReader keyReader = new PgpBouncyKeyReader();
        PGPPrivateKey cachedPrivateKey = keyReader.readPrivateKey("/Users/gokhanimral/Projects/pgp-encrytion/keys/app2_private.pgp",
                "1234");

        List<PGPPublicKey> publicKeys = new ArrayList<>();
        publicKeys.add(keyReader.readPublicKey("/Users/gokhanimral/Projects/pgp-encrytion/keys/app2_public.pgp"));
        publicKeys.add(keyReader.readPublicKey("/Users/gokhanimral/Projects/pgp-encrytion/keys/app1_public.pgp"));

        int iterations = 100000; // Number of iterations to test
        int reportInterval = 1000; // Interval for reporting performance

        long totalDecryptionTime = 0; // Total time spent on decryption

        PgpBouncyEncryption pgpEncryption = new PgpBouncyEncryption();

        for (int i = 1; i <= iterations; i++) {

            String word = generateRandomWord(5, 100); // Generate a random word
            byte[] encryptedValue = pgpEncryption.encryptData(word.getBytes(), publicKeys); // Encrypt the word
            // Time only the decryption process
            long decryptionStartTime = System.nanoTime();
            byte[] decryptedNppValue = pgpEncryption.decryptData(encryptedValue, cachedPrivateKey);
            String app2Value = new String(decryptedNppValue, StandardCharsets.UTF_8);
            if(!app2Value.equals(word)) {
                throw new Exception("Decryption generated different value");
            }

            long decryptionEndTime = System.nanoTime();

            long decryptionTime = decryptionEndTime - decryptionStartTime;
            totalDecryptionTime += decryptionTime;

            if (i % reportInterval == 0) {
                long elapsedTimeInMillis = TimeUnit.NANOSECONDS.toMillis(totalDecryptionTime);
                double averageTimePerDecryption = elapsedTimeInMillis / (double) i;

                System.out.println("Iterations: " + i);
                System.out.println("Total decryption time: " + elapsedTimeInMillis + " ms");
                System.out.println("Average decryption time per operation: " + averageTimePerDecryption + " ms");
            }
        }

        long totalDecryptionTimeInMillis = TimeUnit.NANOSECONDS.toMillis(totalDecryptionTime);

        System.out.println("\nFinal Report:");
        System.out.println("Total decryption time for " + iterations + " iterations: " + totalDecryptionTimeInMillis + " ms");
        System.out.println("Final average decryption time per operation: " + (totalDecryptionTimeInMillis / (double) iterations) + " ms");
    }

    private String generateRandomWord(int minLength, int maxLength) {
        Random random = new Random();
        int length = random.nextInt(maxLength - minLength + 1) + minLength; // Random length between min and max
        StringBuilder word = new StringBuilder();

        for (int i = 0; i < length; i++) {
            char randomChar = (char) ('a' + random.nextInt(26)); // Random lowercase letter
            word.append(randomChar);
        }

        return word.toString();
    }

    public static void main(String[] args) throws Exception {
        PerformanceBouncyTest test = new PerformanceBouncyTest();
        test.testPerformance();
    }
}
