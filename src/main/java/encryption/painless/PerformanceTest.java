package encryption.painless;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import org.bouncycastle.openpgp.PGPException;

public class PerformanceTest {

    public void testPerformance() throws PGPException, IOException {
        PgpEncrytion pgpEncrytion = new PgpEncrytion("/Users/gokhanimral/Projects/pgp-encrytion/keys/app2_private.pgp","1234");
        String[] keyPaths = new String[] {
                "/Users/gokhanimral/Projects/pgp-encrytion/keys/app2_public.pgp",
                "/Users/gokhanimral/Projects/pgp-encrytion/keys/app1_public.pgp"
        };

        int iterations = 100000; // Number of iterations to test
        int reportInterval = 10; // Interval for reporting performance

        long totalDecryptionTime = 0; // Total time spent on decryption

        String word = generateRandomWord(5, 100); // Generate a random word
        byte[] encryptedValue = pgpEncrytion.encryptData(word, keyPaths); // Encrypt the word
        for (int i = 1; i <= iterations; i++) {


            // Time only the decryption process
            long decryptionStartTime = System.nanoTime();
            String decryptedNppValue = pgpEncrytion.decryptData(new String(encryptedValue, StandardCharsets.UTF_8));
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

    public static void main(String[] args) throws PGPException, IOException {
        PerformanceTest test = new PerformanceTest();
        test.testPerformance();
    }
}
