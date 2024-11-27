package encryption.painless;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.Passphrase;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class PgpEncrytion {

    private PGPSecretKeyRing secretKeyRing;
    private SecretKeyRingProtector secretKeyProtector;


    public PgpEncrytion(String privateKeyPath, String passphrase) throws PGPException, IOException {
        initializePrivateKey(privateKeyPath,passphrase);
    }

    private void initializePrivateKey(String privateKeyPath, String passphrase) throws IOException, PGPException {
        try (InputStream keyIn = new FileInputStream(privateKeyPath)) {
            // Read the secret key ring
            secretKeyRing = PGPainless.readKeyRing().secretKeyRing(keyIn);

            // Create a secret key protector using the passphrase
            secretKeyProtector = SecretKeyRingProtector
                    .unlockAnyKeyWith(Passphrase.fromPassword(passphrase));
        }
    }

    public String encryptData(String data, String[] publicKeyPaths) throws IOException, PGPException {
        ByteArrayOutputStream encryptedOutput = new ByteArrayOutputStream();

        List<PGPPublicKeyRing> keys = new ArrayList<>();
        for(String publicKeyPath : publicKeyPaths){
            InputStream keyIn = new FileInputStream(publicKeyPath);
            keys.add(PGPainless.readKeyRing().publicKeyRing(keyIn));
        }

        try (OutputStream outputStream = new ArmoredOutputStream(encryptedOutput)) {
            EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                    .onOutputStream(outputStream)
                    .withOptions(
                            ProducerOptions.encrypt(
                                    new EncryptionOptions()
                                            .addRecipients(keys)
//                                            .addRecipient(bobsKey)
                                            // optionally encrypt to a passphrase
//                                            .addPassphrase(Passphrase.fromPassword("1234"))
                                            // optionally override symmetric encryption algorithm
                                            .overrideEncryptionAlgorithm(SymmetricKeyAlgorithm.AES_256)
                            ).setAsciiArmor(true) // Ascii armor or not
                    );

            try (OutputStream out = encryptionStream) {
                out.write(data.getBytes(StandardCharsets.UTF_8));
            }
            encryptionStream.close();
        }

        return encryptedOutput.toString();
    }

//    public String decryptData(String data, String privateKeyPath) throws IOException, PGPException {
//        InputStream encryptedInput = new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8));
//        ByteArrayOutputStream decryptedOutput = new ByteArrayOutputStream();
//
//        InputStream keyIn = new FileInputStream(privateKeyPath);
//        PGPSecretKeyRing privateKey = PGPainless.readKeyRing().secretKeyRing(keyIn);
//        SecretKeyRingProtector secretKeyProtector = SecretKeyRingProtector
//                .unlockAnyKeyWith(Passphrase.fromPassword("1234"));
//        try (DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
//                .onInputStream(new ArmoredInputStream(encryptedInput))
//                .withOptions(new ConsumerOptions()
//                        .addDecryptionKey(privateKey, secretKeyProtector)
//                )) {
//
//            // Write decrypted data to the output stream
//            try (OutputStream out = decryptedOutput) {
//                decryptionStream.transferTo(out);
//            }
//        }
//
//        return decryptedOutput.toString(StandardCharsets.UTF_8);
//    }

    public String decryptData(String data) throws IOException, PGPException {
        InputStream encryptedInput = new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream decryptedOutput = new ByteArrayOutputStream();

        try (DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(new ArmoredInputStream(encryptedInput))
                .withOptions(new ConsumerOptions().addDecryptionKey(secretKeyRing, secretKeyProtector))) {

            // Write decrypted data to the output stream
            try (OutputStream out = decryptedOutput) {
                decryptionStream.transferTo(out);
            }
        }

        return decryptedOutput.toString(StandardCharsets.UTF_8);
    }
}
