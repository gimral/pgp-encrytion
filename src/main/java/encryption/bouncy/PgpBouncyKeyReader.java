package encryption.bouncy;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.jetbrains.annotations.NotNull;

import java.io.*;
import java.security.Security;

public class PgpBouncyKeyReader {
    static {
        // Add Bouncy Castle Provider to JVM
        Security.addProvider(new BouncyCastleProvider());
    }
    public PGPPrivateKey readPrivateKey(String privateKeyPath, String passphrase) throws IllegalArgumentException, IOException, PGPException {
        PGPSecretKeyRing secretKeyRing = getPgpSecretKeyRing(privateKeyPath);

        // Get the first secret key
        PGPSecretKey secretKey = secretKeyRing.getSecretKey();

        // Build a PBESecretKeyDecryptor using the passphrase
        PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder(
                new JcaPGPDigestCalculatorProviderBuilder().build())
                .setProvider("BC")
                .build(passphrase.toCharArray());

        // Extract the private key
        return secretKey.extractPrivateKey(decryptor);
    }

    @NotNull
    private PGPSecretKeyRing getPgpSecretKeyRing(String privateKeyPath) throws IllegalArgumentException, IOException, PGPException {

        try (InputStream keyIn = new BufferedInputStream(new FileInputStream(privateKeyPath))) {
            PGPSecretKeyRingCollection keyRingCollection = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());
            return keyRingCollection.getKeyRings().next();

        }

//        PGPSecretKeyRing secretKeyRing = null;
//        try (InputStream keyIn = new FileInputStream(privateKeyPath)) {
//            // Read the secret key ring
//            BcPGPObjectFactory objectFactory = new BcPGPObjectFactory(keyIn);
//            for(Object object: objectFactory){
//                if(object instanceof PGPSecretKeyRing)
//                    secretKeyRing = (PGPSecretKeyRing)object;
//            }
//        }
//        if(secretKeyRing == null)
//            throw new IllegalArgumentException("Can't find secret key ring.");
//        return secretKeyRing;
    }

    public PGPPublicKey readPublicKey(String publicKeyPath) throws IOException, PGPException
    {
        try (InputStream keyIn = new BufferedInputStream(new FileInputStream(publicKeyPath))) {
            PGPPublicKeyRingCollection keyRingCollection = new PGPPublicKeyRingCollection(
                    PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());
            for(PGPPublicKeyRing keyRing: keyRingCollection){
                for(PGPPublicKey key: keyRing){
                    if(key.isEncryptionKey()){
                        return key;
                    }
                }
            }
        }
        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }

}
