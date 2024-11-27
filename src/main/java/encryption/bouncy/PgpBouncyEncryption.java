package encryption.bouncy;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.security.Security;
import java.util.Date;
import java.util.List;
import java.util.Optional;

public class PgpBouncyEncryption {

    static {
        // Add Bouncy Castle Provider to JVM
        Security.addProvider(new BouncyCastleProvider());
    }

    public byte[] encryptData(byte[] data, List<PGPPublicKey> publicKeys) throws PGPException, IOException {
        // Initialize the encrypted data generator
        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                        .setWithIntegrityPacket(true)
//                        .setSecureRandom(new SecureRandom())
                        .setProvider("BC"));

        // Add each public key to the encryption generator
        for (PGPPublicKey encryptionKey : publicKeys) {
            encGen.addMethod(
                    new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey)
                            .setProvider("BC"));
        }

        ByteArrayOutputStream encOut = new ByteArrayOutputStream();

        // Wrap the output stream in an ArmoredOutputStream for ASCII-armored output
        try (ArmoredOutputStream armoredOut = new ArmoredOutputStream(encOut)) {
            // Create an indefinite length encrypted stream
            OutputStream cOut = encGen.open(armoredOut, new byte[4096]);

            // Write out the literal data
            PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
            OutputStream pOut = lData.open(
                    cOut, PGPLiteralData.BINARY,
                    PGPLiteralData.CONSOLE, data.length, new Date());
            pOut.write(data);
            pOut.close();

            // Finish the encryption
            cOut.close();
        }


        return encOut.toByteArray();
    }

    public byte[] decryptData(
            byte[] encryptedData,
            List<PGPPrivateKey> privateKeys)
            throws PGPException, IOException
    {
        InputStream encryptedInput = new ByteArrayInputStream(encryptedData);
        ByteArrayOutputStream decryptedOutput = new ByteArrayOutputStream();

        PGPObjectFactory pgpFact = new PGPObjectFactory(PGPUtil.getDecoderStream(new ArmoredInputStream(encryptedInput, true)), new JcaKeyFingerprintCalculator());
        PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpFact.nextObject();
        // find the matching public key encrypted data packet.
        PGPPublicKeyEncryptedData encData = null;
        PGPPrivateKey privateKey = null;
        for (PGPEncryptedData pgpEnc: encList)
        {
            if(!(pgpEnc instanceof PGPPublicKeyEncryptedData))
                continue;
            PGPPublicKeyEncryptedData pkEnc
                    = (PGPPublicKeyEncryptedData)pgpEnc;
            Optional<PGPPrivateKey> optionalKey = privateKeys.stream().filter(p -> p.getKeyID() == pkEnc.getKeyID()).findAny();
            if (optionalKey.isPresent())
            {
                encData = pkEnc;
                privateKey = optionalKey.get();
                break;
            }
        }
        if (encData == null)
        {
            throw new IllegalStateException("matching encrypted data not found");
        }
        // build decryptor factory
        PublicKeyDataDecryptorFactory dataDecryptorFactory =
                new JcePublicKeyDataDecryptorFactoryBuilder()
                        .setProvider("BC")
                        .build(privateKey);
        InputStream clear = encData.getDataStream(dataDecryptorFactory);
        byte[] literalData = Streams.readAll(clear);
        clear.close();
        // check data decrypts okay
        if (encData.verify())
        {
            // parse out literal data
            PGPObjectFactory litFact = new JcaPGPObjectFactory(literalData);
            PGPLiteralData litData = (PGPLiteralData)litFact.nextObject();
            byte[] data = Streams.readAll(litData.getInputStream());
            return data;
        }
        throw new IllegalStateException("modification check failed");
    }


}
