package org.example.securityservicee;


import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class RsaKeyGenerator {

    private static final int KEY_SIZE = 2048;

    // You can change these paths as you like
    private static final Path PUBLIC_KEY_PATH  = Paths.get("src/main/resources/keys/public_key.pem");
    private static final Path PRIVATE_KEY_PATH = Paths.get("src/main/resources/keys/private_key.pem");

    public void generateAndStoreKeys() throws NoSuchAlgorithmException, IOException {
        KeyPair keyPair = generateKeyPair();
        writeKeyFiles(keyPair);
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    private void writeKeyFiles(KeyPair keyPair) throws IOException {
        // Ensure directory exists
        if (PUBLIC_KEY_PATH.getParent() != null) {
            Files.createDirectories(PUBLIC_KEY_PATH.getParent());
        }

        // Public key (X.509, PEM)
        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        String publicKeyPem = toPem("PUBLIC KEY", publicKeyBytes);
        Files.write(PUBLIC_KEY_PATH, publicKeyPem.getBytes());

        // Private key (PKCS#8, PEM)
        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();
        String privateKeyPem = toPem("PRIVATE KEY", privateKeyBytes);
        Files.write(PRIVATE_KEY_PATH, privateKeyPem.getBytes());
    }

    private String toPem(String type, byte[] keyBytes) {
        String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(keyBytes);
        return "-----BEGIN " + type + "-----\n"
                + base64
                + "\n-----END " + type + "-----\n";
    }

    // For quick testing without Spring:
    public static void main(String[] args) {
        RsaKeyGenerator generator = new RsaKeyGenerator();
        try {
            generator.generateAndStoreKeys();
            System.out.println("RSA key pair generated and stored in 'keys/' directory.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

