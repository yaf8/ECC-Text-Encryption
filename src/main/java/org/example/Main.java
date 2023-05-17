package org.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Scanner;
import javax.crypto.Cipher;

public class Main {
    public static void main(String[] args) throws Exception {
        // Add Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());

        // Generate key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        keyGen.initialize(ecSpec);
        KeyPair keyPair = keyGen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Encrypt message
        System.out.print("Enter your message : ");
        Scanner input = new Scanner(System.in);
        String message = input.nextLine();
        Cipher encryptCipher = Cipher.getInstance("ECIES", "BC");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = encryptCipher.doFinal(message.getBytes());

        // Decrypt message
        Cipher decryptCipher = Cipher.getInstance("ECIES", "BC");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypted = decryptCipher.doFinal(encrypted);

        // Print results
        System.out.println("Original message: " + message);
        System.out.println("Encrypted message: " + new String(encrypted));
        System.out.println("Decrypted message: " + new String(decrypted));
    }
}
