package pk;

import org.bouncycastle.crypto.InvalidCipherTextException;
import pk.bouncycastle.symetric.Aes;

import java.io.File;
import java.io.FileNotFoundException;
import java.security.GeneralSecurityException;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        try {
            String input1 = readFromFile();

            testBouncyCastle(input1);

        } catch (FileNotFoundException | GeneralSecurityException | InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
    }

    public static String readFromFile() throws FileNotFoundException {
        StringBuilder sb = new StringBuilder();
        File file = new File("./src/main/resources/plaintext.txt");
        Scanner myReader = new Scanner(file);

        while (myReader.hasNextLine()) {
            sb.append(myReader.nextLine());
        }
        myReader.close();

        return sb.toString();
    }

    public static void testBouncyCastle(String input1) throws GeneralSecurityException, InvalidCipherTextException {
        // Bouncy Castle
        // Symmetric
        Aes aes = new Aes();
        byte[] ivBytes1 = Aes.generateIVBytes();
        byte[] encrypted1 = aes.encrypt(input1, ivBytes1);
        byte[] decrypted1 = aes.decrypt(encrypted1, ivBytes1);
        System.out.println("AES-CBC");
        System.out.println("Original text: " + input1);
        System.out.println("Encrypted text: " + Aes.printEncrypted(encrypted1));
        System.out.println("Decrypted text: " + Aes.printDecrypted(decrypted1));
        System.out.println("Decrypted text " + (input1.equals(Aes.printDecrypted(decrypted1)) ? "matches" : "doesn't match") + " original text");
    }
}
