import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AES {
    // Method to generate symmetric encryption key using AES
    public static SecretKey generateAESKey() {
        try {
            // Create a KeyGenerator instance for AES
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            // Generate a secret key
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    // Method to encrypt data using AES with a given key
    public static String encryptData(String data, SecretKey key) {
        try {
            // Create a Cipher instance for AES
            Cipher cipher = Cipher.getInstance("AES");
            // Initialize the Cipher instance with the key in encryption mode
            cipher.init(Cipher.ENCRYPT_MODE, key);
            // Encrypt the data
            byte[] encryptedData = cipher.doFinal(data.getBytes());
            // Encode the encrypted data as a Base64 string for easy transmission
            return Base64.getEncoder().encodeToString(encryptedData);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            return null;
        }
    }

    // Method to decrypt data using AES with a given key
    public static String decryptData(String encryptedData, SecretKey key) {
        try {
            // Create a Cipher instance for AES
            Cipher cipher = Cipher.getInstance("AES");
            // Initialize the Cipher instance with the key in decryption mode
            cipher.init(Cipher.DECRYPT_MODE, key);
            // Decode the Base64 string to get the encrypted data bytes
            byte[] encryptedDataBytes = Base64.getDecoder().decode(encryptedData);
            // Decrypt the data
            byte[] decryptedDataBytes = cipher.doFinal(encryptedDataBytes);
            // Convert the decrypted data bytes to a string
            return new String(decryptedDataBytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        // Generate symmetric encryption key using AES
        SecretKey aesKey = generateAESKey();

        if (aesKey != null) {
            System.out.println("AES Key generated successfully:");
            System.out.println(aesKey);

            // Sample credit card details
            String creditCardInfo = "1234 5678 9101 2131";
            System.out.println("Original Credit Card Info: " + creditCardInfo);

            // Encrypt the credit card details
            String encryptedData = encryptData(creditCardInfo, aesKey);
            System.out.println("Encrypted Data: " + encryptedData);

            // Decrypt the encrypted data
            String decryptedData = decryptData(encryptedData, aesKey);
            System.out.println("Decrypted Credit Card Info: " + decryptedData);
        } else {
            System.out.println("Failed to generate AES key.");
        }
    }
}
