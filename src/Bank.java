import javax.crypto.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.Base64;
import javax.crypto.spec.SecretKeySpec;


public class Bank {
    private static final int RSA_KEY_SIZE = 2048;

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(9091)) {
            System.out.println("Bank server started. Waiting for connections...");

            // Step 4: Generate RSA key pair
            KeyPair rsaKeyPair = generateRSAKeyPair();

            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Connected to merchant server: " + clientSocket);

                try (clientSocket;
                     BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                     PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {

                    // Step 4: Receive request for RSA public key from the merchant
                    String request = in.readLine();
                    if ("RSA_PUBLIC_KEY_REQUEST".equals(request)) {
                        // Step 5: Transmit RSA public key to the merchant
                        String rsaPublicKey = Base64.getEncoder().encodeToString(rsaKeyPair.getPublic().getEncoded());
                        out.println(rsaPublicKey);
                        System.out.println("Transmitted RSA public key to merchant.");
                        continue; // Skip to the next iteration of the loop
                    }

                    // Receive encrypted AES keys from the merchant
                    String encryptedCardNumberKey = in.readLine();
                    String encryptedCVVKey = in.readLine();
                    String encryptedExpiryDateKey = in.readLine();

                    // Decrypt the AES keys using the bank's RSA private key
                    SecretKey cardNumberKey = decryptAESKey(encryptedCardNumberKey, rsaKeyPair.getPrivate());
                    SecretKey cvvKey = decryptAESKey(encryptedCVVKey, rsaKeyPair.getPrivate());
                    SecretKey expiryDateKey = decryptAESKey(encryptedExpiryDateKey, rsaKeyPair.getPrivate());

                    // Receive encrypted credit card details from the merchant
                    String encryptedCardNumber = in.readLine();
                    String encryptedCVV = in.readLine();
                    String encryptedExpiryDate = in.readLine();

                    // Decrypt the credit card details using the decrypted AES keys
                    String cardNumber = decryptData(cardNumberKey, encryptedCardNumber);
                    String cvv = decryptData(cvvKey, encryptedCVV);
                    String expiryDate = decryptData(expiryDateKey, encryptedExpiryDate);

                    // Process the payment
                    boolean paymentProcessed = processPayment(cardNumber, cvv, expiryDate);

                    // Send response to the merchant
                    if (paymentProcessed) {
                        out.println("Payment successful. Thank you!");
                        System.out.println("Payment successful. Response sent to merchant.");
                    } else {
                        out.println("Payment failed. Please try again.");
                        System.out.println("Payment failed. Response sent to merchant.");
                    }

                } catch (IOException e) {
                    System.err.println("Error handling merchant server request.");
                    e.printStackTrace();
                }
            }
        } catch (IOException e) {
            System.err.println("Error starting bank server.");
            e.printStackTrace();
        }
    }

    // Method to generate RSA key pair
    private static KeyPair generateRSAKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(RSA_KEY_SIZE);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    // Method to decrypt AES keys using RSA private key
    private static SecretKey decryptAESKey(String encryptedKey, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedKeyBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedKey));
            return new SecretKeySpec(decryptedKeyBytes, 0, decryptedKeyBytes.length, "AES");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }

    // Method to decrypt data using AES key
    private static String decryptData(SecretKey key, String encryptedData) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
            return new String(decryptedBytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }

    // Method to process payment
    private static boolean processPayment(String cardNumber, String cvv, String expiryDate) {
        // Dummy implementation for illustration
        // Perform actual payment processing logic here
        return true; // For illustration, always return true
    }
}
