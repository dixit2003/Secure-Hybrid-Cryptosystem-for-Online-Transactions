import javax.crypto.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.ServerSocket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Merchant {
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

    // Method to encrypt data using AES encryption
    public static String encryptData(SecretKey key, String data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static void main(String[] args) throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(8080)) {
            System.out.println("Merchant server started. Waiting for connections...");

            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Connected to client: " + clientSocket);

                try (clientSocket;
                     BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                     PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {

                    // Receive credit card details from the user
                    String cardNumber = in.readLine();
                    String cvv = in.readLine();
                    String expiryDate = in.readLine();

                    // Generate symmetric encryption keys for credit card details
                    SecretKey cardNumberKey = generateAESKey();
                    SecretKey cvvKey = generateAESKey();
                    SecretKey expiryDateKey = generateAESKey();

                    // Encrypt the credit card details using AES keys
                    String encryptedCardNumber = encryptData(cardNumberKey, cardNumber);
                    String encryptedCVV = encryptData(cvvKey, cvv);
                    String encryptedExpiryDate = encryptData(expiryDateKey, expiryDate);

                    // Step 3: Transmit encrypted card details and AES keys to the bank server
                    try (Socket bankSocket = new Socket("localhost", 9091);
                         PrintWriter bankOut = new PrintWriter(bankSocket.getOutputStream(), true);
                         BufferedReader bankIn = new BufferedReader(new InputStreamReader(bankSocket.getInputStream()))) {

                        // Transmit encrypted card details to the bank server
                        bankOut.println("CARD_DETAILS");
                        bankOut.println(encryptedCardNumber);
                        bankOut.println(encryptedCVV);
                        bankOut.println(encryptedExpiryDate);

                        // Receive response from the bank server
                        String bankResponse = bankIn.readLine();
                        System.out.println("Response from bank server: " + bankResponse);

                        // Send response back to the user
                        out.println(bankResponse);
                    } catch (IOException e) {
                        System.err.println("Error communicating with bank server.");
                        e.printStackTrace();
                        out.println("Error communicating with bank server.");
                    } catch (Exception e) {
                        System.err.println("Error encrypting or transmitting data.");
                        e.printStackTrace();
                    }

                } catch (IOException e) {
                    System.err.println("Error handling client request.");
                    e.printStackTrace();
                }
            }
        } catch (IOException e) {
            System.err.println("Error starting merchant server.");
            e.printStackTrace();
        }
    }
}
