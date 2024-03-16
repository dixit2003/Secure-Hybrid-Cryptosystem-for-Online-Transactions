import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class User {
    public static void main(String[] args) {
        // Take credit card information as input
        BufferedReader userInputReader = new BufferedReader(new InputStreamReader(System.in));
        String cardNumber;
        String cvv;
        String expiryDate;
        try {
            System.out.print("Enter credit card number: ");
            cardNumber = userInputReader.readLine();
            System.out.print("Enter CVV: ");
            cvv = userInputReader.readLine();
            System.out.print("Enter expiry date: ");
            expiryDate = userInputReader.readLine();
        } catch (IOException e) {
            System.err.println("Error reading input.");
            return;
        }

        // Connect to the merchant server and send credit card information
        try (Socket socket = new Socket("localhost", 8080);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            // Send credit card information to the merchant server
            out.println(cardNumber);
            out.println(cvv);
            out.println(expiryDate);

            // Receive response from the merchant server
            String response = in.readLine();
            System.out.println("Response from Merchant: " + response);

        } catch (IOException e) {
            System.err.println("Error communicating with the merchant server.");
            e.printStackTrace();
        }
    }
}
