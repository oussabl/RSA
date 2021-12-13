import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Scanner;

public class RSA {
    private PrivateKey privateKey;
    private PublicKey publicKey;


    public  RSA(){
        try{
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(1024);
            KeyPair pair = generator.generateKeyPair();
            privateKey = pair.getPrivate();
            publicKey = pair.getPublic();
        } catch (Exception exception){

            }
        }
    public String encrypt(String message) throws Exception{
        byte[] messageToBytes = message.getBytes();
        Cipher cipher  = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        //cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        cipher.init(Cipher.ENCRYPT_MODE,privateKey);
        byte[] encryptedBytes = cipher.doFinal(messageToBytes);
        return encode(encryptedBytes);
    }
    private String encode(byte[] data) throws Exception {
        return Base64.getEncoder().encodeToString(data);
    }

    private String decrypt(String encryptedMessage) throws Exception {
        byte[] encryptedBytes = decode(encryptedMessage);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
       // cipher.init(Cipher.DECRYPT_MODE,privateKey);
       cipher.init(Cipher.DECRYPT_MODE,publicKey);
        byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
        return  new String(decryptedMessage, "UTF8");
    }

    private byte[] decode(String data){
        return Base64.getDecoder().decode(data);
    }

    public static void main(String[] args){
        RSA rsa = new RSA();
        try {
            System.out.println(" Write your message how we need encrypted \n ==> : ");
            Scanner scanner = new Scanner(System.in);
            String message = scanner.next();
            String encryptedMessage = rsa.encrypt(message);
            String decryptedMessage = rsa.decrypt(encryptedMessage);

            System.out.println("encryptedMessage :" +encryptedMessage);
            System.out.println("decryptedMessage : "+decryptedMessage);

        } catch (Exception e){
            e.printStackTrace();
        }
     }
}
