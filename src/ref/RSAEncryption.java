package ref;

import java.nio.charset.Charset;
import java.security.*;
import javax.crypto.*;
import java.util.*;

public class RSAEncryption {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        
    	KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024); 
        KeyPair keyPair = generator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();     
        Charset charset = Charset.forName("UTF-8");
        
        System.out.println("=== RSA 키생성 ===");
        byte[] pubk = publicKey.getEncoded();
        byte[] prik = privateKey.getEncoded(); 
        System.out.println(" 공개키 포맷 : "+publicKey.getFormat());
        System.out.println(" 개인키 포맷 : "+privateKey.getFormat());
        System.out.println(" 공개키 : "+bytesToHex(pubk));
        System.out.println(" 공개키 길이 : "+pubk.length+ " byte" );	
        System.out.println(" 개인키 : "+bytesToHex(prik));
        System.out.println(" 개인키 길이 : "+prik.length+ " byte" );
        System.out.println();
        
        System.out.println("=== RSA 암호화 ===");
        Scanner s = new Scanner(System.in);
        System.out.print("암호화할 평문을 입력해주세요 >>> ");
        String text = s.next();  
        byte[] t0 = text.getBytes(charset);
        System.out.println(" Plaintext : "+text);
        System.out.println(" Plaintext : "+bytesToHex(t0));
        System.out.println(" Plaintext Length : "+t0.length+ " byte" );	

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] b0 = cipher.doFinal(t0);
        System.out.println(" Ciphertext : "+bytesToHex(b0));
        System.out.println(" Ciphertext Length : "+b0.length+ " byte" );	
        System.out.println();
        
        System.out.println("=== RSA 복호화 ===");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] b1 = cipher.doFinal(b0);
        System.out.println(" Recovered Plaintext : "+ bytesToHex(b1)); 
        System.out.println(" Recovered Plaintext Length : "+b1.length+ " byte" );	
        System.out.println(" Recovered Plaintext : "+ new String(b1, charset));
        
    }
    
	public static String bytesToHex(byte[] bytes) {
	    StringBuilder sb = new StringBuilder(bytes.length * 2);
	 
	    @SuppressWarnings("resource")
		Formatter formatter = new Formatter(sb);
	    for (byte b : bytes) {
	        formatter.format("%02x", b);
	    }
	 
	    return sb.toString();
	}
}
