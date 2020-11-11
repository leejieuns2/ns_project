package practice10_backup;

import java.io.Serializable;
import java.security.Key;
import java.util.Formatter;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SerialSecretKey implements Serializable {
	private static final long serialVersionUID = 1L;
	
	private static final byte[] keyValue = { 's','s','t'};
	
	
	private static final String ALGO = "AES";
	
	public SecretKey generateKey() throws Exception{
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGO);
        keyGenerator.init(128);
        
        SecretKey secretKey = keyGenerator.generateKey();
        		
        System.out.println("비밀키 생성 : " + bytesToHex(secretKey.getEncoded()));
        System.out.println("비밀키 길이 : " + secretKey.getEncoded().length);
        
		return secretKey;
	}

	public static String bytesToHex(byte[] bytes) 
	{
		StringBuilder sb = new StringBuilder(bytes.length * 2);
		@SuppressWarnings("resource")
		Formatter formatter = new Formatter(sb);
	
		for (byte b : bytes) 
		{
			formatter.format("%02x", b);
		}
		return sb.toString();
	} 
	
}
