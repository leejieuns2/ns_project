package practice10;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Formatter;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

// 비밀키 관련 클래스
// 비밀키 생성, 암호화, 복호화, 직렬화, 역직렬화 함수가 내장되어 있음.
class MySecretKey implements Serializable {
	private static final long serialVersionUID = 1L;	
	private static final String ALGO ="AES";
	
	public SecretKey generateKey() throws Exception{
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGO);
        keyGenerator.init(128);
        
        SecretKey secretKey = keyGenerator.generateKey();
        System.out.println("비밀키 생성 : " + bytesToHex(secretKey.getEncoded()));
        System.out.println("비밀키 길이 : " + secretKey.getEncoded().length);
		return secretKey;
	}

	void saveSecretKey(SecretKey secretKey, String filename) 
			throws NoSuchAlgorithmException {
		try(FileOutputStream fstream = new FileOutputStream(filename)){
			try(ObjectOutputStream ostream = new ObjectOutputStream(fstream)){
				ostream.writeObject(secretKey);
			}
		}catch(IOException e) {
			e.printStackTrace();
		}
	}
	
	static SecretKey restoreSecretKey(String filename) { //������ȭ 
		try(FileInputStream fis = new FileInputStream(filename)){
			try(ObjectInputStream ois = new ObjectInputStream(fis)){
				Object obj = ois.readObject();
				SecretKey secretKey = (SecretKey)obj;
				return secretKey;
			}
		}catch(ClassNotFoundException e) {
			e.printStackTrace();
		}
		catch(FileNotFoundException e) {
			e.printStackTrace();
		}
		catch(IOException e) {
			e.printStackTrace();
		}
		return null;	
		
	}

	byte[] encrypt(SecretKey skey, byte[] data) throws Exception{
		Cipher c = Cipher.getInstance(ALGO);
		c.init(Cipher.ENCRYPT_MODE, skey);
		byte[] encVal = c.doFinal(data);
		return encVal;
	}
	
	PlainSet decrypt(SecretKey secretKey, byte[] encryptedData)throws Exception {
		//암호화된 PlainSet을 받아서 비밀키를 가지고 해독 
		Cipher c = Cipher.getInstance(ALGO);
		c.init(Cipher.DECRYPT_MODE, secretKey);
		byte[] decValue = c.doFinal(encryptedData);
		
		//해독한 직렬화된 PlainSet을 역직렬화 
		SerialSet serialSet = new SerialSet();
		PlainSet plainSet = (PlainSet) serialSet.deserialization(decValue);
		return plainSet;
	}

	static String bytesToHex(byte[] bytes) 
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
