package practice10_backup;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class MySecretKey{
	private static final String ALGO ="AES";
			//"AES";
	
	static void saveSecretKey(SecretKey secretKey, String filename) 
			throws NoSuchAlgorithmException { //���Ű�� �ܺ� ���Ͽ� ����. ��, ����ȭ 
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

	public static byte[] encrypt(SecretKey skey, byte[] data) throws Exception{
		Cipher c = Cipher.getInstance(ALGO);
		c.init(Cipher.ENCRYPT_MODE, skey);
		byte[] encVal = c.doFinal(data);
		return encVal;
	}
	
	public PlainSet decrypt(SecretKey secretKey, byte[] encryptedData)throws Exception {
		//암호화된 PlainSet을 받아서 비밀키를 가지고 해독 
		Cipher c = Cipher.getInstance(ALGO);
		c.init(Cipher.DECRYPT_MODE, secretKey);
		byte[] decValue = c.doFinal(encryptedData);
		
		//해독한 직렬화된 PlainSet을 역직렬화 
		SerialSet serialSet = new SerialSet();
		PlainSet plainSet = (PlainSet) serialSet.deserialization(decValue);
		return plainSet;
	}

}
