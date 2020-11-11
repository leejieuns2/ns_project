package digitalEnvelope;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Formatter;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import common.SerialKey;

// 비밀키 관련 클래스
// 비밀키 생성, 암호화, 복호화, 직렬화, 역직렬화 함수가 내장되어 있음.
public class MySecretKey extends SerialKey {

	private static final String algoEnvelope = "AES";
	private static final String algoSign = "RSA";
	
	public SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algoEnvelope);
        keyGenerator.init(128);
        
        SecretKey secretKey = keyGenerator.generateKey();
		return secretKey;
	}
	
	// Overloading
	byte[] encrypt(SecretKey sKey, byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher c = Cipher.getInstance(algoEnvelope);
		c.init(Cipher.ENCRYPT_MODE, sKey);
		byte[] encVal = c.doFinal(data);
		return encVal;
	}
	
	// Overloading
	byte[] encrypt(PublicKey pKey, byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher c = Cipher.getInstance(algoSign);
		c.init(Cipher.ENCRYPT_MODE, pKey);
		byte[] encVal = c.doFinal(data);
		return encVal;
	}
	
	// Overloading
	PlainSet decryptSet(SecretKey key, byte[] encryptedData) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException  {
		//암호화된 PlainSet을 받아서 비밀키를 가지고 해독 
		Cipher c = Cipher.getInstance(algoEnvelope);
		c.init(Cipher.DECRYPT_MODE, key);
		byte[] decValue = c.doFinal(encryptedData);
		
		//해독한 직렬화된 PlainSet을 역직렬화 
		SerialSet serialSet = new SerialSet();
		PlainSet plainSet = (PlainSet) serialSet.deserialization(decValue);
		return plainSet;
	}
	
	public byte[] decryptEnvelope(PrivateKey privateKey, byte[] encryptData)
			throws GeneralSecurityException, IOException {
		Cipher cipher = Cipher.getInstance(algoSign);
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] plainData = cipher.doFinal(encryptData);
		return plainData;
	}
}
