package ref;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Formatter;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec; 

public class Envelope {
	public static void main(String[] args) throws Exception {
		
		System.out.println("전자봉투 (Digital Envelope) ");
		System.out.println("송신자 A  ---->  수신자 B ");
		System.out.println("(1) RSA 전자서명 (송신자의 개인키로 메시지 서명) ");
		System.out.println("(2) AES 암호화 (난수 세션키로 메시지와 서명을 암호화) ");
		System.out.println("(3) RSA 암호화 (수신자의 공개키로 세션키를 암호화) ");
		System.out.println();
		
		System.out.println("1. 송신자 A의 RSA 키쌍 생성 ");
		
		File publicKeyFileA = new File("publicA.key");
		File privateKeyFileA = new File("privateA.key");
		PublicKey publicKeyA = null;
		PrivateKey privateKeyA = null;
		if (publicKeyFileA.exists() && privateKeyFileA.exists()) {
			// 파일에서 키 읽어오기
			Path publicFile = Paths.get("publicA.key");
			byte[] publicKeyBytes = Files.readAllBytes(publicFile);
			Path privateFile = Paths.get("privateA.key");
			byte[] privateKeyBytes = Files.readAllBytes(privateFile);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			publicKeyA = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
			privateKeyA = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
		} else {
			// 공개키쌍 생성
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(2048);
			KeyPair pair = generator.generateKeyPair();
			publicKeyA = pair.getPublic();
			privateKeyA = pair.getPrivate();
			FileOutputStream outputPublic = new FileOutputStream(new File("publicA.key"));
			outputPublic.write(publicKeyA.getEncoded());
			FileOutputStream outputPrivate = new FileOutputStream(new File("privateA.key"));
			outputPrivate.write(privateKeyA.getEncoded());
		}
		System.out.println("송신자 A의 공개키: "+bytesToHex(publicKeyA.getEncoded()));
		System.out.println("송신자 A의 개인키: "+bytesToHex(privateKeyA.getEncoded()));
		System.out.println();
		
		System.out.println("2. 수신자 B의 RSA 키쌍 생성 ");
		
		File publicKeyFileB = new File("publicB.key");
		File privateKeyFileB = new File("privateB.key");
		PublicKey publicKeyB = null;
		PrivateKey privateKeyB = null;
		if (publicKeyFileB.exists() && privateKeyFileB.exists()) {
			// 파일에서 키 읽어오기
			Path publicFile = Paths.get("publicB.key");
			byte[] publicKeyBytes = Files.readAllBytes(publicFile);
			Path privateFile = Paths.get("privateB.key");
			byte[] privateKeyBytes = Files.readAllBytes(privateFile);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			publicKeyB = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
			privateKeyB = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
		} else {
			// 공개키쌍 생성
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(2048);
			KeyPair pair = generator.generateKeyPair();
			publicKeyB = pair.getPublic();
			privateKeyB = pair.getPrivate();
			FileOutputStream outputPublic = new FileOutputStream(new File("publicB.key"));
			outputPublic.write(publicKeyB.getEncoded());
			FileOutputStream outputPrivate = new FileOutputStream(new File("privateB.key"));
			outputPrivate.write(privateKeyB.getEncoded());
		}
		System.out.println("수신자 B의 공개키: "+bytesToHex(publicKeyB.getEncoded()));
		System.out.println("수신자 B의 개인키: "+bytesToHex(privateKeyB.getEncoded()));
		System.out.println();
		
		System.out.println("3. 송신자 A의 전자봉투 생성 ");
		
		String plainText = "죽는 날까지 하늘을 우러러 한점 부끄럼이 없기를 잎새에 이는 바람에도 나는 괴로워했다. "
				+ "별을 노래하는 마음으로 모든 죽어가는 것을 사랑해야지. 그리고 나한테 주어진 길을 걸어가야겠다. "
				+ "오늘밤에도 별이 바람에 스치운다";
		System.out.println("평문: "+plainText);
		Charset charset = Charset.forName("UTF-8");
		
		// 송신자의 전자서명 생성 
		byte[] signature = sign(privateKeyA, plainText.getBytes(charset));
		System.out.println("서명문: "+bytesToHex(signature));
		
		// AES 세션키 생성
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128);
		SecretKey secretKey = keyGenerator.generateKey();
		System.out.println("세션키: "+bytesToHex(secretKey.getEncoded()));
		
		// 메시지와 서명을 세션키로 암호화
		byte[] encryptData = encrypt(secretKey, plainText.getBytes(charset));
		byte[] encryptSig = encrypt(secretKey, signature);
		System.out.println("AES 암호화된 메시지: "+bytesToHex(encryptData));
		System.out.println("AES 암호화된 서명문: "+bytesToHex(encryptSig));

		// 세션키를 수신자 B의 공개키로 암호화 
		byte[] encryptKey = encrypt(publicKeyB, secretKey.getEncoded());
		System.out.println("RSA 암호화된 세션키: "+bytesToHex(encryptKey));
		System.out.println();
		
		System.out.println("4. 수신자 B의 전자봉투 개봉 ");
		
		// 전자봉투로 비밀키 획득
		// 수신자 B의 개인키로 세션키 복구  
		byte[] decryptKey = decrypt(privateKeyB, encryptKey);
		System.out.println("복구된 세션키: "+bytesToHex(decryptKey));		
		// SecretKeySpec으로 비밀키 생성 				
		SecretKey recoveredKey = new SecretKeySpec(decryptKey, "AES");
		
		// 비밀키로 메세지, 서명 획득
		// 세션키로 메시지, 서명 복구 
		byte[] plainData = decrypt(recoveredKey, encryptData);
		String plain = new String(plainData, charset);
		byte[] sig = decrypt(recoveredKey, encryptSig);
		System.out.println("복호화된 메시지:"+plain); 
		System.out.println("복호화된 서명문:"+bytesToHex(sig));
		
		// A의 공개키로 서명 검증 
		boolean verified = verify(publicKeyA, sig, plainData);
		System.out.println("서명검증 = " + verified);
	}
	
	// AES 암호화 함수 
	public static byte[] encrypt(SecretKey secretKey, byte[] plainData)
	throws GeneralSecurityException {
		
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		byte[] encryptData = cipher.doFinal(plainData);
		return encryptData;
	}
	
	// AES 복호화 함수 
	public static byte[] decrypt(SecretKey secretKey, byte[] encryptData)
	throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		byte[] plainData = cipher.doFinal(encryptData);
		return plainData;
	}
	
	// RSA 암호화 함수 
	public static byte[] encrypt(PublicKey publicKey, byte[] plainData)
	throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithMD5AndMGF1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] encryptData = cipher.doFinal(plainData);
		return encryptData;
	}
		
	// RSA 복호화 함수 
	public static byte[] decrypt(PrivateKey privateKey, byte[] encryptData)
	throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithMD5AndMGF1Padding");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] plainData = cipher.doFinal(encryptData);
		return plainData;
	}
	
	// RSA 전자서명 생성  함수
	public static byte[] sign(PrivateKey privateKey, byte[] plainData) throws
	GeneralSecurityException {
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(privateKey);
		signature.update(plainData);
		byte[] signatureData = signature.sign();
		return signatureData;
	}
	
	// RSA 전자서명 검증 함수 
	public static boolean verify(PublicKey publicKey, byte[] signatureData,
	byte[] plainData) throws GeneralSecurityException {
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initVerify(publicKey);
		signature.update(plainData);
		return signature.verify(signatureData);
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