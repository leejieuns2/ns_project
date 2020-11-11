package practice10;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Formatter;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

//객제를 직렬화해서 파일에 저장.
//뭔가 이게 겹치는거같음....
class SerialKey {
	public final static String cipherAlgo = "RSA/ECB/OAEPWithMD5AndMGF1Padding";
	
	// Variable
	// 타인이 KeyFile 이름을 바꾸지 못하도록 private 접근자 선언 후 File 이름 관리
	private String senderPublicKeyFile;
	private String receiverPublicKeyFile;
	
	private String senderPrivateKeyFile;
	private String receiverPrivateKeyFile;
	
	// Constructor
	public SerialKey() {
		
	}
	
	// 뭔가 얘도 String 하나만 해서 코드 줄일 수 있을 것 같은데...
	public SerialKey(String senderId, String receiverId) {
		senderPublicKeyFile = senderId + "_publicKey";
		receiverPublicKeyFile = receiverId + "_publiKey";
		
		senderPrivateKeyFile  = senderId + "_privateKey";
		receiverPrivateKeyFile = receiverId + "_privateKey";
	}
	
	// Getter
	// 역직렬화나 암호화 시에 사용해야하므로 getter 선언. 값만 가져올 수 있음.
	public String getSenderPublicKeyFile() {
		return senderPublicKeyFile;
	}

	public String getReceiverPublicKeyFile() {
		return receiverPublicKeyFile;
	}

	public String getSenderPrivateKeyFile() {
		return senderPrivateKeyFile;
	}

	public String getReceiverPrivateKeyFile() {
		return receiverPrivateKeyFile;
	}
	
	// 얘도 뭔가 굳이 MyKeyPair 두개 매개변수로 안받아도 만들수있을거같은데....
	// 송신자와 수신자의 KeyPair를 받아 직렬화해 파일에 저장하는 메소드
	void saveKeyPair(MyKeyPair senderKeyPair, MyKeyPair receiverKeyPair) throws FileNotFoundException, IOException {
		savePublicKey(senderKeyPair.getPublicKey(), senderPublicKeyFile);
		savePrivateKey(senderKeyPair.getPrivateKey(), senderPrivateKeyFile);
		savePublicKey(receiverKeyPair.getPublicKey(), receiverPublicKeyFile);
		savePrivateKey(receiverKeyPair.getPrivateKey(), receiverPrivateKeyFile);
	}
	
	// 객체 직렬화를 이용하여 RSA키를 파일에 저장하는 메소드 (PublicKey)
	void savePublicKey(PublicKey publicKey, String fileName)
							throws FileNotFoundException, IOException {
	    // 직렬화 데이터를 파일에 저장
		try (FileOutputStream output = new FileOutputStream(fileName, false)) {
			try (ObjectOutputStream ostream = new ObjectOutputStream(output)) {
				ostream.writeObject(publicKey);
				System.out.println("공개 키 직렬화 성공 ! ");
			}
		} catch (IOException e) {
	        e.printStackTrace();
		}
	}	
	
	// 직렬화 된 데이터를 파일에서 불러와 다시 객체로 저장
	PublicKey restorePublicKey(String fileName)
			throws ClassNotFoundException, IOException {
		// 직렬화 된 데이터를 파일에서 불러오기
		PublicKey publicKey = null;
		try (FileInputStream fis = new FileInputStream(fileName)) {
			try (ObjectInputStream ois = new ObjectInputStream(fis)) {
				Object obj = ois.readObject();
				publicKey = (PublicKey) obj;
			}
			fis.close();
     }catch (FileNotFoundException e) {
         e.getStackTrace();
     }catch(IOException e){
         e.getStackTrace();
     }
		return publicKey;
	}
	
	// 객체 직렬화를 이용하여 RSA키를 파일에 저장하는 메소드 (PublicKey)
	void savePrivateKey(PrivateKey privateKey, String fileName)
							throws FileNotFoundException, IOException {
	    // 직렬화 데이터를 파일에 저장
		try (FileOutputStream output = new FileOutputStream(fileName, false)) {
			try (ObjectOutputStream ostream = new ObjectOutputStream(output)) {
				ostream.writeObject(privateKey);
				System.out.println("개인 키 직렬화 성공 ! ");
			}
		} catch (IOException e) {
	        e.printStackTrace();
		}
	}	
	
	// 직렬화 된 데이터를 파일에서 불러와 다시 객체로 저장
	PrivateKey restorePrivateKey(String fileName) throws ClassNotFoundException, IOException {
	    // 직렬화 된 데이터를 파일에서 불러오기
		PrivateKey privateKey = null;
		try (FileInputStream fis = new FileInputStream(fileName)) {
			try (ObjectInputStream ois = new ObjectInputStream(fis)) {
				Object obj = ois.readObject();
				privateKey = (PrivateKey) obj;
			}
			fis.close();
     }catch (FileNotFoundException e) {
         e.getStackTrace();
     }catch(IOException e){
         e.getStackTrace();
     }
		return privateKey;
	}
	
	byte[] encrypt(PublicKey publicKey, String sKeyFileName)
			throws GeneralSecurityException, IOException {
		
		SecretKey sKey = MySecretKey.restoreSecretKey(sKeyFileName);
				//readFile(sKeyFileName);
		
		System.out.println("encrypt()메소드 진입 <비밀키 역직렬화 결과 > : " 
		+ bytesToHex(sKey.getEncoded()));
		System.out.println(sKey.getEncoded().length);
		
		Cipher cipher = Cipher.getInstance(cipherAlgo);
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] encryptData = cipher.doFinal(sKey.getEncoded());
		return encryptData;
	}

	byte[] decrypt(PrivateKey privateKey, byte[] encryptData)
			throws GeneralSecurityException, IOException {
		Cipher cipher = Cipher.getInstance(cipherAlgo);
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] plainData = cipher.doFinal(encryptData);
		return plainData;
	}

	byte[] readFile(String fileName) throws IOException {
	    // 전자서명 파일에 있는 byte[] 읽기
		Path path = (new File(fileName)).toPath(); 
		byte[] rslt = Files.readAllBytes(path);
		
		return rslt;
	}
	
	String makeFile(String id, byte[] data) throws IOException {
	    // byte[] 파일에 저장해 전자서명 파일 만들기
	    if(data == null){
	        return null;
	    }
	    
	    String fileName = id + "_sign";

	    Path path = (new File(fileName)).toPath(); 
		Files.write(path, data);
		
		return fileName;
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
