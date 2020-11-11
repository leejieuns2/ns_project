package practice10_backup;


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
class SerialKey {
	public final static String cipherAlgo = "RSA/ECB/OAEPWithMD5AndMGF1Padding";
	
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
	
	public byte[] encrypt(PublicKey publicKey, String sKeyFileName)
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

	public byte[] decrypt(PrivateKey privateKey, byte[] encryptData)
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
