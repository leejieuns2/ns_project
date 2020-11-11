package practice10;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/* 20170969 컴퓨터학과 이지은
 * 20170971 컴퓨터학과 이채정
 */
// 전자서명 생성, 검증
class DigitSign {

	private static final String signAlgorithm = "SHA1withRSA";
	private static SerialKey serialKey = new SerialKey();
	
	//keyFileName privateKey로 바꿔야함.
	byte[] sign(String dataFileName, String keyFileName) 
			throws NoSuchAlgorithmException, IOException, ClassNotFoundException, SignatureException, InvalidKeyException {
		
		// Create an instance
		Signature signature = Signature.getInstance(signAlgorithm);
	
		// 공개 키 파일을 읽어 key 가져오기
		PrivateKey privateKey = serialKey.restorePrivateKey(keyFileName);
		// Initialize the signer with private or public key
		signature.initSign(privateKey);
		
		byte[] datafile = readFile(dataFileName);
		if (datafile == null) {
			System.out.println("DataFile not exist");
			return null;
		}
		// add data for verification
		signature.update(datafile);
		
		byte[] signatureData = signature.sign();
		return signatureData;
	}
	
	boolean verify(String dataFileName, byte[] sigData, String keyFileName) 
			throws SignatureException, ClassNotFoundException, IOException, NoSuchAlgorithmException, 
					NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {	
		
		// Create an instance
		Signature signature = Signature.getInstance(signAlgorithm);
		
		// 공개 키 파일을 읽어 key 가져오기
		PublicKey publicKey = serialKey.restorePublicKey(keyFileName);

		// Initialize the signer with private or public key
		signature.initVerify(publicKey);
		
		// Add data for signing
		byte[] data = readFile(dataFileName);
		signature.update(data);
		
		// Verify the signature
		return signature.verify(sigData);
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
	
	static byte[] readFile(String fileName) throws IOException {
	    // 전자서명 파일에 있는 byte[] 읽기
		Path path = (new File(fileName)).toPath(); 
		byte[] rslt = Files.readAllBytes(path);
		
		return rslt;
	}
}
