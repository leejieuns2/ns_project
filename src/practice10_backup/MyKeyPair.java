package practice10_backup;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

/* 20170969 컴퓨터학과 이지은
 * 20170971 컴퓨터학과 이채정
 */
class MyKeyPair {
	
	private static final String keyAlgorithm = "RSA";
	
	private KeyPairGenerator keyGen;
	private KeyPair pair;
	
	private PrivateKey privateKey;
	private PublicKey publicKey;
	
	static MyKeyPair getInstance() throws NoSuchAlgorithmException {
		MyKeyPair rslt = new MyKeyPair();
		
		rslt.keyGen = KeyPairGenerator.getInstance(keyAlgorithm);
		rslt.keyGen.initialize(2048);
		
		return rslt;
	}
	
	void createKeys() {
		this.pair = this.keyGen.generateKeyPair();
		this.privateKey = pair.getPrivate();
		this.publicKey = pair.getPublic();
	}
	
	public PrivateKey getPrivateKey() {
		return this.privateKey;
	}
	
	public PublicKey getPublicKey() {
		return this.publicKey;
	}
}