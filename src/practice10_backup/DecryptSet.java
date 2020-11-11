package practice10_backup;

import java.io.Serializable;

public class DecryptSet implements Serializable{ //수신자가 전달받은 것
	
	private static final long serialVersionUID = 1L;
	
	byte[] encryptSet; //plainSet을 암호화한것
	byte[] encryptEnvelope; // 전자봉투를 암호화한것 

	public DecryptSet() {
		super();
	}
	
	public DecryptSet(byte[] encryptSet, byte[] encryptEnvelope) {
		this.encryptSet = encryptSet;
		this.encryptEnvelope = encryptEnvelope;
	}
	
	public byte[] getEncryptSet() {
		return encryptSet;
	}
	public void setEncryptSet(byte[] encryptSet) {
		this.encryptSet = encryptSet;
	}
	public byte[] getEncryptEnvelope() {
		return encryptEnvelope;
	}
	public void setEncryptEnvelope(byte[] encryptEnvelope) {
		this.encryptEnvelope = encryptEnvelope;
	}

	
	
	
	

}
