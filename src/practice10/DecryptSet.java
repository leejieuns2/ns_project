package practice10;

import java.io.Serializable;

//수신자가 전달받은 객체 (암호문, 전자봉투)
class DecryptSet implements Serializable{
	
	// final Variable
	private static final long serialVersionUID = 1L;
	
	// Variable
	byte[] encryptSet; //plainSet을 암호화한것
	byte[] encryptEnvelope; // 전자봉투를 암호화한것 

	// Constructor
	public DecryptSet() {
		super();
	}
	
	public DecryptSet(byte[] encryptSet, byte[] encryptEnvelope) {
		this.encryptSet = encryptSet;
		this.encryptEnvelope = encryptEnvelope;
	}
	
	// Setter & Getter
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
