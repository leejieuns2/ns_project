package practice10;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

class SerialSet {
	
	byte[] serialization(PlainSet encryptSet){

		try(ByteArrayOutputStream baos = new ByteArrayOutputStream()){
			
			try(ObjectOutputStream oos = new ObjectOutputStream(baos)){
				oos.writeObject(encryptSet);
				byte[] rst = baos.toByteArray();
				return rst;
			} catch (IOException e) {
				e.printStackTrace();
			}
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		return null; //null 익셉션 처리해주기 
	}

	Object deserialization(byte[] set) {
		
		try(ByteArrayInputStream bais = new ByteArrayInputStream(set)){
			
			try(ObjectInputStream ois = new ObjectInputStream(bais)){
				Object obj =  ois.readObject();
				return obj;
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			}	
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return null;   //null 익셉션 처리해주기 
	}
	
	
	//decryptSet 오버로드함 
	byte[] serialization(DecryptSet decryptSet){

		try(ByteArrayOutputStream baos = new ByteArrayOutputStream()){
			
			try(ObjectOutputStream oos = new ObjectOutputStream(baos)){
				oos.writeObject(decryptSet);
				byte[] rst = baos.toByteArray();
				return rst;
			} catch (IOException e) {
				e.printStackTrace();
			}
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		return null; //null 익셉션 처리해주기 
	}
	
}
