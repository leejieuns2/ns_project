package practice09;


import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

// 객제를 직렬화해서 파일에 저장.
class SerialKey {
	
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
}
