package practice10;

import java.nio.file.NoSuchFileException;
import java.security.PrivateKey;
import java.util.Formatter;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import javax.crypto.SecretKey; 
import javax.crypto.spec.SecretKeySpec;

// Main Function 
public class Practice10 {

	public static void main(String[] args) throws Exception  {
		Scanner scan = new Scanner(System.in);
		
		System.out.println("전자봉투 (Digital Envelope) ");
		System.out.print("당신이 진행하고 싶은 작업을 선택해주세요 (0-종료/1-송신/2-수신 및 검증) : ");
		int work = scan.nextInt();
		
		//수신자와 수신자의 개인키 맵핑
		Map<String, String> userPrivateKeyMap = new HashMap<>();
		
		//수신자와 최종전달받은 것	
		Map<String, String> sendResultMap = new HashMap<>();
		byte[] envelope = null; //전자봉투 
		
		SerialKey serialKey = null;
		DigitSign digitSign = null;
		
		while(work != 0) {						
			if(work == 1) { // 송신
				System.out.print("당신의 ID를 입력하세요 : ");
				String senderId = scan.next();
				System.out.print("수신자의 ID를 입력하세요 : ");
				String receiverId = scan.next();
				
				System.out.print("전자봉투를 생성할 데이터 파일의 이름을 입력해주세요. : ");
				String filename = scan.next();
				
				digitSign = new DigitSign();
				serialKey = new SerialKey(senderId, receiverId);	
				
		// 송신자의 Public Key & Private Key 생성
				MyKeyPair senderKeyPair = MyKeyPair.getInstance();
				senderKeyPair.createKeys();
				
		// 수신자의 Public Key & Private Key 생성
				MyKeyPair receiverKeyPair = MyKeyPair.getInstance();
				receiverKeyPair.createKeys();
				
		// 송신자와 수신자의 KeyPair를 생성해서 파일로 직렬화하기 
				userPrivateKeyMap.put(receiverId, serialKey.getReceiverPrivateKeyFile());
				
				serialKey.saveKeyPair(senderKeyPair, receiverKeyPair);

		// 먼저, 송신자의 전자서명 생성 	
				byte[] signature = digitSign.sign(filename, serialKey.getSenderPrivateKeyFile());
				System.out.println("서명문(전자서명): " + bytesToHex(signature));
				
		// 평문, 전자서명, 인증서를 객체에 담아 직렬화하기 
				PlainSet plainSet = new PlainSet(filename, signature, serialKey.getSenderPublicKeyFile());
				System.out.println("철수가 보낼 원본파일네임: " + filename);
				System.out.println("철수가 보낼 전자서명: " + bytesToHex(signature));
				System.out.println("철수가 보낼 철수의 공개키 파일네임: " + serialKey.getSenderPublicKeyFile());
				SerialSet serialSet = new SerialSet();
				byte[] dataSet = serialSet.serialization(plainSet);
				
				
		//AES 비밀키 생성해서 encryptSet을 암호화한다.
				MySecretKey mySecretKey = new MySecretKey();
				SecretKey secretKey = mySecretKey.generateKey();
		
				System.out.println("여기는 메인함수에서 비밀키 생성 후 다시 확인하는 곳");
				System.out.println("비밀키 생성 : " + bytesToHex(secretKey.getEncoded()));
			    System.out.println("비밀키 길이 : " + secretKey.getEncoded().length);
				
				String sKeyFileName = receiverId+"_secretKeyFile";
				mySecretKey.saveSecretKey(secretKey, sKeyFileName);
			
		// 비밀키를 수신자 B의 공개키로 암호화 ---> 이것이 전자봉투이다. 
				envelope = serialKey.encrypt(receiverKeyPair.getPublicKey(), sKeyFileName); //비밀키파일네임 
				System.out.println("전자봉투: " + bytesToHex(envelope));
				System.out.println(); 
				
		//그 세가지 데이터를 직렬화한 byte[]를 비밀키로 암호화한다.
				byte[] encryptDataSet = mySecretKey.encrypt(secretKey, dataSet);
				
		// 세가지 암호화된 결과물과 전자봉투를 묶어서 최종적으로 직렬화해서 파일에 저장 
				DecryptSet decryptSet = new DecryptSet(encryptDataSet, envelope); //dataSet
				byte[] finalSet = serialSet.serialization(decryptSet);
				String receiveFile = serialKey.makeFile(receiverId, finalSet);
				
				sendResultMap.put(receiverId, receiveFile); //직렬화한 파일이름을 값으로 넣기 
				
			}else if(work == 2) { // 수신
				
				String userId;
				String receiveFile;
				//do {
				System.out.print("당신의 ID를 입력하세요 : "); //영희 
				userId = scan.next(); 
					
				DecryptSet decryptSet = null;
				PrivateKey prKey = null;
				try {
					System.out.print("당신이 전달받은 파일명 입력하세요 : "); //영희 
					//영희는 암호문세트와 전자봉투를 전달받은 것임 
		            //-> 암호문 세트 파일 네임은 sendResultMap에 수신자 아이디에 맵핑된 값이다.  
					
					receiveFile = scan.next(); 
					
					if(receiveFile == null || !receiveFile.equals(sendResultMap.get(userId))) {
						throw new FileNameException();
					}	
					
					if(userPrivateKeyMap.get(userId) == null) { 
						System.out.println("수신받을 것이 없습니다.");
						continue;
					}else { //수신받을것이 있으면 
						String prfilename = userPrivateKeyMap.get(userId);
						prKey = serialKey.restorePrivateKey(prfilename); //영희의 사설키 
					}
					
					//수신자가 입력한 파일이 맞으면.. 이제 검증 .. 
	                //전자봉투는 원문파일을 전달받은게 아니므로.. 원본 데이터 파일을 임의로 내가 송신하고나서 위조하면 false가 떠야함 

					SerialSet serialSet = new SerialSet();
					byte[] resultSet = serialKey.readFile(receiveFile);
					decryptSet = (DecryptSet) serialSet.deserialization(resultSet);		
				} catch (FileNameException e) {
					e.toString();
				} catch (NoSuchFileException e) {
					System.out.println(e.getMessage() + "는 없는 파일 입니다.");
				}
				
				//영희가 받은 전자봉투
				byte[] receiveEnvelope = decryptSet.getEncryptEnvelope();
				System.out.println("영희가 받은 전자봉투: " + bytesToHex(receiveEnvelope));
				
				// 수신자 B의 개인키로 전자봉투를 복호화하여 비밀키 복구 -> 바이트 배열 !!!!!!!
				byte[] receiveSKey = serialKey.decrypt(prKey, receiveEnvelope);
				System.out.println("영희가 받은 비밀키 길이" + receiveSKey.length);
				System.out.println("비밀키 획득: "+ bytesToHex(receiveSKey));
				
				SecretKey secretKey = new SecretKeySpec(receiveSKey, "AES");
				
				//영희가 받은 암호문 세트
				byte[] receiveDataSet = decryptSet.getEncryptSet();
				
				MySecretKey mySecretKey = new MySecretKey();
				PlainSet receivePlainSet = mySecretKey.decrypt(secretKey, receiveDataSet);
			
				// A의 공개키로 전자서명 검증
				boolean verified = digitSign.verify(receivePlainSet.getDataFileName(), receivePlainSet.getSignature(), receivePlainSet.getPubFileName());
				System.out.println("수신자가 받은 원본파일네임: " + receivePlainSet.getDataFileName());
				System.out.println("수신자가 받은 전자서명: " + bytesToHex(receivePlainSet.getSignature()));
				System.out.println("수신자가 받은 철수의 공개키 파일네임: " + receivePlainSet.getPubFileName());
				System.out.println("Results of verification : " + verified);
			} else {
				// 이걸 try-catch문을 써서 WrongNumberException이라는 사용자 예외를 만들어 처리를 해야할지 고민쓰...
				System.out.println("Wrong Number !!!!!");
			}
			System.out.print("당신이 진행하고 싶은 작업을 선택해주세요 (0-종료/1-송신/2-수신 및 검증) : ");
			work = scan.nextInt();
		}
		System.out.println("시스템이 종료되었습니다.");
		scan.close();
	}
	
	static String bytesToHex(byte[] bytes) {
		StringBuilder sb = new StringBuilder(bytes.length * 2);
		
		@SuppressWarnings("resource")
		Formatter formatter = new Formatter(sb);
	
		for (byte b : bytes) {
			formatter.format("%02x", b);
		}
		return sb.toString();
	} 
}
