package practice10_backup;

import java.nio.file.NoSuchFileException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Formatter;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.SecretKey; 
import javax.crypto.spec.SecretKeySpec;
//main함수 있는 곳 
public class Practice10 
{

	public static void main(String[] args) throws Exception 
	{
		Scanner scan = new Scanner(System.in);
		
		System.out.println("전자봉투 (Digital Envelope) ");
		System.out.print("당신이 진행하고 싶은 작업을 선택해주세요 (0-종료/1-송신/2-수신 및 검증) : ");
		int work = scan.nextInt();
		
		Map<String, String> userPrivateKeyMap = new HashMap<>(); //수신자와 수신자의 개인키 맵핑
		//Map<String, EncryptSet> userEncryptMap = new HashMap<>(); // 비밀키파일네임과 송신자가 전달할(데이터파일네임, 전자서명, 인증서) 맵핑
		//Map<String, byte[]> userEnvelopeMap = new HashMap<>(); //수신자와 전자봉투를 맵핑
		Map<String, String> sendResultMap = new HashMap<>(); //수신자와 최종전달받은 것
		
		
		PublicKey publicKeyA = null;
		PrivateKey privateKeyA = null;	
		PublicKey publicKeyB = null;
		PrivateKey privateKeyB = null;

		byte[] encryptData = null;
		byte[] encryptSig = null;
		byte[] encryptPublic = null;	
		byte[] envelope = null; //전자봉투 
		
		while(work != 0) {
			String filename;
			String senderPubKeyFile;
			String senderPriKeyFile;
			String receiverPubKeyFile;
			String recevierPriKeyFile;
			
			DigitSign digitSign = new DigitSign();
			SerialKey serialKey = new SerialKey();
			
			
			if(work == 1) { // 송신
				System.out.print("당신의 ID를 입력하세요 : ");
				String senderId = scan.next();
				System.out.print("수신자의 ID를 입력하세요 : ");
				String receiverId = scan.next();
				
				System.out.print("전자봉투를 생성할 데이터 파일의 이름을 입력해주세요. : ");
				filename = scan.next();
				
				senderPubKeyFile = senderId + "PublicKey.txt";
				senderPriKeyFile = senderId + "PrivateKey.txt";
				receiverPubKeyFile = receiverId + "PubliKey.txt";
				recevierPriKeyFile = receiverId + "PrivateKey.txt";
				
				// 송신자의 Public Key & Private Key 생성
				MyKeyPair senderKeyPair = MyKeyPair.getInstance();
				senderKeyPair.createKeys();
				// 수신자의 Public Key & Private Key 생성
				MyKeyPair receiverKeyPair = MyKeyPair.getInstance();
				receiverKeyPair.createKeys();
				
		// 송신자와 수신자의 KeyPair를 생성해서 파일로 직렬화하기 
				userPrivateKeyMap.put(receiverId, recevierPriKeyFile);
				
				serialKey.savePublicKey(senderKeyPair.getPublicKey(), senderPubKeyFile);
				serialKey.savePrivateKey(senderKeyPair.getPrivateKey(), senderPriKeyFile);
				serialKey.savePublicKey(receiverKeyPair.getPublicKey(), receiverPubKeyFile);
				serialKey.savePrivateKey(receiverKeyPair.getPrivateKey(), recevierPriKeyFile);
				
		// 먼저, 송신자의 전자서명 생성 	
				byte[] signature = digitSign.sign(filename, senderPriKeyFile);
				System.out.println("서명문(전자서명): " + bytesToHex(signature));
				
		// 평문, 전자서명, 인증서를 객체에 담아 직렬화하기 
				PlainSet plainSet = new PlainSet(filename, signature, senderPubKeyFile);
				System.out.println("철수가 보낼 원본파일네임: " + filename);
				System.out.println("철수가 보낼 전자서명: " + bytesToHex(signature));
				System.out.println("철수가 보낼 철수의 공개키 파일네임: " + senderPubKeyFile);
				SerialSet serialSet = new SerialSet();
				byte[] dataSet = serialSet.serialization(plainSet);
				
				
		//AES 비밀키 생성해서 encryptSet을 암호화한다.
				SerialSecretKey seialSecretKey = new SerialSecretKey();
				SecretKey secretKey = seialSecretKey.generateKey();
		
				System.out.println("여기는 메인함수에서 비밀키 생성 후 다시 확인하는 곳");
				System.out.println("비밀키 생성 : " + bytesToHex(secretKey.getEncoded()));
			    System.out.println("비밀키 길이 : " + secretKey.getEncoded().length);
				
			    //MySecretKey mySecretKey = new MySecretKey();
				String sKeyFileName = receiverId+"_secretKeyFile";
				MySecretKey.saveSecretKey(secretKey, sKeyFileName);
			
		// 비밀키를 수신자 B의 공개키로 암호화 ---> 이것이 전자봉투이다. 
				envelope = serialKey.encrypt(receiverKeyPair.getPublicKey(), sKeyFileName); //비밀키파일네임 
				System.out.println("전자봉투: " + bytesToHex(envelope));
				System.out.println(); 
				
		//그 세가지 데이터를 직렬화한 byte[]를 비밀키로 암호화한다.
				byte[] encryptDataSet = MySecretKey.encrypt(secretKey, dataSet);
				
		// 세가지 암호화된 결과물과 전자봉투를 묶어서 최종적으로 직렬화해서 파일에 저장 
				//헐 여기 ㅇdataset이 아님 그 세가지를 암호화한 결과물이 들어가야함 
				DecryptSet decryptSet = new DecryptSet(encryptDataSet, envelope); //dataSet
				byte[] finalSet = serialSet.serialization(decryptSet);
				String finalFile = serialKey.makeFile(receiverId, finalSet);
				sendResultMap.put(receiverId, finalFile); //직렬화한 파일이름을 값으로 넣기 
				
			}else if(work == 2) { // 수신
				
				String userId;
				String finalFile;
				//do {
				System.out.print("당신의 ID를 입력하세요 : "); //영희 
				userId = scan.next(); 
					
				DecryptSet decryptSet = null;
				PrivateKey prKey = null;
				try {
					System.out.print("당신이 전달받은 파일명 입력하세요 : "); //영희 
					finalFile = scan.next(); 
					
					if(finalFile == null) {
						throw new FileNameException();
					}	
					
					if(userPrivateKeyMap.get(userId) == null) { 
						System.out.println("수신받을 것이 없습니다.");
						continue;
					}else { //수신받을것이 있으면 
						String prfilename = userPrivateKeyMap.get(userId);
								//finalFile;
								
						prKey = serialKey.restorePrivateKey(prfilename); //영희의 사설키 
					}
					
					SerialSet serialSet = new SerialSet();
					byte[] resultSet = serialKey.readFile(finalFile);
					
					decryptSet = (DecryptSet) serialSet.deserialization(resultSet);
					
				} catch (FileNameException e) {
					e.toString();
				} catch (NoSuchFileException e) {
					System.out.println(e.getMessage() + "는 없는 파일 입니다.");
				}
				
				
				//}while(!finalFile.equals(sendResultMap.get(userId)));

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
				
				SerialSecretKey serialSecretKey = new SerialSecretKey();
				
				MySecretKey mySecretKey = new MySecretKey();
				PlainSet receivePlainSet = mySecretKey.decrypt(secretKey, receiveDataSet);
			
				// A의 공개키로 전자서명 검증
				boolean verified = digitSign.verify(receivePlainSet.getDataFileName(), receivePlainSet.getSignature(), receivePlainSet.getPubFileName());
				System.out.println("영희가 받은 원본파일네임: " + receivePlainSet.getDataFileName());
				System.out.println("영희가 받은 전자서명: " + bytesToHex(receivePlainSet.getSignature()));
				System.out.println("영희가 받은 철수의 공개키 파일네임: " + receivePlainSet.getPubFileName());
				
				System.out.println("서명검증 = " + verified);
				
			}else {
				System.out.println("Wrong Number !!!!!");
			}

			System.out.print("당신이 진행하고 싶은 작업을 선택해주세요 (0-종료/1-송신/2-수신 및 검증) : ");
			work = scan.nextInt();
		}
		System.out.println("시스템이 종료되었습니다.");
		scan.close();
	}//여기까지 메인함수 
	

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
