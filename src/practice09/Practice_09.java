package practice09;

import java.nio.file.NoSuchFileException;
import java.security.InvalidKeyException;
import java.util.HashMap;
import java.util.Scanner;

/* 20170969 컴퓨터학과 이지은
 * 20170971 컴퓨터학과 이채정
 */
class Practice_09 {

	// String : id
	// MyKeyPair : private/public KeyPair
	private static HashMap<String, MyKeyPair> userKeyMap = new HashMap<String, MyKeyPair>();
	
	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub

		Scanner scan = new Scanner(System.in);
		
		System.out.println("전자서명 (Digital Sign)");
		System.out.print("당신이 진행하고 싶은 작업을 선택해주세요 (0-종료/1-송신/2-수신 및 검증) : ");
		int work = scan.nextInt();
		
		while(work != 0) {
			if(work == 1) {
				// 송신
				
				// 22
				String id;
				do {
					System.out.print("당신의 ID를 입력해주세요 : ");
					id = scan.next();			
				}while(!isValidId(id)); 

				// KeyPair 생성 (- KeyPair 직렬화해서 파일로 저장 여기서!!!)
				MyKeyPair keyPair = MyKeyPair.getInstance();
				SerialKey serialKey = new SerialKey();
				
				// Public Key & Private Key 생성
				keyPair.createKeys();
				
				// Public Key File 생성
				String pubKeyFileName = id + "_publicKey";
				String priKeyFileName = id + "_privateKey";
				
				serialKey.savePublicKey(keyPair.getPublicKey(), pubKeyFileName);
				serialKey.savePrivateKey(keyPair.getPrivateKey(), priKeyFileName);
				
				// 서명 내용을 저장하는 부분
				// 04
				try {
					System.out.print("당신이 서명할 파일의 이름을 입력해주세요. : ");
					String fileName = scan.next();
					
					if(fileName == null) {
						throw new FileNameException();
					}
					
					DigitSign digitSign = new DigitSign();
					byte[] signRslt = digitSign.sign(fileName, priKeyFileName);
				
					String makeFile = digitSign.makeFile(id, signRslt);
					
					if(makeFile == null) {
						throw new MakeFileException();
					}
				} catch (FileNameException e) {
					e.toString();
				} catch (MakeFileException e) {
					e.toString();
				} catch (NoSuchFileException e) {
					System.out.println(e.getMessage() + "는 없는 파일 입니다.");
				}
				
				// HashMap에 ID를 key로, Document 객체를 Value로 하는 객체 추가
				userKeyMap.put(id, keyPair);
				
			} else if(work == 2) {
				// 수신
				
				// 04
				try {
					System.out.print("당신이 가지고 있는 키 파일의 이름을 입력해주세요. : ");
					String keyFileName = scan.next();
					
					System.out.print("당신이 가지고 있는 원본 파일 이름을 입력해주세요. : ");
					String textFile = scan.next();
					
					System.out.print("당신이 가지고 있는 서명문 파일 이름을 입력해주세요 : ");
					String signFile = scan.next();
				
					if(keyFileName == null || textFile == null || signFile == null) {
						throw new FileNameException();
					}
					
					// 키 문서 주인의 아이디를 받아 HashMap에 저장되어 있는 Document 객체 가져오기
					// Document 객체에 저장되어 있는 데이터를 바탕으로 verify 함수 호출, 필요한 매개변수 전달

					DigitSign digitSign = new DigitSign();
					System.out.println(digitSign.verify(textFile, signFile, keyFileName));
				} catch (FileNameException e) {
					e.toString();
				} catch (InvalidKeyException e) {
					System.out.println(e.getMessage());
				}
			}	else {
				System.out.println("Wrong Number !!!!!");
			}

			System.out.print("당신이 진행하고 싶은 작업을 선택해주세요 (0-종료/1-송신/2-수신 및 검증) : ");
			work = scan.nextInt();
		}
		System.out.println("시스템이 종료되었습니다.");
		scan.close();
	}

	// hashMap에 중복되는 id가 있는지 판별하는 메소드
	static boolean isValidId(String id) {
		if(id == null || id == "") {
			// id null checking
			return false;
		} else if(userKeyMap.containsKey(id)) {
			// 중복 아이디 검사
			System.err.println("중복된 ID입니다. 다른 ID를 사용해주세요.");
			return false;
		}
		return true;
	}

}
