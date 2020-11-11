package practice09_backup;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Scanner;

import javax.crypto.Cipher;

/* 20170969 컴퓨터학과 이지은
 * 20170971 컴퓨터학과 이채정
 */
public class Practice_09 {

	// String : id
	// Document : 해당하는 id의 원본 데이터 파일, 공개 키 직렬화 파일, private/public KeyPair, 전자서명 파일을 담고 있는 객체
	private static HashMap<String, MyKeyPair> user = new HashMap<String, MyKeyPair>();
	
	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub

		Scanner scan = new Scanner(System.in);
		
		System.out.print("당신이 진행하고 싶은 작업을 선택해주세요 (0-종료/1-송신/2-수신 및 검증) : ");
		int work = scan.nextInt();
		
		while(work != 0) {
			
			String id=" ";
			if(work == 1) {
				// 송신
				do {
					System.out.print("당신의 ID를 입력해주세요 : ");
					id = scan.next();
				}while(isDuplicatedId(id) == true); 

				// keyLength를 1024로 하는게 맞는지 모르겠음. 일단 이 전 과제에서 이렇게 했길래...
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
				System.out.print("당신이 서명할 파일의 이름을 입력해주세요. : ");
				String fileName = scan.next();
				
				DigitSign digitSign = new DigitSign();
				byte[] signRslt = digitSign.sign(fileName, priKeyFileName);
			
				String makeFile = digitSign.makeFile(id, signRslt);
				
				if(makeFile == null) {
					System.err.println("파일 생성 실패 !!");
				}
				
				// HashMap에 ID를 key로, Document 객체를 Value로 하는 객체 추가
				user.put(id, keyPair);
				// 만든 private Key랑 문서 내용을 가지고 전자서명 생성
			} else if(work == 2) {
				// 수신
				System.out.print("당신이 가지고 있는 키 파일의 이름을 입력해주세요. : ");
				String keyFileName = scan.next();
				
				System.out.print("당신이 가지고 있는 원본 파일 이름을 입력해주세요. : ");
				String textFile = scan.next();
				
				System.out.print("당신이 가지고 있는 서명문 파일 이름을 입력해주세요 : ");
				String signFile = scan.next();
				
				// 키 문서 주인의 아이디를 받아 HashMap에 저장되어 있는 Document 객체 가져오기
				// Document 객체에 저장되어 있는 데이터를 바탕으로 verify 함수 호출, 필요한 매개변수 전달

				DigitSign digitSign = new DigitSign();
				System.out.println(digitSign.verify(textFile, signFile, keyFileName));
			}	else {
				System.out.println("Wrong Number !!!!!");
			}

			System.out.print("당신이 진행하고 싶은 작업을 선택해주세요 (0-종료/1-송신/2-수신 및 검증) : ");
			work = scan.nextInt();
		}
	}

	// hashMap에 중복되는 id가 있는지 판별하는 메소드
	public static boolean isDuplicatedId(String id) {
		if(user.containsKey(id)) {
			System.err.println("중복된 ID입니다. 다른 ID를 사용해주세요.");
		}
		return user.containsKey(id);
	}

}
