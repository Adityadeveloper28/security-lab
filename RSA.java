import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;

public class RSA {
	private BigInteger privateKey;
	private BigInteger publicKey;
	private BigInteger modulus;

	public RSA(int bitLength) {
		SecureRandom random = new SecureRandom();
		BigInteger p = BigInteger.probablePrime(bitLength, random);
		BigInteger q = BigInteger.probablePrime(bitLength, random);

		modulus = p.multiply(q);
		BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

		publicKey = new BigInteger("65537"); // Common choice for e
		privateKey = publicKey.modInverse(phi);
	}

	public BigInteger encrypt(BigInteger message) {
		return message.modPow(publicKey, modulus);
	}

	public BigInteger decrypt(BigInteger encryptedMessage) {
		return encryptedMessage.modPow(privateKey, modulus);
	}

	public static void main(String[] args) {
		Scanner scanner = new Scanner(System.in);

		System.out.print("Enter the bit length for RSA key generation: ");
		int bitLength = scanner.nextInt();

		RSA rsa = new RSA(bitLength);

		scanner.nextLine(); // Consume the newline

		System.out.print("Enter the message to be encrypted: ");
		String originalMessageStr = scanner.nextLine();
		BigInteger originalMessage = new BigInteger(originalMessageStr.getBytes());

		System.out.println("Original Message: " + originalMessageStr);

		BigInteger encryptedMessage = rsa.encrypt(originalMessage);
		System.out.println("Encrypted Message: " + encryptedMessage);

		BigInteger decryptedMessage = rsa.decrypt(encryptedMessage);
		String decryptedMessageStr = new String(decryptedMessage.toByteArray());
		System.out.println("Decrypted Message: " + decryptedMessageStr);
	}
}
// ouput:
// Enter the bit length for RSA key generation: 1054
// Enter the message to be encrypted: hello
// Original Message: hello
// Encrypted Message:
// 25909231741089217864659090293339141066867564253217130390525548147515883653123857702564455435614573790731391681352403907725257489874560620528803430507727636050557614114344173399619917618453584393404299990049176401429194473215552476948384517577189129243692887527943070008010164225711515162958644108841560640156266739525609075845318960955582062707794160618297144033375919642317518032116329578089394749047132100049648906528751941226614403875752128636163787924417226755378340356029765900334985285870508198362900088750962110974936594675658005132973232817100001995061126092866491010872555221778339476882317262484377810654610050539920788734572
// Decrypted Message: hello*