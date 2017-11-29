import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Scanner;
import java.util.zip.CRC32;

import javax.crypto.*;

public class FileTransfer {

	public static void main(String[] args) {
		if ( args.length < 1 || args.length > 4){
			printUsageInstructions();
		} else if ( args[0].equals("makekeys") ){
			makeKeys();
		} else if ( args.length == 3 && args[0].equals("server") ){
			int portNumber = Integer.parseInt(args[2]);
			server(args[1], portNumber);
		} else if (  args.length == 4 && args[0].equals("client") ){
			int portNumber = Integer.parseInt(args[3]);
			client(args[1], args[2], portNumber);
		} else {
			printUsageInstructions();
		}
	}

	private static void client(String keyPath, String ip, int portNumber) {
		Scanner kb = new Scanner(System.in);
		try (Socket socket = new Socket(ip, portNumber)) {
			System.out.printf("Connected to server: %s:%d%n",ip,portNumber);
			System.out.print("Enter path: ");
			String targetFilePath = kb.nextLine();
			System.out.print("Enter chunk size [1024]: ");
			int chunkSize;
			try {
				chunkSize = Integer.parseInt(kb.nextLine());
			} catch (NumberFormatException e ){
				chunkSize = 1024;
			}
			File file = new File(targetFilePath);
			if ( file.exists() ){
				PublicKey publicKey = loadPublicKey(keyPath);
				Key secretKey = generateAESKey();
				byte[] wrappedSessionKey = wrapCipherKey(publicKey, secretKey);
				Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
				cipher.init(Cipher.ENCRYPT_MODE, secretKey );
				Chunk[] chunks = getChunks(file, chunkSize, cipher);
				System.out.printf("Sending: %s. File size:%d%n",targetFilePath,file.length());
				System.out.println("Sending " + chunks.length + " chunks.");
				ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
				ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
				StartMessage startMessage = new StartMessage(targetFilePath, wrappedSessionKey, 
						chunkSize);
				oos.writeObject(startMessage);
				boolean done = false;
				int counter = 0;
				while ( !done ){
					AckMessage reply = (AckMessage)ois.readObject();
					if (counter == chunks.length || reply.getSeq() == -1 ){
						done = true;
					} else  if (reply.getSeq() == counter ){
						oos.writeObject(chunks[counter]);
						System.out.printf("Chunks completed [%d/%d]%n",counter+1,chunks.length);
					} else {
						System.out.println("Incorrect Seq Number. Aborting..");
						oos.writeObject(new StopMessage(targetFilePath));
						done = true;
					}
					counter++;
				}
				oos.writeObject(new DisconnectMessage());
				//System.out.println("File transfer complete.");
			}
		} catch ( Exception e ){
			e.printStackTrace();
		} finally {
			System.out.println("Disconnected from server.");
		}
	}

	private static byte[] wrapCipherKey(PublicKey publicKey,Key key) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.WRAP_MODE, publicKey);
		byte[] wrappedSessionKey = cipher.wrap(key);
		return wrappedSessionKey;
	}

	private static PublicKey loadPublicKey(String keyPath) {
		PublicKey publicKey = null;
		try (ObjectInputStream ois = new ObjectInputStream(
				new FileInputStream(new File(keyPath)))) {
			publicKey = (PublicKey) ois.readObject();
		} catch ( IOException e){
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return publicKey;
	}

	private static PrivateKey loadPrivateKey(String keyPath) {
		PrivateKey privateKey = null;
		try (ObjectInputStream ois = new ObjectInputStream(
				new FileInputStream(new File(keyPath)))) {
			privateKey = (PrivateKey) ois.readObject();
		} catch ( IOException e){
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return privateKey;
	}

	private static Key generateAESKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128); 
		Key secretKey = keyGen.generateKey();
		return secretKey;
	}

	private static Chunk[] getChunks(File targetFile, int chunkSize, Cipher cipher) throws Exception{
		Chunk[] chunks = null;
		long fileSize = 0;
		try (FileInputStream f = new FileInputStream( targetFile )) {
			fileSize = targetFile.length();
			int numChunks = (int)Math.ceil((float)fileSize / chunkSize);
			chunks = new Chunk[ numChunks ];
			int i = 0;
			while( f.available() > 0){
				byte[] data = new byte[chunkSize];
				f.read(data);
				byte[] encryptedData = cipher.doFinal(data);
				CRC32 crc = new CRC32();
				crc.update(data);
				chunks[i] = new Chunk(i,encryptedData,(int)crc.getValue());
				i++;
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return chunks;
	}

	private static void server(String keyPath, int portNumber) {
		Scanner kb = new Scanner(System.in);
		try (ServerSocket serverSocket = new ServerSocket(portNumber)) {
			while (true) {
				System.out.println("Waiting for connection...");
				Socket socket = serverSocket.accept();
				System.out.println("Connected to client.");
				ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
				ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
				FileOutputStream fos = null;
				int seqNum = 0;
				int numChunks = 0;
				Cipher aesCipher = null;
				Message m = (Message)ois.readObject();
				do {
					if ( m.getType() == MessageType.START ){
						StartMessage startMessage = (StartMessage)m;
						System.out.print("Choose output path: ");
						String path = kb.nextLine();
						fos = new FileOutputStream(new File(path));
						aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
						Key key = unwrapSessionKey(loadPrivateKey(keyPath), startMessage.getEncryptedKey());
						aesCipher.init(Cipher.DECRYPT_MODE, key);
						numChunks = (int)Math.ceil((float)startMessage.getSize() / startMessage.getChunkSize());
						oos.writeObject( new AckMessage(0) );
					} else if ( m.getType() == MessageType.STOP ){
						oos.writeObject( new AckMessage(-1) );
					} else if ( m.getType() == MessageType.CHUNK ){
						Chunk chunk = (Chunk)m;
						System.out.printf("Chunk received [%d/%d].%n",seqNum+1,numChunks);
						byte[] decryptedData = aesCipher.doFinal(chunk.getData());
						if ( checkCRC(decryptedData, chunk.getCrc()) ){
							fos.write(decryptedData);
							oos.writeObject( new AckMessage(++seqNum) );
						} else {
							System.out.println("failed CRC. retrying seqnum " + seqNum);
							oos.writeObject( new AckMessage(seqNum) );
						}
						if ( seqNum == numChunks){
							fos.close();
						}
					}
					m = (Message)ois.readObject();
				} while ( m.getType() != MessageType.DISCONNECT );
				System.out.println("Transfer ended.\n");
				socket.close();
			}
		} catch ( BindException e ){
			System.out.println( "A server is already running, terminating...");
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private static boolean checkCRC(byte[] data, int crc) {
		CRC32 crcGen = new CRC32();
		crcGen.update(data);
		return crc == (int)crcGen.getValue();
	}

	private static Key unwrapSessionKey(PrivateKey privateKey, byte[] encryptedKey) {
		Key key = null;
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.UNWRAP_MODE, privateKey);
			key = cipher.unwrap(encryptedKey, "AES", Cipher.SECRET_KEY);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return key;
	}

	private static void makeKeys() {
		try {
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
			gen.initialize(4096); // you can use 2048 for faster key generation
			KeyPair keyPair = gen.genKeyPair();
			PrivateKey privateKey = keyPair.getPrivate();
			PublicKey publicKey = keyPair.getPublic();
			try (ObjectOutputStream oos = new ObjectOutputStream(
					new FileOutputStream(new File("public.bin")))) {
				oos.writeObject(publicKey);
			}
			try (ObjectOutputStream oos = new ObjectOutputStream(
					new FileOutputStream(new File("private.bin")))) {
				oos.writeObject(privateKey);
			}
			System.out.println("Successfully generated 4096-bit RSA keys. Saved to private.bin and public.bin");
		} catch (NoSuchAlgorithmException | IOException e) {
			e.printStackTrace(System.err);

		}
	}

	private static void printUsageInstructions() {
		System.out.println("Usage:\n"
				+ " FileTransfer makekeys\n"
				+ " FileTransfer server {priv_key.bin} {port#}\n"
				+ " FileTransfer client {pub_key.bin} {server_ip} {port}");
	}

}
