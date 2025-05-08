package dev.luin.file.common.encryption;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Objects;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;

class Test1 {
	byte[] sample = Base64.decode(
			"mQGiBEA83v0RBADzKVLVCnpWQxX0LCsevw/3OLs0H7MOcLBQ4wMO9sYmzGYn"
					+ "xpVj+4e4PiCP7QBayWyy4lugL6Lnw7tESvq3A4v3fefcxaCTkJrryiKn4+Cg"
					+ "y5rIBbrSKNtCEhVi7xjtdnDjP5kFKgHYjVOeIKn4Cz/yzPG3qz75kDknldLf"
					+ "yHxp2wCgwW1vAE5EnZU4/UmY7l8kTNkMltMEAJP4/uY4zcRwLI9Q2raPqAOJ"
					+ "TYLd7h+3k/BxI0gIw96niQ3KmUZDlobbWBI+VHM6H99vcttKU3BgevNf8M9G"
					+ "x/AbtW3SS4De64wNSU3189XDG8vXf0vuyW/K6Pcrb8exJWY0E1zZQ1WXT0gZ"
					+ "W0kH3g5ro//Tusuil9q2lVLF2ovJA/0W+57bPzi318dWeNs0tTq6Njbc/GTG"
					+ "FUAVJ8Ss5v2u6h7gyJ1DB334ExF/UdqZGldp0ugkEXaSwBa2R7d3HBgaYcoP"
					+ "Ck1TrovZzEY8gm7JNVy7GW6mdOZuDOHTxyADEEP2JPxh6eRcZbzhGuJuYIif"
					+ "IIeLOTI5Dc4XKeV32a+bWrQidGVzdCAoVGVzdCBrZXkpIDx0ZXN0QHViaWNh"
					+ "bGwuY29tPohkBBMRAgAkBQJAPN79AhsDBQkB4TOABgsJCAcDAgMVAgMDFgIB"
					+ "Ah4BAheAAAoJEJh8Njfhe8KmGDcAoJWr8xgPr75y/Cp1kKn12oCCOb8zAJ4p"
					+ "xSvk4K6tB2jYbdeSrmoWBZLdMLACAAC5AQ0EQDzfARAEAJeUAPvUzJJbKcc5"
					+ "5Iyb13+Gfb8xBWE3HinQzhGr1v6A1aIZbRj47UPAD/tQxwz8VAwJySx82ggN"
					+ "LxCk4jW9YtTL3uZqfczsJngV25GoIN10f4/j2BVqZAaX3q79a3eMiql1T0oE"
					+ "AGmD7tO1LkTvWfm3VvA0+t8/6ZeRLEiIqAOHAAQNBACD0mVMlAUgd7REYy/1"
					+ "mL99Zlu9XU0uKyUex99sJNrcx1aj8rIiZtWaHz6CN1XptdwpDeSYEOFZ0PSu"
					+ "qH9ByM3OfjU/ya0//xdvhwYXupn6P1Kep85efMBA9jUv/DeBOzRWMFG6sC6y"
					+ "k8NGG7Swea7EHKeQI40G3jgO/+xANtMyTIhPBBgRAgAPBQJAPN8BAhsMBQkB"
					+ "4TOAAAoJEJh8Njfhe8KmG7kAn00mTPGJCWqmskmzgdzeky5fWd7rAKCNCp3u"
					+ "ZJhfg0htdgAfIy8ppm05vLACAAA=");

	int encryptionAlgorithm = SymmetricKeyAlgorithmTags.AES_256;
	int compressionAlgorithm = CompressionAlgorithmTags.UNCOMPRESSED;
	boolean armorOutput = true;
	boolean withIntegrityPacket = true;
	int bufferSize = 1 << 16;

	static {
		if (Objects.isNull(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)))
			Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	void testArmor() throws IOException {
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		ArmoredOutputStream aOut = new ArmoredOutputStream(bOut);
		aOut.write(sample);
		aOut.close();
		System.out.println(bOut.toString());
		ArmoredInputStream aIn = new ArmoredInputStream(new ByteArrayInputStream(bOut.toByteArray()));
		byte[] msg = aIn.readAllBytes();
		aIn.close();
		assertThat(sample).isEqualTo(msg);
	}

	@Test
	void testArmor1() throws IOException {
		byte[] msg = "Dit is een sample.".getBytes();
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		ArmoredOutputStream aOut = new ArmoredOutputStream(bOut);
		aOut.write(msg);
		aOut.close();
		System.out.println(bOut.toString());
		ArmoredInputStream aIn = new ArmoredInputStream(new ByteArrayInputStream(bOut.toByteArray()));
		byte[] data = aIn.readAllBytes();
		aIn.close();
		assertThat(data).isEqualTo(msg);
	}

	@Test
	void testArmor2() throws IOException {
		byte[] msg = "Dit is een sample.".getBytes();
		ByteArrayInputStream in = new ByteArrayInputStream(msg);
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		ArmoredOutputStream aOut = new ArmoredOutputStream(bOut);
		in.transferTo(aOut);
		aOut.close();
		System.out.println(bOut.toString());
		ArmoredInputStream aIn = new ArmoredInputStream(new ByteArrayInputStream(bOut.toByteArray()));
		byte[] data = aIn.readAllBytes();
		aIn.close();
		assertThat(data).isEqualTo(msg);
	}

	@Test
	void testArmor3() throws Exception {
		byte[] msg = Strings.toByteArray("Hello, world!");

		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		ArmoredOutputStream aOut = new ArmoredOutputStream(bOut);

		PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();

		OutputStream lOut = lGen.open(aOut, PGPLiteralData.TEXT,
				PGPLiteralData.CONSOLE, msg.length, new Date());

		lOut.write(msg);
		lOut.close();

		aOut.close();

		System.out.println(Strings.fromByteArray(bOut.toByteArray()));

		PGPObjectFactory oIn = new JcaPGPObjectFactory(new ArmoredInputStream(new ByteArrayInputStream(bOut.toByteArray())));

		PGPLiteralData ld = (PGPLiteralData)oIn.nextObject();
		byte[] data = Streams.readAll(ld.getDataStream());

		assertThat(data).isEqualTo(msg);
	}

	@Test
	void encryptDecryptMultiChunkTest() throws Exception {
		SecureRandom random = new SecureRandom();
		byte[] msg = new byte[60000];

		random.nextBytes(msg);

		KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

		kpGen.initialize(2048);

		PGPKeyPair pgpKp = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, kpGen.generateKeyPair(), new Date());

		PGPPublicKey pubKey = pgpKp.getPublicKey();

		PGPPrivateKey privKey = pgpKp.getPrivateKey();

		ByteArrayOutputStream cbOut = new ByteArrayOutputStream();
		JcePGPDataEncryptorBuilder encryptorBuilder = new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_128)
				.setSecureRandom(random).setProvider("BC");

		encryptorBuilder.setUseV5AEAD();
		encryptorBuilder.setWithAEAD(AEADAlgorithmTags.OCB, 6);

		PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(encryptorBuilder);

		cPk.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pubKey).setProvider("BC"));

		ByteArrayOutputStream ldbOut = new ByteArrayOutputStream();
		PGPLiteralDataGenerator ldGen = new PGPLiteralDataGenerator();

		OutputStream ldOut = ldGen.open(ldbOut, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, (long) msg.length,
				new Date());

		ldOut.write(msg);

		ldOut.close();

		byte[] litData = ldbOut.toByteArray();

		// Added Armor
		OutputStream cOut = cPk.open(armorOutput ? new ArmoredOutputStream(cbOut) : cbOut, litData.length);

		cOut.write(litData);

		cOut.close();

		System.out.println(cbOut.toString());

		// decrypt
		// Added Armor
		PGPObjectFactory oIn = new JcaPGPObjectFactory(
				armorOutput ? new ArmoredInputStream(new ByteArrayInputStream(cbOut.toByteArray()))
						: new ByteArrayInputStream(cbOut.toByteArray()));

		PGPEncryptedDataList encList = (PGPEncryptedDataList) oIn.nextObject();

		PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData) encList.get(0);

		InputStream clear = encP
				.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privKey));

		// System.err.println(Hex.toHexString(Streams.readAll(clear)));
		PGPObjectFactory pgpFact = new JcaPGPObjectFactory(clear);

		PGPLiteralData ld = (PGPLiteralData) pgpFact.nextObject();

		// isEquals("wrong filename", PGPLiteralData.CONSOLE, ld.getFileName());
		assertThat(ld.getFileName()).isEqualTo(PGPLiteralData.CONSOLE);

		byte[] data = Streams.readAll(ld.getDataStream());

		assertThat(data).isEqualTo(msg);
		// isTrue("msg mismatch", Arrays.areEqual(msg, data));
	}

	@Test
	void encryptDecryptMultiChunkBoundaryTest() throws Exception {
		SecureRandom random = new SecureRandom();
		byte[] msg = new byte[(1 << 6) * 5 - 17]; // take of literal data header

		random.nextBytes(msg);

		KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

		kpGen.initialize(2048);

		PGPKeyPair pgpKp = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, kpGen.generateKeyPair(), new Date());

		PGPPublicKey pubKey = pgpKp.getPublicKey();

		PGPPrivateKey privKey = pgpKp.getPrivateKey();

		ByteArrayOutputStream cbOut = new ByteArrayOutputStream();
		JcePGPDataEncryptorBuilder encryptorBuilder = new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_128)
				.setSecureRandom(random).setProvider("BC");

		encryptorBuilder.setUseV5AEAD();
		encryptorBuilder.setWithAEAD(AEADAlgorithmTags.OCB, 6);

		PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(encryptorBuilder);

		cPk.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pubKey).setProvider("BC"));

		ByteArrayOutputStream ldbOut = new ByteArrayOutputStream();
		PGPLiteralDataGenerator ldGen = new PGPLiteralDataGenerator();

		OutputStream ldOut = ldGen.open(ldbOut, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, (long) msg.length,
				new Date());

		ldOut.write(msg);

		ldOut.close();

		byte[] litData = ldbOut.toByteArray();

		// Added Armor
		OutputStream cOut = cPk.open(armorOutput ? new ArmoredOutputStream(cbOut) : cbOut, litData.length);

		cOut.write(litData);

		cOut.close();

		System.out.println(cbOut.toString());

		// decrypt
		// Added Armor
		PGPObjectFactory oIn = new JcaPGPObjectFactory(
				armorOutput ? new ArmoredInputStream(new ByteArrayInputStream(cbOut.toByteArray()))
						: new ByteArrayInputStream(cbOut.toByteArray()));

		PGPEncryptedDataList encList = (PGPEncryptedDataList) oIn.nextObject();

		PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData) encList.get(0);

		InputStream clear = encP
				.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privKey));

		// System.err.println(Hex.toHexString(Streams.readAll(clear)));
		PGPObjectFactory pgpFact = new JcaPGPObjectFactory(clear);

		PGPLiteralData ld = (PGPLiteralData) pgpFact.nextObject();

		// isEquals("wrong filename", PGPLiteralData.CONSOLE, ld.getFileName());
		assertThat(ld.getFileName()).isEqualTo(PGPLiteralData.CONSOLE);

		byte[] data = Streams.readAll(ld.getDataStream());

		assertThat(data).isEqualTo(msg);
		// isTrue("msg mismatch", Arrays.areEqual(msg, data));
	}
}
