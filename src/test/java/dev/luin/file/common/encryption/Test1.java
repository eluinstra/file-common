package dev.luin.file.common.encryption;

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

import org.assertj.core.api.Assertions;
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
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;

import lombok.val;

class Test1
{
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
	boolean armorOutput = false;
	boolean withIntegrityPacket = true;
	int bufferSize = 1 << 16;

	static
	{
		if (Objects.isNull(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)))
			Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	void testArmor() throws IOException {
		val bOut = new ByteArrayOutputStream();
		val aOut = new ArmoredOutputStream(bOut);

		aOut.write(sample);

		aOut.close();

		System.out.println(bOut.toString());

		ArmoredInputStream aIn = new ArmoredInputStream(new ByteArrayInputStream(bOut.toByteArray()));

	}

	@Test
	void testArmor1() throws IOException {
		val bOut = new ByteArrayOutputStream();
		val aOut = new ArmoredOutputStream(bOut);

		aOut.write("Dit is een sample.".getBytes());

		aOut.close();

		System.out.println(bOut.toString());

		ArmoredInputStream aIn = new ArmoredInputStream(new ByteArrayInputStream(bOut.toByteArray()));

	}

	@Test
	void testArmor2() throws IOException {
		val in = new ByteArrayInputStream("Dit is een sample.".getBytes());
		val bOut = new ByteArrayOutputStream();
		val aOut = new ArmoredOutputStream(bOut);

		in.transferTo(aOut);

		aOut.close();

		System.out.println(bOut.toString());

		ArmoredInputStream aIn = new ArmoredInputStream(new ByteArrayInputStream(bOut.toByteArray()));

	}

	@Test
	void encryptDecryptMultiChunkTest() throws Exception
	{
		// SecureRandom random = new SecureRandom();
		val msg = new ByteArrayInputStream("Dit is een test.".getBytes());

		// random.nextBytes(msg);

		KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

		kpGen.initialize(2048);

		PGPKeyPair pgpKp = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, kpGen.generateKeyPair(), new Date());

		PGPPublicKey pubKey = pgpKp.getPublicKey();
		// PGPPublicKey pubKey = new PgpEngine().getEncryptionKey((getClass().getResourceAsStream("public_key.asc"))).get();

		PGPPrivateKey privKey = pgpKp.getPrivateKey();

		ByteArrayOutputStream cbOut = new ByteArrayOutputStream();
		// JcePGPDataEncryptorBuilder encryptorBuilder = new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256).setSecureRandom(random).setProvider("BC");
		JcePGPDataEncryptorBuilder encryptorBuilder = new JcePGPDataEncryptorBuilder(encryptionAlgorithm).setWithIntegrityPacket(withIntegrityPacket)
				.setSecureRandom(new SecureRandom())
				.setProvider(BouncyCastleProvider.PROVIDER_NAME);

		// encryptorBuilder.setUseV5AEAD();
		// encryptorBuilder.setWithAEAD(AEADAlgorithmTags.OCB, 6);

		PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(encryptorBuilder);

		cPk.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pubKey).setProvider("BC"));

		ByteArrayOutputStream ldbOut = new ByteArrayOutputStream();
		PGPLiteralDataGenerator ldGen = new PGPLiteralDataGenerator();

		// OutputStream ldOut = ldGen.open(ldbOut, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, (long)msg.length, new Date());
		OutputStream ldOut = ldGen.open(ldbOut, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, new Date(), new byte[bufferSize]);

		ldOut.write(msg.readAllBytes());

		ldOut.close();

		byte[] litData = ldbOut.toByteArray();

		// OutputStream cOut = cPk.open(cbOut, litData.length);
		OutputStream cOut = cPk.open(armorOutput ? new ArmoredOutputStream(cbOut) : cbOut, new byte[bufferSize]);

		cOut.write(litData);

		cOut.flush();
		cOut.close();

		System.out.println(cbOut.toString());

		// decrypt
		PGPObjectFactory oIn = new JcaPGPObjectFactory(armorOutput ? new ArmoredInputStream(new ByteArrayInputStream(cbOut.toByteArray())) : new ByteArrayInputStream(cbOut.toByteArray()));

		PGPEncryptedDataList encList = (PGPEncryptedDataList)oIn.nextObject();

		PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

		InputStream clear = encP.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privKey));

		// System.err.println(Hex.toHexString(Streams.readAll(clear)));
		PGPObjectFactory pgpFact = new JcaPGPObjectFactory(clear);

		PGPLiteralData ld = (PGPLiteralData)pgpFact.nextObject();

		// isEquals("wrong filename", PGPLiteralData.CONSOLE, ld.getFileName());
		Assertions.assertThat(ld.getFileName()).isEqualTo(PGPLiteralData.CONSOLE);

		byte[] data = Streams.readAll(ld.getDataStream());

		msg.reset();
		Assertions.assertThat(data).isEqualTo(msg.readAllBytes());
		// isTrue("msg mismatch", Arrays.areEqual(msg, data));
	}

	@Test
	void encryptDecryptMultiChunkTest1() throws Exception
	{
		SecureRandom random = new SecureRandom();
		byte[] msg = new byte[60000];

		random.nextBytes(msg);

		KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

		kpGen.initialize(2048);

		PGPKeyPair pgpKp = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL , kpGen.generateKeyPair(), new Date());

		PGPPublicKey pubKey = pgpKp.getPublicKey();

		PGPPrivateKey privKey = pgpKp.getPrivateKey();

		ByteArrayOutputStream cbOut = new ByteArrayOutputStream();
		JcePGPDataEncryptorBuilder encryptorBuilder = new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_128).setSecureRandom(random).setProvider("BC");

		encryptorBuilder.setUseV5AEAD();
		encryptorBuilder.setWithAEAD(AEADAlgorithmTags.OCB, 6);

		PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(encryptorBuilder);

		cPk.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pubKey).setProvider("BC"));

		ByteArrayOutputStream ldbOut = new ByteArrayOutputStream();
		PGPLiteralDataGenerator ldGen = new PGPLiteralDataGenerator();

		OutputStream ldOut = ldGen.open(ldbOut, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, (long)msg.length, new Date());

		ldOut.write(msg);

		ldOut.close();

		byte[] litData = ldbOut.toByteArray();

		OutputStream cOut = cPk.open(armorOutput ? new ArmoredOutputStream(cbOut) : cbOut, litData.length);

		cOut.write(litData);

		cOut.close();

		System.out.println(cbOut.toString());

		// decrypt
		PGPObjectFactory oIn = new JcaPGPObjectFactory(armorOutput ? new ArmoredInputStream(new ByteArrayInputStream(cbOut.toByteArray())) : new ByteArrayInputStream(cbOut.toByteArray()));

		PGPEncryptedDataList encList = (PGPEncryptedDataList)oIn.nextObject();

		PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

		InputStream clear = encP.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privKey));

		// System.err.println(Hex.toHexString(Streams.readAll(clear)));
		PGPObjectFactory pgpFact = new JcaPGPObjectFactory(clear);

		PGPLiteralData ld = (PGPLiteralData)pgpFact.nextObject();

		// isEquals("wrong filename", PGPLiteralData.CONSOLE, ld.getFileName());
		Assertions.assertThat(ld.getFileName()).isEqualTo(PGPLiteralData.CONSOLE);

		byte[] data = Streams.readAll(ld.getDataStream());

		Assertions.assertThat(data).isEqualTo(msg);
		// isTrue("msg mismatch", Arrays.areEqual(msg, data));
}

@Test
void encryptDecryptMultiChunkBoundaryTest() throws Exception
{
		SecureRandom random = new SecureRandom();
		byte[] msg = new byte[(1 << 6) * 5 - 17];     // take of literal data header

		random.nextBytes(msg);

		KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

		kpGen.initialize(2048);

		PGPKeyPair pgpKp = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL , kpGen.generateKeyPair(), new Date());

		PGPPublicKey pubKey = pgpKp.getPublicKey();

		PGPPrivateKey privKey = pgpKp.getPrivateKey();

		ByteArrayOutputStream cbOut = new ByteArrayOutputStream();
		JcePGPDataEncryptorBuilder encryptorBuilder = new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_128).setSecureRandom(random).setProvider("BC");

		encryptorBuilder.setUseV5AEAD();
		encryptorBuilder.setWithAEAD(AEADAlgorithmTags.OCB, 6);

		PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(encryptorBuilder);

		cPk.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pubKey).setProvider("BC"));

		ByteArrayOutputStream ldbOut = new ByteArrayOutputStream();
		PGPLiteralDataGenerator ldGen = new PGPLiteralDataGenerator();

		OutputStream ldOut = ldGen.open(ldbOut, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, (long)msg.length, new Date());

		ldOut.write(msg);

		ldOut.close();

		byte[] litData = ldbOut.toByteArray();

		OutputStream cOut = cPk.open(armorOutput ? new ArmoredOutputStream(cbOut) : cbOut, litData.length);

		cOut.write(litData);

		cOut.close();

		System.out.println(cbOut.toString());

		// decrypt
		PGPObjectFactory oIn = new JcaPGPObjectFactory(armorOutput ? new ArmoredInputStream(new ByteArrayInputStream(cbOut.toByteArray())) : new ByteArrayInputStream(cbOut.toByteArray()));

		PGPEncryptedDataList encList = (PGPEncryptedDataList)oIn.nextObject();

		PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

		InputStream clear = encP.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privKey));

		// System.err.println(Hex.toHexString(Streams.readAll(clear)));
		PGPObjectFactory pgpFact = new JcaPGPObjectFactory(clear);

		PGPLiteralData ld = (PGPLiteralData)pgpFact.nextObject();

		// isEquals("wrong filename", PGPLiteralData.CONSOLE, ld.getFileName());
		Assertions.assertThat(ld.getFileName()).isEqualTo(PGPLiteralData.CONSOLE);

		byte[] data = Streams.readAll(ld.getDataStream());

		Assertions.assertThat(data).isEqualTo(msg);
		// isTrue("msg mismatch", Arrays.areEqual(msg, data));
	}
}
