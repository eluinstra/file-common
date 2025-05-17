package dev.luin.file.common.encryption;

import static java.util.Spliterator.ORDERED;
import static java.util.Spliterators.spliteratorUnknownSize;
import static java.util.stream.StreamSupport.stream;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Optional;
import java.util.stream.Stream;
import lombok.AccessLevel;
import lombok.experimental.FieldDefaults;
import lombok.val;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;

@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class PgpEngine
{
	int encryptionAlgorithm = SymmetricKeyAlgorithmTags.AES_256;
	int compressionAlgorithm = CompressionAlgorithmTags.UNCOMPRESSED;
	boolean armorOutput = false;
	boolean withIntegrityPacket = true;
	int bufferSize = 1 << 16;

	public Optional<PGPPublicKey> getEncryptionKey(InputStream keyInputStream) throws IOException, PGPException
	{
		val publicKeyRings = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyInputStream), new JcaKeyFingerprintCalculator());
		return stream(spliteratorUnknownSize(publicKeyRings.getKeyRings(), ORDERED), false).flatMap(this::getEncryptionKeys).findFirst();
	}

	private Stream<PGPPublicKey> getEncryptionKeys(PGPPublicKeyRing publicKeyRing)
	{
		return stream(publicKeyRing.spliterator(), false).filter(PGPPublicKey::isEncryptionKey);
	}

	public void encrypt(OutputStream out, InputStream in, PGPPublicKey publicKey) throws IOException, PGPException
	{
		val pgpEncryptedDataGenerator = createEncryptedDataGenerator(publicKey);
		val os = pgpEncryptedDataGenerator.open(armorOutput ? new ArmoredOutputStream(out) : out, new byte[bufferSize]);
		// val compressedDataGenerator = new PGPCompressedDataGenerator(compressionAlgorithm);
		// copyAsLiteralData(compressedDataGenerator.open(os), in, bufferSize);
		copyAsLiteralData(os, in, bufferSize);
		// compressedDataGenerator.close();
		os.close();
	}

	private PGPEncryptedDataGenerator createEncryptedDataGenerator(PGPPublicKey publicKey)
	{
		val result = new PGPEncryptedDataGenerator(
				new JcePGPDataEncryptorBuilder(encryptionAlgorithm).setWithIntegrityPacket(withIntegrityPacket)
						.setSecureRandom(new SecureRandom())
						.setProvider(BouncyCastleProvider.PROVIDER_NAME));
		result.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider(BouncyCastleProvider.PROVIDER_NAME));
		return result;
	}

	private void copyAsLiteralData(OutputStream out, InputStream in, int bufferSize) throws IOException
	{
		val dataGenerator = new PGPLiteralDataGenerator();
		val dataStream =
				dataGenerator.open(out, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, Date.from(LocalDateTime.now().toInstant(ZoneOffset.UTC)), new byte[bufferSize]);
		in.transferTo(dataStream);
		in.close();
	}

	public void decrypt(InputStream encryptedIn, OutputStream clearOut, PGPPrivateKey privateKey) throws PGPException, IOException
	{
		// JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory(encryptedIn);
		JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory(PGPUtil.getDecoderStream(encryptedIn));
		// Object obj = objectFactory.nextObject();
		// PGPEncryptedDataList encryptedDataList = (obj instanceof
		// PGPEncryptedDataList)
		// ? (PGPEncryptedDataList) obj
		// : (PGPEncryptedDataList) objectFactory.nextObject();
		PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList)objectFactory.nextObject();

		PGPPublicKeyEncryptedData encData = null;
		for (PGPEncryptedData pgpEnc : encryptedDataList)
		{
			PGPPublicKeyEncryptedData pkEnc = (PGPPublicKeyEncryptedData)pgpEnc;
			if (pkEnc.getKeyID() == privateKey.getKeyID())
			{
				encData = pkEnc;
				break;
			}
		}
		if (encData == null)
			throw new IllegalStateException("matching encrypted data not found");

		// build decryptor factory
		PublicKeyDataDecryptorFactory dataDecryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey);

		InputStream clear = encData.getDataStream(dataDecryptorFactory);
		byte[] literalData = Streams.readAll(clear);
		clear.close();

		// check data decrypts okay
		if (encData.verify())
		{
			// parse out literal data
			PGPObjectFactory litFact = new JcaPGPObjectFactory(literalData);
			PGPLiteralData litData = (PGPLiteralData)litFact.nextObject();
			// byte[] data = Streams.readAll(litData.getInputStream());
			// return data;
			litData.getInputStream().transferTo(clearOut);
		}
		else
			throw new IllegalStateException("modification check failed");

		// PGPPrivateKey pgpPrivateKey = null;
		// PGPPublicKeyEncryptedData publicKeyEncryptedData = null;

		// Iterator<PGPEncryptedData> encryptedDataItr =
		// encryptedDataList.getEncryptedDataObjects();
		// while (pgpPrivateKey == null && encryptedDataItr.hasNext()) {
		// publicKeyEncryptedData = (PGPPublicKeyEncryptedData) encryptedDataItr.next();
		// pgpPrivateKey = findSecretKey(publicKeyEncryptedData.getKeyID());
		// }

		// if (Objects.isNull(publicKeyEncryptedData)) {
		// throw new PGPException("Could not generate PGPPublicKeyEncryptedData
		// object");
		// }

		// if (pgpPrivateKey == null) {
		// throw new PGPException("Could Not Extract private key");
		// }
		// decrypt(clearOut, pgpPrivateKey, publicKeyEncryptedData);
	}

	// private PGPPrivateKey findSecretKey(long keyID) throws PGPException {
	// PGPSecretKey pgpSecretKey = pgpSecretKeyRingCollection.getSecretKey(keyID);
	// return pgpSecretKey == null ? null
	// : pgpSecretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
	// .setProvider(BouncyCastleProvider.PROVIDER_NAME).build("passphrase".toCharArray()));
	// }

	void decrypt(OutputStream clearOut, PGPPrivateKey pgpPrivateKey, PGPPublicKeyEncryptedData publicKeyEncryptedData) throws IOException, PGPException
	{
		PublicKeyDataDecryptorFactory decryptorFactory =
				new JcePublicKeyDataDecryptorFactoryBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(pgpPrivateKey);
		InputStream decryptedCompressedIn = publicKeyEncryptedData.getDataStream(decryptorFactory);

		JcaPGPObjectFactory decCompObjFac = new JcaPGPObjectFactory(decryptedCompressedIn);
		PGPCompressedData pgpCompressedData = (PGPCompressedData)decCompObjFac.nextObject();

		InputStream compressedDataStream = new BufferedInputStream(pgpCompressedData.getDataStream());
		JcaPGPObjectFactory pgpCompObjFac = new JcaPGPObjectFactory(compressedDataStream);

		Object message = pgpCompObjFac.nextObject();

		if (message instanceof PGPLiteralData)
		{
			PGPLiteralData pgpLiteralData = (PGPLiteralData)message;
			InputStream decDataStream = pgpLiteralData.getInputStream();
			// IOUtils.copy(decDataStream, clearOut);
			decDataStream.transferTo(clearOut);
			clearOut.close();
		}
		else if (message instanceof PGPOnePassSignatureList)
		{
			throw new PGPException("Encrypted message contains a signed message not literal data");
		}
		else
		{
			throw new PGPException("Message is not a simple encrypted file - Type Unknown");
		}
		// Performing Integrity check
		if (publicKeyEncryptedData.isIntegrityProtected())
		{
			if (!publicKeyEncryptedData.verify())
			{
				throw new PGPException("Message failed integrity check");
			}
		}
	}
}
