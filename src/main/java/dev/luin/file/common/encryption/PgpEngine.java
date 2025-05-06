package dev.luin.file.common.encryption;

import static java.util.Spliterator.ORDERED;
import static java.util.Spliterators.spliteratorUnknownSize;
import static java.util.stream.StreamSupport.stream;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Date;
import java.util.stream.Stream;
import lombok.AccessLevel;
import lombok.experimental.FieldDefaults;
import lombok.val;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class PgpEngine
{
	int encryptionAlgorithm = SymmetricKeyAlgorithmTags.AES_256;
	int compressionAlgorithm = CompressionAlgorithmTags.UNCOMPRESSED;
	boolean armorOutput = true;
	boolean withIntegrityPacket = true;
	int bufferSize = 1 << 16;

	public PGPPublicKey getEncryptionKey(InputStream keyInputStream) throws IOException, PGPException
	{
		val publicKeyRings = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyInputStream), new JcaKeyFingerprintCalculator());
		return stream(spliteratorUnknownSize(publicKeyRings.getKeyRings(), ORDERED), false).flatMap(this::getEncryptionKeys)
				.findAny()
				.orElseThrow(() -> new PGPException("No encryption key found"));
	}

	private Stream<PGPPublicKey> getEncryptionKeys(PGPPublicKeyRing publicKeyRing)
	{
		return stream(publicKeyRing.spliterator(), false).filter(PGPPublicKey::isEncryptionKey);
	}

	public void encrypt(OutputStream out, InputStream in, PGPPublicKey publicKey) throws IOException, PGPException
	{
		val pgpEncryptedDataGenerator = new PGPEncryptedDataGenerator(
				new JcePGPDataEncryptorBuilder(encryptionAlgorithm).setWithIntegrityPacket(withIntegrityPacket)
						.setSecureRandom(new SecureRandom())
						.setProvider(BouncyCastleProvider.PROVIDER_NAME));
		pgpEncryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey));
		val os = pgpEncryptedDataGenerator.open(armorOutput ? new ArmoredOutputStream(out) : out, new byte[bufferSize]);
		val compressedDataGenerator = new PGPCompressedDataGenerator(compressionAlgorithm);
		copyAsLiteralData(compressedDataGenerator.open(os), in, bufferSize);
		compressedDataGenerator.close();
		os.close();
	}

	private void copyAsLiteralData(OutputStream out, InputStream in, int bufferSize) throws IOException
	{
		val dataGenerator = new PGPLiteralDataGenerator();
		val dataStream =
				dataGenerator.open(out, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, Date.from(LocalDateTime.now().toInstant(ZoneOffset.UTC)), new byte[bufferSize]);
		// TODO in.transferTo(pOut);
		val buffer = new byte[bufferSize];
		try
		{
			int length;
			while ((length = in.read(buffer)) > 0)
				dataStream.write(buffer, 0, length);
			dataStream.close();
		}
		finally
		{
			Arrays.fill(buffer, (byte)0);
			in.close();
		}
	}
}
