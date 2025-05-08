package dev.luin.file.common.encryption;

import static java.util.Spliterator.ORDERED;
import static java.util.Spliterators.spliteratorUnknownSize;
import static java.util.stream.StreamSupport.stream;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
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
public class PgpEngine {
	int encryptionAlgorithm = SymmetricKeyAlgorithmTags.AES_256;
	int compressionAlgorithm = CompressionAlgorithmTags.UNCOMPRESSED;
	boolean armorOutput = false;
	boolean withIntegrityPacket = true;
	int bufferSize = 1 << 16;

	public Optional<PGPPublicKey> getEncryptionKey(InputStream keyInputStream) throws IOException, PGPException {
		val publicKeyRings = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyInputStream),
				new JcaKeyFingerprintCalculator());
		return stream(spliteratorUnknownSize(publicKeyRings.getKeyRings(), ORDERED), false).flatMap(this::getEncryptionKeys)
				.findFirst();
	}

	private Stream<PGPPublicKey> getEncryptionKeys(PGPPublicKeyRing publicKeyRing) {
		return stream(publicKeyRing.spliterator(), false).filter(PGPPublicKey::isEncryptionKey);
	}

	public void encrypt(OutputStream out, ByteArrayInputStream in, PGPPublicKey publicKey) throws IOException, PGPException {
		val pgpEncryptedDataGenerator = new PGPEncryptedDataGenerator(
				new JcePGPDataEncryptorBuilder(encryptionAlgorithm).setWithIntegrityPacket(withIntegrityPacket)
						.setSecureRandom(new SecureRandom())
						.setProvider(BouncyCastleProvider.PROVIDER_NAME));
		pgpEncryptedDataGenerator.addMethod(
				new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider(BouncyCastleProvider.PROVIDER_NAME));
		val os = pgpEncryptedDataGenerator.open(armorOutput ? new ArmoredOutputStream(out) : out, new byte[bufferSize]);
		// val compressedDataGenerator = new
		// PGPCompressedDataGenerator(compressionAlgorithm);
		// val result = copyAsLiteralData(compressedDataGenerator.open(os), in,
		// bufferSize);
		copyAsLiteralData(os, in, bufferSize);
		// compressedDataGenerator.close();
		os.close();
	}

	private void copyAsLiteralData(OutputStream out, ByteArrayInputStream in, int bufferSize) throws IOException {
		val dataGenerator = new PGPLiteralDataGenerator();
		ByteArrayOutputStream ldbOut = new ByteArrayOutputStream();
		val dataStream = dataGenerator.open(ldbOut, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE,
				Date.from(LocalDateTime.now().toInstant(ZoneOffset.UTC)), new byte[bufferSize]);
		// dataGenerator.open(out, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, 16,
		// Date.from(LocalDateTime.now().toInstant(ZoneOffset.UTC)));
		// System.out.println(in.transferTo(dataStream));

		// val buffer = new byte[bufferSize];
		// try {
		// 	int length;
		// 	int total = 0;
		// 	while (total < 16 && (length = in.read(buffer)) > 0) {
		// 		dataStream.write(buffer, 0, length);
		// 		total += length;
		// 	}
		// 	dataStream.close();
		// } finally {
		// 	Arrays.fill(buffer, (byte) 0);
		// }

		dataStream.write(in.readAllBytes());
		dataStream.close();
		out.write(ldbOut.toByteArray());
	}
}
