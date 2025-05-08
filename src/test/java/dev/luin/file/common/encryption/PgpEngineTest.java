package dev.luin.file.common.encryption;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Security;
import java.util.Objects;
import lombok.val;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.junit.jupiter.api.Test;

class PgpEngineTest
{
	static
	{
		if (Objects.isNull(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)))
			Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	void testEncryptionKey() throws IOException, PGPException
	{
		val result = new PgpEngine().getEncryptionKey(getClass().getResourceAsStream("public_key.asc"));
		assertThat(result).isPresent().hasValueSatisfying(k -> assertThat(k.getKeyID()).isEqualTo(7629388801588835830L));
	}

	@Test
	void testNoEncryptionKey() throws IOException, PGPException
	{
		val result = new PgpEngine().getEncryptionKey(getClass().getResourceAsStream("public_signing_key.asc"));
		assertThat(result).isEmpty();
	}

	@Test
	void testEncryptFile() throws IOException, PGPException
	{
		val in = new ByteArrayInputStream("Dit is een test.".getBytes());
		val out = new ByteArrayOutputStream();
		val key = new PgpEngine().getEncryptionKey(getClass().getResourceAsStream("public_key.asc"));
		new PgpEngine().encrypt(out, in, key.get());
		// out.flush();
		System.out.println("----");
		System.out.println(out.toString());
		System.out.println("----");
	}
}
