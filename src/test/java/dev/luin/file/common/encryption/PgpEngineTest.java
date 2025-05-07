package dev.luin.file.common.encryption;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import lombok.val;
import org.bouncycastle.openpgp.PGPException;
import org.junit.jupiter.api.Test;

class PgpEngineTest
{
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
}
