package easy.peasy.pgp.api.keys;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;

import easy.peasy.pgp.api.exceptions.PgpException;

public interface PgpKeyPairGenerator {

	public long createKeyPair(String userId, String password, OutputStream publicKeyOut, OutputStream privateKeyOut) throws IOException, PgpException;

	public long createKeyPair(String userId, String password, Path publicKeyFile, Path privateKeyFile) throws IOException, PgpException;

}
