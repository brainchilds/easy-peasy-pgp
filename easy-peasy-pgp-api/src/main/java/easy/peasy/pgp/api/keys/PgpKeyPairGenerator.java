package easy.peasy.pgp.api.keys;

import java.io.IOException;
import java.io.OutputStream;

import easy.peasy.pgp.api.exceptions.PgpException;

public interface PgpKeyPairGenerator {

	public long createKeyPair(String userId, OutputStream publicKeyOut, OutputStream privateKeyOut, String password) throws IOException, PgpException;

}
