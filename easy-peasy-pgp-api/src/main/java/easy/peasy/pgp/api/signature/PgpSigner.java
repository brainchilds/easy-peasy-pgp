package easy.peasy.pgp.api.signature;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import easy.peasy.pgp.api.exceptions.PgpException;

public interface PgpSigner {

	void sign(InputStream plainIn, OutputStream signedOut) throws IOException, PgpException;
	
	void sign(long keyId, InputStream plainIn, OutputStream signedOut) throws IOException, PgpException;

}
