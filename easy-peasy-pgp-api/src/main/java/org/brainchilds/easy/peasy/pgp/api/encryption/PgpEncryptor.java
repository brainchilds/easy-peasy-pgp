package org.brainchilds.easy.peasy.pgp.api.encryption;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.brainchilds.easy.peasy.pgp.api.exceptions.PgpException;

public interface PgpEncryptor {

	void encrypt(InputStream plaiIn, OutputStream encryptedOut) throws IOException, PgpException;
	
	void encrypt(long keyId, InputStream plaiIn, OutputStream encryptedOut) throws IOException, PgpException;

}
