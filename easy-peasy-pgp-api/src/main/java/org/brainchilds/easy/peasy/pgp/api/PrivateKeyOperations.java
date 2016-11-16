package org.brainchilds.easy.peasy.pgp.api;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.brainchilds.easy.peasy.pgp.api.exceptions.PgpException;

public interface PrivateKeyOperations {

	void decrypt(InputStream encryptedIn, OutputStream decryptedOut) throws IOException, PgpException;

	void sign(InputStream plainIn, OutputStream signedOut) throws IOException, PgpException;

	void sign(String keyId, InputStream plainIn, OutputStream signedOut) throws IOException, PgpException;
}
