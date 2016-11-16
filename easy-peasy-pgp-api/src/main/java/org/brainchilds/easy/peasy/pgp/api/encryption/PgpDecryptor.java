package org.brainchilds.easy.peasy.pgp.api.encryption;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.brainchilds.easy.peasy.pgp.api.exceptions.PgpException;

public interface PgpDecryptor {

	void decrypt(InputStream encryptedIn, OutputStream decryptedOut) throws  IOException, PgpException;

}
