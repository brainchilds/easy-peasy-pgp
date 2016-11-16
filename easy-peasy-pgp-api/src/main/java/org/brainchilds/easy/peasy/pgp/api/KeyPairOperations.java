package org.brainchilds.easy.peasy.pgp.api;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;

import org.brainchilds.easy.peasy.pgp.api.exceptions.PgpException;

public interface KeyPairOperations {

	public String createKeyPair(String userId, String password, OutputStream publicKeyOut, OutputStream privateKeyOut) throws IOException, PgpException;

	public String createKeyPair(String userId, String password, Path publicKeyFile, Path privateKeyFile) throws IOException, PgpException;

}
