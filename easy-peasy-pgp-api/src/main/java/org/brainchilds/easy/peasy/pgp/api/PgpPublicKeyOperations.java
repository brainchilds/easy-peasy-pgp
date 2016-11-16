package org.brainchilds.easy.peasy.pgp.api;

import org.brainchilds.easy.peasy.pgp.api.encryption.PgpEncryptor;
import org.brainchilds.easy.peasy.pgp.api.signature.PgpVerifier;

public interface PgpPublicKeyOperations extends PgpEncryptor, PgpVerifier {

}
