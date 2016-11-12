package easy.peasy.pgp.api.exceptions;

public class PgpException extends Exception {

	private static final long serialVersionUID = -3838040095005492313L;

	public PgpException() {
		super();
	}

	public PgpException(String message, Throwable cause) {
		super(message, cause);
	}

	public PgpException(String message) {
		super(message);
	}

	public PgpException(Throwable cause) {
		super(cause);
	}

}
