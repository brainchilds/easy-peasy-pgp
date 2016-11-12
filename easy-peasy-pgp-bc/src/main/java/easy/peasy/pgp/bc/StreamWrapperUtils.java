package easy.peasy.pgp.bc;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPUtil;

class StreamWrapperUtils {

	public static InputStream wrap(InputStream in, boolean pgpDecoderStream) throws IOException {
		if (pgpDecoderStream) {
			in = PGPUtil.getDecoderStream(in);
		}
		if (!(in instanceof BufferedInputStream)) {
			in = new BufferedInputStream(in);
		}
		return in;
	}

	public static OutputStream wrap(OutputStream out, boolean asciiArmor) throws IOException {
		if (asciiArmor) {
			out = new ArmoredOutputStream(out);
		}
		if (!(out instanceof BufferedOutputStream)) {
			out = new BufferedOutputStream(out);
		}
		return out;
	}
}
