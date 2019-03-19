package info.bencollier.cmp4j;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;

public class CmpHelper {

    /**
     * Output a byte-encoded Pem to the console
     *
     * @param pemDescription    The PEM header
     * @param encodedPem        Byte encoded PEM
     * @throws IOException      If unable to write the PEM
     */
    public static void writePem(String pemDescription, byte[] encodedPem) throws IOException {
        Writer textWriter = new StringWriter();
        PemWriter pemWriter = new JcaPEMWriter(textWriter);
        PemObjectGenerator pemObject = new PemObject(pemDescription, encodedPem);
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        String textPublicKey = textWriter.toString();
        System.out.println(textPublicKey);
    }

}
