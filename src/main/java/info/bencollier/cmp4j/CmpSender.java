package info.bencollier.cmp4j;

import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.ProtocolException;
import java.net.URL;

/**
 * Performs an HTTP send action on a protected PKI message in CMP format.
 */
public class CmpSender {

    private final static String POST_METHOD = "POST";
    private final static String CONTENT_TYPE = "Content-type";
    private final static String CMP_CONTENT_TYPE = "application/pkixcmp";

    public static CmpResponse send(CmpProtectedRequest request, CmpServer server) throws CmpSendException {
        try {
            String url = "http://" + server.hostname + ":" + server.port + server.path;
            final HttpURLConnection con = getCmpConnection(url);
            httpSendCmp(con, request.protectedMessage);
            final int responseCode = con.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) {
                throw new CmpSendException("Bad response from CMP HTTP call: " + responseCode);
            }
            byte[] cmpData = new byte[(int) con.getContentLength()];
            DataInputStream cmpInputStream = new DataInputStream(con.getInputStream());
            cmpInputStream.readFully(cmpData);
            return new CmpResponse(cmpData, responseCode);
        } catch (IOException exception) {
            throw new CmpSendException("Unable to send CMP: " + exception);
        }
    }

    private static void httpSendCmp(HttpURLConnection con, ProtectedPKIMessage pkim) throws CmpSendException {
        try {
            final OutputStream os = con.getOutputStream();
            os.write(encodeDER(pkim));
            os.close();
        } catch (IOException exception) {
            throw new CmpSendException("Unable to send CMP: " + exception);
        }
    }

    private static HttpURLConnection getCmpConnection(String server) throws CmpSendException {
        try {
            final HttpURLConnection con = (HttpURLConnection) new URL(server).openConnection();
            con.setDoOutput(true);
            con.setRequestMethod(POST_METHOD);
            con.setRequestProperty(CONTENT_TYPE, CMP_CONTENT_TYPE);
            con.connect();
            return con;
        } catch (ProtocolException exception) {
            throw new CmpSendException("Unable to send CMP: " + exception);
        } catch (IOException exception) {
            throw new CmpSendException("Unable to send CMP: " + exception);
        }
    }

    /**
     * Encode a protected message in DER format for sending.
     * @param protectedMessage  Protected PKI message
     * @return                  ByteArray in DER format
     * @throws IOException      If unable to create byte array
     */
    private static byte[] encodeDER(ProtectedPKIMessage protectedMessage) throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(outputStream);
        out.writeObject(protectedMessage.toASN1Structure());
        return outputStream.toByteArray();
    }

}
