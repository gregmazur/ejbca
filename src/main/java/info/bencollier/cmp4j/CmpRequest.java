package info.bencollier.cmp4j;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder;
import java.io.*;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * The CmpRequest represents an encoded Certificate Request Message.
 */
public class CmpRequest {

    private BigInteger certReqId;
    private KeyPair keyPair;

    X500Name subjectDN;
    X500Name issuerDN;
    CertificateRequestMessage request;

    /**
     * If CmpRequest is instantiated without a public-private keypair, it will autogenerate a keypair before creating
     * the request object. If the length and algorithm of the keypair is not specified, the pair will be generated
     * using RSA and a length of 2Kb by default.
     *
     * @param subjectDN   The thing being secured, as represented by a series of tags, eg. "C=UK, CN=bencollier.info"
     * @param requestId   An ID for tracking the CMP request.
     */
    public CmpRequest(String subjectDN, String issuerDN, int requestId) throws CmpRequestException {
        this(subjectDN, issuerDN, requestId, null, 2048, "RSA");
    }

    /**
     * If CmpRequest is instantiated with a key length and algorith, it will generate a keypair with these attributes
     * before creating the request object. CmpRequest can also be instantiated directly with a keypair.
     *
     * @param subjectDN     The thing being secured, as represented by a series of tags, eg. "C=UK, CN=bencollier.info".
     * @param requestId     An ID for tracking the CMP request.
     * @param keyPair       A public-private keypair.
     */
    public CmpRequest(String subjectDN, String issuerDN, int requestId,
                      KeyPair keyPair, int keyBytes, String keyAlgorithm) throws CmpRequestException {
        try {
            this.subjectDN = new X500Name(subjectDN);
            this.issuerDN = new X500Name(issuerDN);
            this.certReqId = BigInteger.valueOf(requestId);
            if (keyPair == null) {
                this.keyPair = genKeyPair(keyBytes, keyAlgorithm);
            } else {
                this.keyPair = keyPair;
            }
            this.generate();
        } catch (NoSuchAlgorithmException exception) {
            throw new CmpRequestException ("Bad algorithm: " + exception);
        }
    }


    /**
     * Build a Certificate Request Message
     * @throws CmpRequestException if unable to do so.
     */
    private void generate() throws CmpRequestException {
        try {
            CertificateRequestMessageBuilder msgbuilder = new CertificateRequestMessageBuilder(this.certReqId);

            msgbuilder.setIssuer(this.issuerDN);
            msgbuilder.setSubject(this.subjectDN);
            msgbuilder.setPublicKey(createPublicKeyInfo(this.keyPair.getPublic().getEncoded()));
            msgbuilder.setAuthInfoSender(new GeneralName(this.subjectDN));
            msgbuilder.setProofOfPossessionRaVerified();
            this.request = msgbuilder.build();
        } catch (IOException exception) {
            throw new CmpRequestException("Unable to build public key info: " + exception);
        } catch (CRMFException exception) {
            throw new CmpRequestException("Unable to build message: " + exception);
        }
    }

    /**
     * genKeyPair - Generate a public-private keypair from a byte length and algorithm.
     * @param keyBytes                      Number of bytes in the public key of the keypair we are generating.
     * @param keyAlgorithm                  Algorithm used to generate our public-private keypair.
     * @return                              Keypair.
     * @throws NoSuchAlgorithmException     Thrown if the algorithm passed to the constructor does not exist.
     */
    private static KeyPair genKeyPair(int keyBytes, String keyAlgorithm) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyAlgorithm);
        keyGen.initialize(keyBytes);
        return keyGen.generateKeyPair();
    }

    /**
     * Encode Public Key as ASN1
     * @param encodedPK     Byte-encoded public key
     * @return              ASN1-encoded public key
     * @throws IOException
     */
    private static SubjectPublicKeyInfo createPublicKeyInfo(byte[] encodedPK) throws IOException {
        final ByteArrayInputStream byteArrayIn = new ByteArrayInputStream(encodedPK);
        final ASN1InputStream inputStream = new ASN1InputStream(byteArrayIn);
        return new SubjectPublicKeyInfo((ASN1Sequence)inputStream.readObject());
    }

}

