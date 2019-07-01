package info.bencollier.cmp4j;

import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.bouncycastle.operator.MacCalculator;
import java.util.Date;

/**
 * Creates the HMAC protection for a CMP request by signing an encapsulated message with what at the moment can only
 * be a shared secret. TODO: Support additional protection schemes, specifically private key signing etc.
 */
public class CmpProtectedRequest {

    private CertificateRequestMessage request;
    private String sharedSecret;
    private byte[] nonce;
    private byte[] transactionId;
    private GeneralName subjectDN;
    private GeneralName issuerDN;
    private String keyId;
    public ProtectedPKIMessage protectedMessage;

    /**
     * Required information used to protect a message.
     *
     * @param request           The original request, which we will be encapsulating.
     * @param sharedSecret      The shared secret, used to sign the CMP message with an HMAC.
     * @param nonce             A nonce where we're using them to prevent message replaying.
     * @param transactionId     A transaction ID, where we want to use one to keep track of all our requests.
     * @param keyId             Sender Key ID. Your reference for the key. See RFC 4210. Optional, can be set to "".
     */
    CmpProtectedRequest(
            CmpRequest request,
            String sharedSecret,
            byte[] nonce,
            byte[] transactionId,
            String keyId) throws CmpProtectionException {
        this.request = request.request;
        this.sharedSecret = sharedSecret;
        this.subjectDN = new GeneralName(request.subjectDN);
        this.issuerDN = new GeneralName(request.issuerDN);
        this.nonce = nonce;
        this.transactionId = transactionId;
        this.keyId = keyId;
        this.protect();
    }

    /**
     * Set up a MAC and use it to protect the certificate request messages.
     * @throws CmpProtectionException if unable to do so.
     */
    private void protect() throws CmpProtectionException {
        try {
            MacCalculator macCalculator = setupPKMAC();
            CertReqMessages messages = new CertReqMessages(this.request.toASN1Structure());
            PKIBody initialRequest = new PKIBody(PKIBody.TYPE_CERT_REQ, messages);

            this.protectedMessage = createProtectedMessage(this.nonce, this.transactionId, this.subjectDN,
                    this.issuerDN, initialRequest, macCalculator, this.keyId);

        } catch (CRMFException crmfException) {
            throw new CmpProtectionException("Unable to correctly set up a MAC calculator." + crmfException);
        } catch (CMPException cmpException) {
            throw new CmpProtectionException("Unable to successfully encode CMP." + cmpException);
        }
    }

    /**
     * Setup a private key MAC. This method currently only uses shared secrets.
     * @return A macbuilder object for use in signing the message.
     * @throws CRMFException If the macbuilder can't be setup.
     */
    private MacCalculator setupPKMAC() throws CRMFException {
        final JcePKMACValuesCalculator jcePkmacCalc = new JcePKMACValuesCalculator();
        final AlgorithmIdentifier digestAlgorithm = new AlgorithmIdentifier(X509ObjectIdentifiers.id_SHA1);
        final AlgorithmIdentifier macAlgorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA1);
        final String sharedSecret = this.sharedSecret;

        jcePkmacCalc.setup(digestAlgorithm, macAlgorithm);
        PKMACBuilder macbuilder = new PKMACBuilder(jcePkmacCalc);
        return macbuilder.build(sharedSecret.toCharArray());
    }

    /**
     * Build a protected message using the message details and a mac calculator to sign the message.
     * @param nonce             For replay protection. Optional. Can be set to the same thing repeatedly if not in use.
     * @param transactionId     Optional. Can be set to the same thing repeatedly if not in use.
     * @param sender            Sender Name used to indicate the key to use to verify verify protection. See RFC.
     * @param recipient         Recipient Name should be usable to verify the protection on the message. See RFC.
     * @param pkiBody           Message body.
     * @param macCalculator     Mac Calculator to build an HMAC.
     * @param keyId             Sender Key ID. Your reference for the key. See RFC 4210. Optional, can be set to "".
     * @return                  Protected PKI message.
     * @throws CMPException     If message cannot be built.
     */
    private ProtectedPKIMessage createProtectedMessage(
            byte[] nonce, byte[] transactionId, GeneralName sender, GeneralName recipient, PKIBody pkiBody,
            MacCalculator macCalculator, String keyId) throws CMPException {
        ProtectedPKIMessageBuilder pbuilder = new ProtectedPKIMessageBuilder(sender, recipient);
        pbuilder.setMessageTime(new Date());
        pbuilder.setSenderNonce(nonce);
        pbuilder.setTransactionID(transactionId);
        pbuilder.setSenderKID(keyId.getBytes());
        pbuilder.setBody(pkiBody);
        return pbuilder.build(macCalculator);
    }

}
