package info.bencollier.cmp4j;

import javax.net.ssl.KeyManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.security.*;
import java.security.cert.Certificate;

import static info.bencollier.cmp4j.CmpRequest.genKeyPair;

public class TestCmp4j {

    /**
     * Integration test - calls local EJBCA server with appropriate configuration.
     */
    public static void main(String[] args) throws Exception {

//        KeyPair keyPair = genKeyPair(2048, "RSA");

        KeyStore ks = KeyStore.getInstance("JKS");
        InputStream ksIs = new FileInputStream("test.jks");
        try {
            ks.load(ksIs, "test".toCharArray());
        } finally {
            if (ksIs != null) {
                ksIs.close();
            }
        }

        String alias = "teststore";

        KeyPair keyPair = null;
        Key key = ks.getKey(alias, "test".toCharArray());
        if (key instanceof PrivateKey) {
            // Get certificate of public key
            Certificate cert = ks.getCertificate(alias);


            // Get public key
            PublicKey publicKey = cert.getPublicKey();

            // Return a key pair
            keyPair = new KeyPair(publicKey, (PrivateKey) key);
        }

//        Principal subjectDN = ((X509Certificate)cert).getSubjectDN();
//        Vector<Certificate> vec = hash.get(subjectDN);


        CmpServer server = new CmpServer(
                "localhost",
                "/ejbca/publicweb/cmp/ra",
                80);
        CmpRequest request = new CmpRequest(
                "CN=new, O=HYS",
                "CN=ManagementCA, O=EJBCA Container Quickstart",
                2, keyPair, 2048, "RSA");
        byte[] nonce = {1, 1, 1, 1, 1, 1};
        byte[] transactionId = new byte [1];
        CmpProtectedRequest protectedRequest = new CmpProtectedRequest(
                request,
                "secret",//enrollment code
                nonce,
                transactionId,
                "endentity");//entity profile
        CmpResponse cmpResponse = CmpSender.send(protectedRequest, server);
        CmpHelper.writePem( "CERTIFICATE", cmpResponse.response);
        System.out.println(cmpResponse.responseCode);

        System.out.println("2nd req");

        request = new CmpRequest(
                "CN=GREGSUPERGREGSUPER, O=HYS",
                "CN=no, O=no",
                2, keyPair, 2048, "RSA");

        protectedRequest = new CmpProtectedRequest(
                request,
                "secret",
                nonce,
                transactionId,
                "endentity");

        cmpResponse = CmpSender.send(protectedRequest, server);
        CmpHelper.writePem( "CERTIFICATE", cmpResponse.response);
        System.out.println(cmpResponse.responseCode);
    }

}
