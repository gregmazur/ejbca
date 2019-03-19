package info.bencollier.cmp4j;

public class TestCmp4j {

    /**
     * Integration test - calls local EJBCA server with appropriate configuration.
     */
    public static void main(String[] args) throws Exception {

        CmpServer server = new CmpServer(
                "localhost",
                "/ejbca/publicweb/cmp/test",
                8080);
        CmpRequest request = new CmpRequest(
                "CN=12341234, O=benben",
                "CN=issuer, O=issuingorg",
                1);
        byte[] nonce = {1, 1, 1, 1, 1, 1};
        byte[] transactionId = new byte [1];
        CmpProtectedRequest protectedRequest = new CmpProtectedRequest(
                request,
                "password",
                nonce,
                transactionId,
                "1");
        CmpResponse cmpResponse = CmpSender.send(protectedRequest, server);
        CmpHelper.writePem( "CERTIFICATE", cmpResponse.response);
        System.out.println(cmpResponse.responseCode);
    }

}
