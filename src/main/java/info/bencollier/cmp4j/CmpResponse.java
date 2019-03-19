package info.bencollier.cmp4j;

public class CmpResponse {

    public byte[] response;
    public int responseCode;

    public CmpResponse(byte[] response, int responseCode) {
        this.response = response;
        this.responseCode = responseCode;
    }
}
