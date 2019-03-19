package info.bencollier.cmp4j;

public class CmpServer {

    String hostname;
    String path;
    int port;

    CmpServer(String hostname, String path, int port) {
        this.hostname = hostname;
        this.path = path;
        this.port = port;
    }

}
