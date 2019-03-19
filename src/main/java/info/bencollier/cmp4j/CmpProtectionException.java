package info.bencollier.cmp4j;

public class CmpProtectionException extends Exception {

    CmpProtectionException(String s) {
        super(s);
        System.exit(1);
    }
}
