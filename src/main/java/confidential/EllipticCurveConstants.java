package confidential;

import java.math.BigInteger;

public final class EllipticCurveConstants {
    public static final int CURVES_COUNTER = 3;

    public static final class BLS12_381 {
        public static final String NAME = "BLS12_381";
        public static final BigInteger PRIME = new BigInteger("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16);
        public static final BigInteger ORDER = new BigInteger("73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001", 16);
        public static final BigInteger A = new BigInteger("0", 16);
        public static final BigInteger B = new BigInteger("4", 16);
        public static final BigInteger X = new BigInteger("17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB", 16);
        public static final BigInteger Y = new BigInteger("08B3F481E3AAA0F1A09E30ED741D8AE4FCF5E095D5D00AF600DB18CB2C04B3EDD03CC744A2888AE40CAA232946C5E7E1", 16);
        public static final BigInteger COFACTOR = new BigInteger("396C8C005555E1568C00AAAB0000AAAB", 16);   // Also known as 'h'

        public static final EllipticCurveParameters PARAMETERS = new EllipticCurveParameters(
                NAME, PRIME, ORDER, A, B, X, Y, COFACTOR
        );
    }

    // Aliases: nist/P-256 | x962/prime256v1
    public static final class secp256r1 {
        public static final String NAME = "secp256r1";
        public static final BigInteger PRIME = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
        public static final BigInteger ORDER = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
        public static final BigInteger A = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);
        public static final BigInteger B = new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
        public static final BigInteger X = new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
        public static final BigInteger Y = new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);
        public static final BigInteger COFACTOR = new BigInteger("1", 16);   // Also known as 'h'
        public static final EllipticCurveParameters PARAMETERS = new EllipticCurveParameters(
                NAME, PRIME, ORDER, A, B, X, Y, COFACTOR
        );
    }

    // Aliases: x963/ansip256k1
    public static final class secp256k1 {
        public static final String NAME = "secp256k1";
        public static final BigInteger PRIME = new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16);
        public static final BigInteger ORDER = new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);
        public static final BigInteger A = new BigInteger("0", 16);
        public static final BigInteger B = new BigInteger("7", 16);
        public static final BigInteger X = new BigInteger("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16);
        public static final BigInteger Y = new BigInteger("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16);
        public static final BigInteger COFACTOR = new BigInteger("1", 16);   // Also known as 'h'
        public static final EllipticCurveParameters PARAMETERS = new EllipticCurveParameters(
                NAME, PRIME, ORDER, A, B, X, Y, COFACTOR
        );
    }

    private EllipticCurveConstants() {}
}
