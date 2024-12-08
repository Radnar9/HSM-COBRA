package confidential;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;

public class EllipticCurveParameters implements Externalizable {

    private String curveName;
    private BigInteger prime;
    private BigInteger order;
    private BigInteger a;
    private BigInteger b;
    private BigInteger x;
    private BigInteger y;
    private BigInteger cofactor;

    public EllipticCurveParameters(String curveName, BigInteger prime, BigInteger order, BigInteger a, BigInteger b, BigInteger x, BigInteger y, BigInteger cofactor) {
        this.curveName = curveName;
        this.prime = prime;
        this.order = order;
        this.a = a;
        this.b = b;
        this.x = x;
        this.y = y;
        this.cofactor = cofactor;
    }

    public EllipticCurveParameters() {
    }

    public String curveName() {
        return curveName;
    }

    public BigInteger prime() {
        return prime;
    }

    public BigInteger order() {
        return order;
    }

    public BigInteger a() {
        return a;
    }

    public BigInteger b() {
        return b;
    }

    public BigInteger x() {
        return x;
    }

    public BigInteger y() {
        return y;
    }

    public BigInteger cofactor() {
        return cofactor;
    }


    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        byte[] aux = curveName.getBytes();
        out.writeInt(aux.length);
        out.write(aux);

        aux = prime.toByteArray();
        out.writeInt(aux.length);
        out.write(aux);

        aux = order.toByteArray();
        out.writeInt(aux.length);
        out.write(aux);

        aux = a.toByteArray();
        out.writeInt(aux.length);
        out.write(aux);

        aux = b.toByteArray();
        out.writeInt(aux.length);
        out.write(aux);

        aux = x.toByteArray();
        out.writeInt(aux.length);
        out.write(aux);

        aux = y.toByteArray();
        out.writeInt(aux.length);
        out.write(aux);

        aux = cofactor.toByteArray();
        out.writeInt(aux.length);
        out.write(aux);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException {
        int len = in.readInt();
        byte[] aux = new byte[len];
        in.readFully(aux);
        curveName = new String(aux);

        len = in.readInt();
        aux = new byte[len];
        in.readFully(aux);
        prime = new BigInteger(aux);

        len = in.readInt();
        aux = new byte[len];
        in.readFully(aux);
        order = new BigInteger(aux);

        len = in.readInt();
        aux = new byte[len];
        in.readFully(aux);
        a = new BigInteger(aux);

        len = in.readInt();
        aux = new byte[len];
        in.readFully(aux);
        b = new BigInteger(aux);

        len = in.readInt();
        aux = new byte[len];
        in.readFully(aux);
        x = new BigInteger(aux);

        len = in.readInt();
        aux = new byte[len];
        in.readFully(aux);
        y = new BigInteger(aux);

        len = in.readInt();
        aux = new byte[len];
        in.readFully(aux);
        cofactor = new BigInteger(aux);
    }
}
