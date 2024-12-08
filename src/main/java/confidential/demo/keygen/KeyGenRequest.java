package confidential.demo.keygen;

import java.io.*;

public record KeyGenRequest(String privateKeyId, String ellipticCurve) {

    public byte[] serialize() throws IOException {
        byte[] serializedData;
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            try (ObjectOutputStream out = new ObjectOutputStream(bos)) {
                writeByteArray(out, privateKeyId.getBytes());
                writeByteArray(out, ellipticCurve.getBytes());
                out.flush();
                bos.flush();
                serializedData = bos.toByteArray();
            }
        }

        return serializedData;
    }

    public static KeyGenRequest deserialize(byte[] data) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(data)) {
            try (ObjectInputStream in = new ObjectInputStream(bis)) {
                String privateKeyId = new String(readByteArray(in));
                String ellipticCurve = new String(readByteArray(in));
                return new KeyGenRequest(privateKeyId, ellipticCurve);
            }
        }
    }

    private static byte[] readByteArray(ObjectInputStream in) throws IOException {
        int length = in.readInt();
        if (length == -1) {
            return null;
        }
        byte[] bytes = new byte[length];
        in.readFully(bytes);
        return bytes;
    }

    private void writeByteArray(ObjectOutputStream out, byte[] byteArray) throws IOException {
        if (byteArray != null) {
            out.writeInt(byteArray.length);
            out.write(byteArray);
        } else {
            out.writeInt(-1);
        }
    }
}
