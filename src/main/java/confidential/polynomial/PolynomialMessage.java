package confidential.polynomial;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

public class PolynomialMessage implements Externalizable {
    private int id;
    private int sender;
    private String confidentialitySchemeId;

    public PolynomialMessage() {}

    public PolynomialMessage(int id, int sender) {
        this.id = id;
        this.sender = sender;
        this.confidentialitySchemeId = "csid not set";//"secp256k1";
    }

    public PolynomialMessage(int id, int sender, String confidentialitySchemeId) {
        this.id = id;
        this.sender = sender;
        this.confidentialitySchemeId = confidentialitySchemeId;
    }

    public int getId() {
        return id;
    }

    public int getSender() {
        return sender;
    }

    public String getConfidentialitySchemeId() {
        return confidentialitySchemeId;
    }

    /**
     * The confidentiality scheme id is always encoded at the start. Encode is done in serialize of PolynomialCreator.
     */
    public String readConfidentialitySchemeId(ObjectInput in) throws IOException {
        confidentialitySchemeId = in.readUTF();
        return confidentialitySchemeId;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeInt(id);
        out.writeInt(sender);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        id = in.readInt();
        sender = in.readInt();
    }
}
