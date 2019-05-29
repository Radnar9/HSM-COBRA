package confidential;

import vss.secretsharing.VerifiableShare;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

public class ConfidentialData implements Externalizable {
    private VerifiableShare share;
    private List<VerifiableShare> publicShares;

    public ConfidentialData() {}

    public ConfidentialData(VerifiableShare share) {
        this.share = share;
    }

    public void addPublicShare(VerifiableShare share) {
        if (publicShares == null)
            publicShares = new LinkedList<>();
        publicShares.add(share);
    }

    public List<VerifiableShare> getPublicShares() {
        return publicShares;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        share.writeExternal(out);
        out.writeInt(publicShares == null ? -1 : publicShares.size());
        if (publicShares != null)
            for (VerifiableShare share : publicShares) {
                share.writeExternal(out);
            }
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException {
        share = new VerifiableShare();
        share.readExternal(in);
        int len = in.readInt();
        if (len != -1) {
            publicShares = new LinkedList<>();
            while (len-- > 0) {
                VerifiableShare share = new VerifiableShare();
                share.readExternal(in);
                publicShares.add(share);
            }
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ConfidentialData that = (ConfidentialData) o;
        if (!Arrays.equals(share.getSharedData(), that.share.getSharedData())
                || !share.getCommitments().equals(that.share.getCommitments()))
            return false;
        if (publicShares == null && that.publicShares == null)
            return true;
        if (publicShares == null || that.publicShares == null)
            return false;
        for (int i = 0; i < publicShares.size(); i++) {
            if (!Arrays.equals(publicShares.get(i).getSharedData(), that.publicShares.get(i).getSharedData())
                    || !publicShares.get(i).getCommitments().equals(that.publicShares.get(i).getCommitments()))
                return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(share.getSharedData());
        result = 31 * result + share.getCommitments().hashCode();
        if (publicShares != null) {
            for (VerifiableShare share : publicShares) {
                result = 31 * result + Arrays.hashCode(share.getSharedData());
                result = 31 * result + share.getCommitments().hashCode();
            }
        }
        return result;
    }
}
