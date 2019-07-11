package confidential.statemanagement;

import vss.commitment.Commitments;
import vss.secretsharing.Share;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.LinkedList;

public class RecoveryApplicationState implements Externalizable {
    private Commitments transferPolynomialCommitments;
    private byte[] commonState;
    private LinkedList<Share> shares;
    private int lastCheckpointCID;
    private int lastCID;
    private int pid;

    public RecoveryApplicationState() {}

    public RecoveryApplicationState(byte[] commonState, LinkedList<Share> shares, int lastCheckpointCID, int lastCID, int pid, Commitments transferPolynomialCommitments) {
        this.commonState = commonState;
        this.shares = shares;
        this.lastCheckpointCID = lastCheckpointCID;
        this.lastCID = lastCID;
        this.pid = pid;
        this.transferPolynomialCommitments = transferPolynomialCommitments;
    }

    public int getLastCID() {
        return lastCID;
    }

    public int getLastCheckpointCID() {
        return lastCheckpointCID;
    }

    public byte[] getCommonState() {
        return commonState;
    }

    public int getPid() {
        return pid;
    }

    public LinkedList<Share> getShares() {
        return shares;
    }

    public Commitments getTransferPolynomialCommitments() {
        return transferPolynomialCommitments;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        transferPolynomialCommitments.writeExternal(out);
        out.writeInt(commonState == null ? -1 : commonState.length);
        if (commonState != null)
            out.write(commonState);

        out.writeInt(shares == null ? -1 : shares.size());
        if (shares != null) {
            for (Share share : shares) {
                share.writeExternal(out);
            }
        }

        out.writeInt(lastCheckpointCID);
        out.writeInt(lastCID);
        out.writeInt(pid);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException {
        transferPolynomialCommitments = new Commitments();
        transferPolynomialCommitments.readExternal(in);
        int len = in.readInt();
        if (len != -1) {
            commonState = new byte[len];
            in.readFully(commonState);
        }

        len = in.readInt();
        if (len != -1) {
            shares = new LinkedList<>();
            while (len-- > 0) {
                Share share = new Share();
                share.readExternal(in);
                shares.add(share);
            }
        }

        lastCheckpointCID = in.readInt();
        lastCID = in.readInt();
        pid = in.readInt();
    }
}
