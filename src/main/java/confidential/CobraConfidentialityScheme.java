package confidential;

import bftsmart.reconfiguration.views.View;
import confidential.polynomial.MissingProposalsMessage;
import confidential.polynomial.Proposal;
import confidential.polynomial.ProposalMessage;
import vss.Constants;
import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.commitment.CommitmentUtils;
import vss.commitment.ellipticCurve.EllipticCurveCommitment;
import vss.commitment.ellipticCurve.EllipticCurveCommitmentScheme;
import vss.facade.SecretSharingException;
import vss.facade.VSSFacade;
import vss.interpolation.InterpolationStrategy;
import vss.polynomial.Polynomial;
import vss.secretsharing.Share;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;
import java.security.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * @author Robin
 */
public abstract class CobraConfidentialityScheme {
    protected final VSSFacade vss;
    private final Map<Integer, BigInteger> serverToShareholder;
    private final Map<BigInteger, Integer> shareholderToServer;
    private final Cipher cipher;
    private final Lock cipherLock;
    private final boolean isLinearCommitmentScheme;
    private final boolean useTLSEncryption;
    protected KeysManager keysManager;
    protected int threshold;
    private final Map<String, EllipticCurveCommitmentScheme> ellipticCurveCommitmentSchemesMap;
    private EllipticCurveCommitmentScheme currentEllipticCurveCommitmentScheme;
    private final String confidentialSchemeId;

    public CobraConfidentialityScheme(View view) throws SecretSharingException {
        cipherLock = new ReentrantLock(true);
        int[] processes = view.getProcesses();
        serverToShareholder = new HashMap<>(processes.length);
        shareholderToServer = new HashMap<>(processes.length);
        BigInteger[] shareholders = new BigInteger[processes.length];
        for (int i = 0; i < processes.length; i++) {
            int process = processes[i];
            BigInteger shareholder = BigInteger.valueOf(process + 1);
            serverToShareholder.put(process, shareholder);
            shareholderToServer.put(shareholder, process);
            shareholders[i] = shareholder;
        }

        threshold = view.getF();
        Configuration configuration = Configuration.getInstance();

        Properties properties = new Properties();
        properties.put(Constants.TAG_THRESHOLD, String.valueOf(threshold));
        properties.put(Constants.TAG_DATA_ENCRYPTION_ALGORITHM, configuration.getDataEncryptionAlgorithm());
        properties.put(Constants.TAG_COMMITMENT_SCHEME, configuration.getVssScheme());
        if (configuration.getVssScheme().equals("1")) {
            properties.put(Constants.TAG_PRIME_FIELD, configuration.getPrimeField());
            properties.put(Constants.TAG_SUB_FIELD, configuration.getSubPrimeField());
            properties.put(Constants.TAG_GENERATOR, configuration.getGenerator());
        }
        try {
            cipher = Cipher.getInstance(configuration.getShareEncryptionAlgorithm());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new SecretSharingException("Failed to initialize the cipher");
        }
        vss = new VSSFacade(properties, shareholders);
        keysManager = new KeysManager();
        isLinearCommitmentScheme = Configuration.getInstance().getVssScheme().equals("1");
        useTLSEncryption = configuration.useTLSEncryption();

        ellipticCurveCommitmentSchemesMap = new HashMap<>(EllipticCurveConstants.CURVES_COUNTER);

        registerEllipticCurve(EllipticCurveConstants.secp256r1.PARAMETERS);
        setCurrentEllipticCurve(EllipticCurveConstants.secp256r1.NAME);

        confidentialSchemeId = EllipticCurveConstants.secp256r1.NAME;
    }

    public CobraConfidentialityScheme(View view, EllipticCurveParameters ellipticCurveParameters) throws SecretSharingException {
        cipherLock = new ReentrantLock(true);
        int[] processes = view.getProcesses();
        serverToShareholder = new HashMap<>(processes.length);
        shareholderToServer = new HashMap<>(processes.length);
        BigInteger[] shareholders = new BigInteger[processes.length];
        for (int i = 0; i < processes.length; i++) {
            int process = processes[i];
            BigInteger shareholder = BigInteger.valueOf(process + 1);
            serverToShareholder.put(process, shareholder);
            shareholderToServer.put(shareholder, process);
            shareholders[i] = shareholder;
        }

        threshold = view.getF();
        Configuration configuration = Configuration.getInstance();

        Properties properties = new Properties();
        properties.put(Constants.TAG_THRESHOLD, String.valueOf(threshold));
        properties.put(Constants.TAG_DATA_ENCRYPTION_ALGORITHM, configuration.getDataEncryptionAlgorithm());
        properties.put(Constants.TAG_COMMITMENT_SCHEME, configuration.getVssScheme());
        if (configuration.getVssScheme().equals("1")) {
            properties.put(Constants.TAG_PRIME_FIELD, configuration.getPrimeField());
            properties.put(Constants.TAG_SUB_FIELD, configuration.getSubPrimeField());
            properties.put(Constants.TAG_GENERATOR, configuration.getGenerator());
        }
        try {
            cipher = Cipher.getInstance(configuration.getShareEncryptionAlgorithm());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new SecretSharingException("Failed to initialize the cipher");
        }
        vss = new VSSFacade(properties, shareholders);
        keysManager = new KeysManager();
        isLinearCommitmentScheme = Configuration.getInstance().getVssScheme().equals("1");
        useTLSEncryption = configuration.useTLSEncryption();

        ellipticCurveCommitmentSchemesMap = new HashMap<>(EllipticCurveConstants.CURVES_COUNTER);

        registerEllipticCurve(ellipticCurveParameters);
        setCurrentEllipticCurve(ellipticCurveParameters.curveName());

        confidentialSchemeId = ellipticCurveParameters.curveName();
    }

    public String getConfidentialSchemeId() {
        return confidentialSchemeId;
    }

    public boolean setCurrentEllipticCurve(String curveName) {
        EllipticCurveCommitmentScheme nextEllipticCurve = ellipticCurveCommitmentSchemesMap.get(curveName);
        if (nextEllipticCurve == null) return false;
        if (nextEllipticCurve == currentEllipticCurveCommitmentScheme) return true;
        currentEllipticCurveCommitmentScheme = nextEllipticCurve;
        return true;
    }

    public void registerEllipticCurve(EllipticCurveParameters ecParams) {
        try {
            EllipticCurveCommitmentScheme nextEllipticCurve = new EllipticCurveCommitmentScheme(
                    ecParams.prime(),
                    ecParams.order(),
                    ecParams.a(),
                    ecParams.b(),
                    ecParams.x(),
                    ecParams.y(),
                    ecParams.cofactor()
            );
            ellipticCurveCommitmentSchemesMap.put(ecParams.curveName(), nextEllipticCurve);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public EllipticCurveCommitmentScheme getCurrentEllipticCurveCommitmentScheme() {
        return currentEllipticCurveCommitmentScheme;
    }

    public boolean useTLSEncryption() {
        return useTLSEncryption;
    }

    public BigInteger getField() {
        return vss.getField();
    }

    public InterpolationStrategy getInterpolationStrategy() {
        return vss.getInterpolationStrategy();
    }

    public boolean isLinearCommitmentScheme() {
        return isLinearCommitmentScheme;
    }

    public void addShareholder(int newServer, BigInteger shareholderId) throws SecretSharingException {
        vss.addShareholder(shareholderId);
        serverToShareholder.put(newServer, shareholderId);
        shareholderToServer.put(shareholderId, newServer);
    }

    public CommitmentScheme getCommitmentScheme() {
        return vss.getCommitmentScheme();
    }

    public BigInteger getShareholder(int process) {
        return serverToShareholder.get(process);
    }

    public int getProcess(BigInteger shareholder) {
        return shareholderToServer.get(shareholder);
    }

    public void updateParameters(View view) {
        throw new UnsupportedOperationException("Not implemented");
    }

    public PublicKey getSigningPublicKeyFor(int id) {
        return keysManager.getSigningPublicKeyFor(id);
    }

    public PrivateKey getSigningPrivateKey() {
        return keysManager.getSigningKey();
    }

    public byte[] encryptDataFor(int id, byte[] data) {
        Key encryptionKey = keysManager.getEncryptionKeyFor(id);

        try {
            return encrypt(data, encryptionKey);
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
            return null;
        }
    }

    public byte[] encryptShareFor(int id, Share clearShare) throws SecretSharingException {
        Key encryptionKey = keysManager.getEncryptionKeyFor(id);

        try {
            return encrypt(clearShare.getShare().toByteArray(), encryptionKey);
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new SecretSharingException("Failed to encrypt share", e);
        }
    }

    public BigInteger decryptShareFor(int id, byte[] encryptedShare) throws SecretSharingException {
        Key decryptionKey = keysManager.getDecryptionKeyFor(id);
        try {
            return new BigInteger(decrypt(encryptedShare, decryptionKey));
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new SecretSharingException("Failed to decrypt share", e);
        }
    }

    public byte[] decryptData(int id, byte[] encryptedData) {
        Key decryptionKey = keysManager.getDecryptionKeyFor(id);
        try {
            return decrypt(encryptedData, decryptionKey);
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
            return null;
        }
    }

    protected byte[] encrypt(byte[] data, Key encryptionKey) throws InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        try {
            cipherLock.lock();
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
            return cipher.doFinal(data);
        } finally {
            cipherLock.unlock();
        }
    }

    protected byte[] decrypt(byte[] data, Key decryptionKey) throws InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        try {
            cipherLock.lock();
            cipher.init(Cipher.DECRYPT_MODE, decryptionKey);
            return cipher.doFinal(data);
        } finally {
            cipherLock.unlock();
        }
    }

    public BigInteger getCurrentEllipticCurveField() {
        return currentEllipticCurveCommitmentScheme.getOrder();
    }

    public Commitment generateEllipticCurveCommitment(Polynomial polynomial) {
        return currentEllipticCurveCommitmentScheme.generateCommitments(polynomial);
    }

    public boolean checkEllipticCurveCommitment(Share share, Commitment commitment) {
        return currentEllipticCurveCommitmentScheme.checkValidity(share, commitment);
    }

    public Commitment sumEllipticCurveCommitments(Commitment... commitments) throws SecretSharingException {
        return currentEllipticCurveCommitmentScheme.sumCommitments(commitments);
    }

    public void serializeProposalMessage(ProposalMessage message, ObjectOutput out) throws IOException {
        int id = message.getId();
        int sender = message.getSender();
        Proposal[] proposals = message.getProposals();
        byte[] signature = message.getSignature();

        out.writeInt(id);
        out.writeInt(sender);
        out.writeInt(proposals == null ? -1 : proposals.length);
        if (proposals != null) {
            for (Proposal proposal : proposals) {
                writeProposal(proposal, out);
            }
        }
        out.writeInt(signature == null ? -1 : signature.length);
        if (signature != null)
            out.write(signature);
    }

    public void serializeMissingProposalMessage(MissingProposalsMessage message, ObjectOutput out) throws IOException {
        int id = message.getId();
        int sender = message.getSender();
        ProposalMessage proposal = message.getMissingProposal();
        out.writeInt(id);
        out.writeInt(sender);
        serializeProposalMessage(proposal, out);
    }

    public ProposalMessage deserializeProposalMessage(ObjectInput in) throws IOException, ClassNotFoundException {
        int id = in.readInt();
        int sender = in.readInt();
        Proposal[] proposals = null;
        byte[] signature = null;

        int len = in.readInt();
        if (len != -1) {
            proposals = new Proposal[len];
            for (int i = 0; i < len; i++) {
                proposals[i] = readProposal(in);
            }
        }
        len = in.readInt();
        if (len != -1) {
            signature = new byte[len];
            in.readFully(signature);
        }
        ProposalMessage proposalMessage = new ProposalMessage(id, sender, confidentialSchemeId, proposals);
        proposalMessage.setSignature(signature);
        return proposalMessage;
    }

    public MissingProposalsMessage deserializeMissingProposalMessage(ObjectInput in) throws IOException, ClassNotFoundException {
        int id = in.readInt();
        int sender = in.readInt();
        ProposalMessage proposal = deserializeProposalMessage(in);
        return new MissingProposalsMessage(id, sender, confidentialSchemeId, proposal);
    }

    private void writeProposal(Proposal proposal, ObjectOutput out) throws IOException {
        Map<Integer, byte[]> points = proposal.getPoints();
        Commitment commitments = proposal.getCommitments();
        out.writeInt(points == null ? -1 : points.size());
        if (points != null) {
            for (Map.Entry<Integer, byte[]> entry : points.entrySet()) {
                out.writeInt(entry.getKey());
                byte[] b = entry.getValue();
                out.writeInt(b.length);
                out.write(b);

            }
        }
        out.writeBoolean(commitments != null);
        if (commitments != null) {
            out.writeBoolean(commitments instanceof EllipticCurveCommitment);
            if (commitments instanceof EllipticCurveCommitment)
                currentEllipticCurveCommitmentScheme.writeCommitment(commitments, out);
            else
                CommitmentUtils.getInstance().writeCommitment(commitments, out);
        }
    }

    private Proposal readProposal(ObjectInput in) throws IOException, ClassNotFoundException {
        Map<Integer, byte[]> points = null;
        int size = in.readInt();
        if (size != -1) {
            points = new HashMap<>(size);
            byte[] b;
            while (size-- > 0) {
                int shareholder = in.readInt();
                b = new byte[in.readInt()];
                in.readFully(b);
                points.put(shareholder, b);
            }
        }
        Commitment commitment = null;
        if (in.readBoolean()) {
            if (in.readBoolean()) {
                commitment = currentEllipticCurveCommitmentScheme.readCommitment(in);
            } else {
                commitment = CommitmentUtils.getInstance().readCommitment(in);
            }
        }
        return new Proposal(points, commitment);
    }
}
