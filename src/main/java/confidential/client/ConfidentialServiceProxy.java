package confidential.client;

import bftsmart.tom.ExtendedServiceProxy;
import bftsmart.tom.util.ServiceResponse;
import confidential.Configuration;
import confidential.ExtractedResponse;
import confidential.MessageType;
import confidential.Metadata;
import confidential.encrypted.EncryptedPublishedShares;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.Commitment;
import vss.commitment.CommitmentUtils;
import vss.commitment.constant.ConstantCommitment;
import vss.facade.Mode;
import vss.facade.SecretSharingException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public class ConfidentialServiceProxy {
    private final Logger logger = LoggerFactory.getLogger("confidential");
    private final ExtendedServiceProxy service;
    private final ClientConfidentialityScheme confidentialityScheme;
    private final ServersResponseHandler serversResponseHandler;
    private final boolean isLinearCommitmentScheme;
    private final boolean isSendAllSharesTogether;

	public ConfidentialServiceProxy(int clientId) throws SecretSharingException {
		this(clientId, null);
	}

    public ConfidentialServiceProxy(int clientId, ServersResponseHandler customServersResponseHandler) throws SecretSharingException {
        if (customServersResponseHandler == null) {
			if (Configuration.getInstance().useTLSEncryption()) {
				serversResponseHandler = new PlainServersResponseHandler();
			} else {
				serversResponseHandler = new EncryptedServersResponseHandler(clientId);
			}
		} else {
			serversResponseHandler = customServersResponseHandler;
		}
        this.service = new ExtendedServiceProxy(clientId, serversResponseHandler,
                serversResponseHandler, serversResponseHandler);
        this.confidentialityScheme = new ClientConfidentialityScheme(service.getViewManager().getCurrentView());
        serversResponseHandler.setClientConfidentialityScheme(confidentialityScheme);
        isLinearCommitmentScheme = confidentialityScheme.isLinearCommitmentScheme();
        isSendAllSharesTogether = Configuration.getInstance().isSendAllSharesTogether();
    }

	public int getProcessId() {
		return service.getProcessId();
	}

	public int getCurrentF() {
		return service.getViewManager().getCurrentViewF();
	}

	public int getCurrentN() {
		return service.getViewManager().getCurrentViewN();
	}

	public Response invokeOrdered(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
		ServiceResponse response = invokeOrdered(plainData, Mode.LARGE_SECRET, confidentialData);
		return composeResponse(response);
	}

    public ServiceResponse invokeOrderedOperation(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
        return invokeOrdered(plainData, Mode.LARGE_SECRET, confidentialData);
    }

	public Response invokeOrderedHashed(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
		ServiceResponse response = invokeOrderedHashed(plainData, Mode.LARGE_SECRET, confidentialData);
		return composeResponse(response);
	}

	public Response invokeUnordered(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
		ServiceResponse response = invokeUnordered(plainData, Mode.LARGE_SECRET, confidentialData);
		return composeResponse(response);
	}

	public Response invokeUnorderedHashed(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
		ServiceResponse response = invokeUnorderedHashed(plainData, Mode.LARGE_SECRET, confidentialData);
		return composeResponse(response);
	}

    public ServiceResponse invokeOrdered(byte[] plainData, Mode mode, byte[]... confidentialData) throws SecretSharingException {
        serversResponseHandler.reset();
        EncryptedPublishedShares[] shares = sharePrivateData(mode, confidentialData);
        if (confidentialData.length != 0 && shares == null)
            return null;
        byte[] commonData = serializeCommonData(plainData, shares);
        if (commonData == null)
            return null;

        Map<Integer, byte[]> privateData = null;
        if (!isSendAllSharesTogether && confidentialData.length != 0) {
            int[] servers = service.getViewManager().getCurrentViewProcesses();
            privateData = new HashMap<>(servers.length);
            for (int server : servers) {
                byte[] b = serializePrivateDataFor(server, shares);
                privateData.put(server, b);
            }
        }
        byte metadata = (byte)(confidentialData.length == 0 ? Metadata.DOES_NOT_VERIFY.ordinal() : Metadata.VERIFY.ordinal());
        return service.invokeOrdered(commonData, privateData, metadata);
    }

	public ServiceResponse invokeOrderedHashed(byte[] plainData, Mode mode, byte[]... confidentialData) throws SecretSharingException {
		serversResponseHandler.reset();
		EncryptedPublishedShares[] shares = sharePrivateData(mode, confidentialData);
		if (confidentialData.length != 0 && shares == null)
			return null;
		byte[] commonData = serializeCommonData(plainData, shares);
		if (commonData == null)
			return null;

		Map<Integer, byte[]> privateData = null;
		if (!isSendAllSharesTogether && confidentialData.length != 0) {
			int[] servers = service.getViewManager().getCurrentViewProcesses();
			privateData = new HashMap<>(servers.length);
			for (int server : servers) {
				byte[] b = serializePrivateDataFor(server, shares);
				privateData.put(server, b);
			}
		}
		byte metadata = (byte)(confidentialData.length == 0 ? Metadata.DOES_NOT_VERIFY.ordinal() : Metadata.VERIFY.ordinal());
		return service.invokeOrderedHashed(commonData, privateData, metadata);
	}

    public ServiceResponse invokeUnordered(byte[] plainData, Mode mode, byte[]... confidentialData) throws SecretSharingException {
        serversResponseHandler.reset();
        EncryptedPublishedShares[] shares = sharePrivateData(mode, confidentialData);
        if (confidentialData.length != 0 && shares == null)
            return null;
        byte[] commonData = serializeCommonData(plainData, shares);
        if (commonData == null)
            return null;

        Map<Integer, byte[]> privateData = null;
        if (!isSendAllSharesTogether && confidentialData.length != 0) {
            int[] servers = service.getViewManager().getCurrentViewProcesses();
            privateData = new HashMap<>(servers.length);
            for (int server : servers) {
                byte[] b = serializePrivateDataFor(server, shares);
                privateData.put(server, b);
            }
        }
        byte metadata = (byte)(confidentialData.length == 0 ? Metadata.DOES_NOT_VERIFY.ordinal() : Metadata.VERIFY.ordinal());
        return service.invokeUnordered(commonData, privateData, metadata);
    }

	public ServiceResponse invokeUnorderedHashed(byte[] plainData, Mode mode, byte[]... confidentialData) throws SecretSharingException {
		serversResponseHandler.reset();
		EncryptedPublishedShares[] shares = sharePrivateData(mode, confidentialData);
		if (confidentialData.length != 0 && shares == null)
			return null;
		byte[] commonData = serializeCommonData(plainData, shares);
		if (commonData == null)
			return null;

		Map<Integer, byte[]> privateData = null;
		if (!isSendAllSharesTogether && confidentialData.length != 0) {
			int[] servers = service.getViewManager().getCurrentViewProcesses();
			privateData = new HashMap<>(servers.length);
			for (int server : servers) {
				byte[] b = serializePrivateDataFor(server, shares);
				privateData.put(server, b);
			}
		}
		byte metadata = (byte)(confidentialData.length == 0 ? Metadata.DOES_NOT_VERIFY.ordinal() : Metadata.VERIFY.ordinal());
		return service.invokeUnorderedHashed(commonData, privateData, metadata);
	}

    public void close() {
        service.close();
    }

    private Response composeResponse(ServiceResponse response) throws SecretSharingException {
		if (response == null)
			return null;
		ExtractedResponse extractedResponse = (ExtractedResponse) response;

		if (extractedResponse.getThrowable() != null)
			throw extractedResponse.getThrowable();
		return new Response(extractedResponse.getContent(), extractedResponse.getConfidentialData());
    }

    private byte[] serializePrivateDataFor(int server, EncryptedPublishedShares[] shares) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            if (shares != null) {
                BigInteger shareholder = confidentialityScheme.getShareholder(server);
                for (EncryptedPublishedShares share : shares) {
                    byte[] encryptedShareBytes = share.getShareOf(server);
                    out.writeInt(encryptedShareBytes == null ? -1 : encryptedShareBytes.length);
                    if (encryptedShareBytes != null)
                        out.write(encryptedShareBytes);
                    if (!isLinearCommitmentScheme) {
                        ConstantCommitment commitment = (ConstantCommitment)share.getCommitment();
                        byte[] witness = commitment.getWitness(shareholder);
                        out.writeInt(witness.length);
                        out.write(witness);
                    }
                }
            }

            out.flush();
            bos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            logger.error("Occurred while composing request", e);
            return null;
        }
    }

    private byte[] serializeCommonData(byte[] plainData, EncryptedPublishedShares[] shares) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {

            out.write((byte) MessageType.CLIENT.ordinal());

            out.writeInt(plainData == null ? -1 : plainData.length);
            if (plainData != null)
                out.write(plainData);

            out.writeInt(shares == null ? -1 : shares.length);
            if (shares != null) {
                for (EncryptedPublishedShares share : shares) {
                    if (isSendAllSharesTogether) {
                        share.writeExternal(out);
                    } else {
                        byte[] sharedData = share.getSharedData();
                        Commitment commitment = share.getCommitment();
                        out.writeInt(sharedData == null ? -1 : sharedData.length);
                        if (sharedData != null)
                            out.write(sharedData);
                        if (isLinearCommitmentScheme)
                            CommitmentUtils.getInstance().writeCommitment(commitment, out);
                        else {
                            byte[] c = ((ConstantCommitment) commitment).getCommitment();
                            out.writeInt(c.length);
                            out.write(c);
                        }
                    }

                }
            }

            out.flush();
            bos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            logger.error("Occurred while composing request", e);
            return null;
        }
    }

    private EncryptedPublishedShares[] sharePrivateData(Mode mode, byte[]... privateData) throws SecretSharingException {
        if (privateData == null)
            return null;
        EncryptedPublishedShares[] result = new EncryptedPublishedShares[privateData.length];
        for (int i = 0; i < privateData.length; i++) {
            result[i] = confidentialityScheme.share(privateData[i], mode);
        }
        return result;
    }
}
