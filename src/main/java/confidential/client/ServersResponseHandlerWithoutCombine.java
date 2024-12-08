package confidential.client;

import bftsmart.tom.core.messages.TOMMessage;
import bftsmart.tom.util.ServiceResponse;
import confidential.ConfidentialMessage;
import vss.facade.SecretSharingException;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.math.BigInteger;
import java.util.*;


public class ServersResponseHandlerWithoutCombine extends ServersResponseHandler {
	private final int clientId;

	public ServersResponseHandlerWithoutCombine(int clientId) {
		this.clientId = clientId;
	}

	@Override
	public void setClientConfidentialityScheme(ClientConfidentialityScheme confidentialityScheme) {
		super.setClientConfidentialityScheme(confidentialityScheme);
	}

	@Override
	public ServiceResponse extractResponse(TOMMessage[] replies, int sameContent, int lastReceived) {
		TOMMessage lastMsg = replies[lastReceived];
		ConfidentialMessage response;
		Map<Integer, LinkedList<ConfidentialMessage>> msgs = new HashMap<>();
		for (TOMMessage msg : replies) {
			if (msg == null)
				continue;
			response = responses.get(msg.getContent());
			if (response == null) {
				logger.warn("Something went wrong while getting deserialized response from {}", msg.getSender());
				continue;
			}
			int responseHash = responseHashes.get(response);

			LinkedList<ConfidentialMessage> msgList = msgs.computeIfAbsent(responseHash, k -> new LinkedList<>());
			msgList.add(response);
		}

		for (LinkedList<ConfidentialMessage> msgList : msgs.values()) {
			if (msgList.size() == sameContent) {
				ConfidentialMessage firstMsg = msgList.getFirst();
				byte[] plainData = firstMsg.getPlainData();
				VerifiableShare[][] allVerifiableShares = null;
				byte[][] sharedData = null;

				if (firstMsg.getShares() != null) { // this response has secret data
					int numSecrets = firstMsg.getShares().length;
					ArrayList<LinkedList<VerifiableShare>> verifiableShares = new ArrayList<>(numSecrets);
					for (int i = 0; i < numSecrets; i++) {
						verifiableShares.add(new LinkedList<>());
					}
					for (ConfidentialMessage confidentialMessage : msgList) {
						VerifiableShare[] sharesI = confidentialMessage.getShares();
						for (int i = 0; i < numSecrets; i++) {
							verifiableShares.get(i).add(sharesI[i]);
						}
					}

					allVerifiableShares = new VerifiableShare[numSecrets][];
					sharedData = new byte[numSecrets][];
					for (int i = 0; i < numSecrets; i++) {
						LinkedList<VerifiableShare> secretI = verifiableShares.get(i);
						sharedData[i] = secretI.getFirst().getSharedData();
						int k = 0;
						allVerifiableShares[i] = new VerifiableShare[secretI.size()];
						for (VerifiableShare verifiableShare : secretI) {
							allVerifiableShares[i][k] = verifiableShare;
							k++;
						}
					}
				}
				return new UncombinedConfidentialResponse(lastMsg.getViewID(), plainData, allVerifiableShares, sharedData);
			}
		}
		logger.error("This should not happen. Did not found {} equivalent responses", sameContent);
		return null;
	}

	@Override
	protected Share reconstructShare(BigInteger shareholder, byte[] serializedShare) {
		if (confidentialityScheme.useTLSEncryption()) {
			return new Share(shareholder, new BigInteger(serializedShare));
		}
		try {
			return new Share(shareholder, confidentialityScheme.decryptShareFor(clientId, serializedShare));
		} catch (SecretSharingException e) {
			e.printStackTrace();
			return new Share(shareholder, new BigInteger(serializedShare));
		}
	}
}
