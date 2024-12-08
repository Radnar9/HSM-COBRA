package confidential.demo.keygen.server;

import bftsmart.tom.MessageContext;
import bftsmart.tom.ServiceReplica;
import confidential.ConfidentialMessage;
import confidential.EllipticCurveConstants;
import confidential.demo.keygen.KeyGenRequest;
import confidential.facade.server.ConfidentialSingleExecutable;
import confidential.polynomial.DistributedPolynomialManager;
import confidential.polynomial.RandomKeyPolynomialListener;
import confidential.polynomial.RandomPolynomialContext;
import confidential.server.ConfidentialRecoverable;
import confidential.server.ServerConfidentialityScheme;
import confidential.statemanagement.ConfidentialSnapshot;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.ellipticCurve.EllipticCurveCommitment;
import vss.facade.SecretSharingException;
import vss.secretsharing.VerifiableShare;

import java.io.*;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;


public class Server implements ConfidentialSingleExecutable, RandomKeyPolynomialListener {
	private final Logger logger = LoggerFactory.getLogger("keygen");
	private final DistributedPolynomialManager distributedPolynomialManager;
	private final ServiceReplica serviceReplica;
	private final ConfidentialRecoverable cr;

	//used during requests and data map access
	private final Lock lock;
	private final int id;

	//used to store requests asking for a random number
	private Map<Integer, MessageContext> requests;  // <polynomial id, MessageContext>
	//used to store random number's shares of clients
	private Map<Integer, VerifiableShare> data; // <client id, random number's share>

	//used to store requests asking for generation of a signing key
    private record RequestData(String indexId, MessageContext messageContext) {}

	private final Map<Integer, String> signingKeyGenerationIds; // keygen id: index id
	private final Map<String, RequestData> signingKeyRequests; // index id: req.data

    private record KeyPair(VerifiableShare privateKeyShare, byte[] publicKey) {}
    private final Map<String, KeyPair> signingKeyPairsMap;

	public static void main(String[] args) throws NoSuchAlgorithmException, SecretSharingException {
		if (args.length < 1) {
			System.out.println("Usage: confidential.demo.keygen.server.Server <server id>");
			System.exit(-1);
		}
		new Server(Integer.parseInt(args[0]));
	}

	public Server(int id) throws NoSuchAlgorithmException, SecretSharingException {
		this.id = id;
		lock = new ReentrantLock(true);
		requests = new TreeMap<>();
		data = new TreeMap<>();

		signingKeyGenerationIds = new HashMap<>();
		signingKeyRequests = new HashMap<>();
        signingKeyPairsMap = new TreeMap<>();
		cr = new ConfidentialRecoverable(id, this);

		serviceReplica = new ServiceReplica(id, cr, cr, cr);
		distributedPolynomialManager = cr.getDistributedPolynomialManager();
		distributedPolynomialManager.setRandomKeyPolynomialListener(this);

		var confidentialitySchemes = new HashMap<String, ServerConfidentialityScheme>();
		confidentialitySchemes.put(
				EllipticCurveConstants.BLS12_381.NAME,
				new ServerConfidentialityScheme(id, serviceReplica.getReplicaContext().getCurrentView(), EllipticCurveConstants.BLS12_381.PARAMETERS)
		);
		confidentialitySchemes.put(
				EllipticCurveConstants.secp256r1.NAME,
				new ServerConfidentialityScheme(id, serviceReplica.getReplicaContext().getCurrentView(), EllipticCurveConstants.secp256r1.PARAMETERS)
		);
		confidentialitySchemes.put(
				EllipticCurveConstants.secp256k1.NAME,
				new ServerConfidentialityScheme(id, serviceReplica.getReplicaContext().getCurrentView(), EllipticCurveConstants.secp256k1.PARAMETERS)
		);
		cr.registerConfidentialitySchemes(confidentialitySchemes);
	}

	@Override
	public ConfidentialMessage appExecuteOrdered(byte[] bytes, VerifiableShare[] verifiableShares, MessageContext messageContext) {
		try {
			lock.lock();
			KeyGenRequest request = KeyGenRequest.deserialize(bytes);
			String indexId = request.privateKeyId() + messageContext.getSender();
			logger.info("Received a request with indexID {} from {} in cid {}", indexId, messageContext.getSender(), messageContext.getConsensusId());

			boolean dbContainsIndex = signingKeyPairsMap.containsKey(indexId);
			if (!dbContainsIndex && !signingKeyRequests.containsKey(indexId)) {
				signingKeyRequests.put(indexId, new RequestData(indexId, messageContext));
				int signingKeyGenerationId;
				switch (request.ellipticCurve()) {
					case "BLS12_381" -> signingKeyGenerationId = generateSigningKey(EllipticCurveConstants.BLS12_381.NAME);
					case "secp256k1" -> signingKeyGenerationId = generateSigningKey(EllipticCurveConstants.secp256k1.NAME);
					case "secp256r1" -> signingKeyGenerationId = generateSigningKey(EllipticCurveConstants.secp256r1.NAME);
					default -> throw new InputMismatchException("Elliptic curve not supported: " + request.ellipticCurve());
				}
				signingKeyGenerationIds.put(signingKeyGenerationId, indexId);
			} else if (dbContainsIndex) {
				logger.warn("I already have a signing key with the provided identifier.");
				return new ConfidentialMessage(signingKeyPairsMap.get(indexId).publicKey);
			} else {
				logger.warn("Signing key is being created.");
			}
		} catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        } finally {
			lock.unlock();
		}
		return null;
	}

	/**
	 * Method used to generate a signing key.
	 */
	private int generateSigningKey(String confidentialitySchemeId) {
		return distributedPolynomialManager.createRandomKeyPolynomial(
				serviceReplica.getReplicaContext().getCurrentView().getF(),
				serviceReplica.getReplicaContext().getCurrentView().getProcesses(),
				confidentialitySchemeId);
	}

	/**
	 * Method called by the polynomial generation manager when the requested random key is generated
	 * @param context Random number share and its context
	 */
	@Override
	public void onRandomKeyPolynomialsCreation(RandomPolynomialContext context) {
		lock.lock();
		VerifiableShare privateKeyShare = context.getPoint();
		ECPoint[] commitment = ((EllipticCurveCommitment)context.getPoint().getCommitments()).getCommitment();
		ECPoint publicKey = commitment[commitment.length - 1];
		onRandomKey(context.getInitialId(), privateKeyShare, publicKey);
		lock.unlock();
	}

    private void onRandomKey(int id, VerifiableShare privateKeyShare, ECPoint publicKey) {
		String indexId = signingKeyGenerationIds.get(id);
		logger.info("Received random signing key with indexId: {}", indexId);
		if (indexId != null) {
			RequestData requestData = signingKeyRequests.get(indexId);
            signingKeyPairsMap.put(
					indexId,
					new KeyPair(privateKeyShare, publicKey.getEncoded(true))
			);

			System.out.println("Private key share:\n" + privateKeyShare.getShare().getShare().toString(16) + "\n");
			System.out.println("Public key:\n" + new BigInteger(publicKey.getEncoded(true)).toString(16) + "\n");

			sendPublicKeyTo(requestData.messageContext, publicKey);

			signingKeyGenerationIds.remove(id);
			signingKeyRequests.remove(indexId);
        } else {
            logger.warn("Received an unknown polynomial id {}", id);
        }
    }

    private void sendPublicKeyTo(MessageContext receiverContext, ECPoint publicKey) {
        byte[] encodedPublicKey = publicKey.getEncoded(true);
		ConfidentialMessage response = new ConfidentialMessage(encodedPublicKey);
        cr.sendMessageToClient(receiverContext, response);
    }

	@Override
	public ConfidentialMessage appExecuteUnordered(byte[] bytes, VerifiableShare[] verifiableShares, MessageContext messageContext) {
		return null;
	}

	@Override
	public ConfidentialSnapshot getConfidentialSnapshot() {
		try (ByteArrayOutputStream bout = new ByteArrayOutputStream();
			 ObjectOutput out = new ObjectOutputStream(bout)) {
			out.writeInt(requests.size());
			for (Map.Entry<Integer, MessageContext> entry : requests.entrySet()) {
				out.writeInt(entry.getKey());
				out.writeObject(entry.getValue());
			}
			out.writeInt(data.size());
			VerifiableShare[] shares = new VerifiableShare[data.size()];
			int index = 0;
			for (Map.Entry<Integer, VerifiableShare> entry : data.entrySet()) {
				out.writeInt(entry.getKey());
				entry.getValue().writeExternal(out);
				shares[index++] = entry.getValue();
			}
			out.flush();
			bout.flush();
			return new ConfidentialSnapshot(bout.toByteArray(), shares);
		} catch (IOException e) {
			logger.error("Error while taking snapshot", e);
		}
		return null;
	}

	@Override
	public void installConfidentialSnapshot(ConfidentialSnapshot confidentialSnapshot) {
		try (ByteArrayInputStream bin = new ByteArrayInputStream(confidentialSnapshot.getPlainData());
			 ObjectInput in = new ObjectInputStream(bin)) {
			int size = in.readInt();
			requests = new TreeMap<>();
			while (size-- > 0) {
				int key = in.readInt();
				MessageContext value = (MessageContext) in.readObject();
				requests.put(key, value);
			}
			size = in.readInt();
			data = new TreeMap<>();
			VerifiableShare[] shares = confidentialSnapshot.getShares();
			for (int i = 0; i < size; i++) {
				int key = in.readInt();
				VerifiableShare value = shares[i];
				value.readExternal(in);
				data.put(key, value);
			}
		} catch (IOException | ClassCastException | ClassNotFoundException e) {
			logger.error("Error while installing snapshot", e);
		}
	}
}
