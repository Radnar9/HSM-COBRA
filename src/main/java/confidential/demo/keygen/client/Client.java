package confidential.demo.keygen.client;

import confidential.client.ConfidentialServiceProxy;
import confidential.client.ServersResponseHandlerWithoutCombine;
import confidential.client.UncombinedConfidentialResponse;
import confidential.demo.keygen.KeyGenRequest;
import vss.facade.SecretSharingException;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

public class Client {

	public static void main(String[] args) throws SecretSharingException, NoSuchAlgorithmException, IOException {
		if (args.length < 1) {
			System.out.println("Usage: confidential.demo.keygen.client.Client <client id>");
			System.exit(-1);
		}
		int clientId = Integer.parseInt(args[0]);
		String secp256k1 = "secp256k1"; // Schnorr
		String BLS12_381 = "BLS12_381";	// BLS
		String secp256r1 = "secp256r1";	// COBRA default

		ServersResponseHandlerWithoutCombine serversResponseHandler = new ServersResponseHandlerWithoutCombine(clientId);
		ConfidentialServiceProxy serviceProxy = new ConfidentialServiceProxy(clientId, serversResponseHandler);

		// Asking the verifier to generate the signing key - this operation should be called by a trusted client
		String indexId = "slb";
		KeyGenRequest keyGenRequest = new KeyGenRequest(indexId, secp256k1);
		UncombinedConfidentialResponse signingPublicKeyResponse = (UncombinedConfidentialResponse) serviceProxy.invokeOrderedOperation(keyGenRequest.serialize());
		BigInteger pk = new BigInteger(signingPublicKeyResponse.getPlainData());
		System.out.println("Signing public key for indexID " + indexId + ":\n" + pk.toString(16) + "\n");

//		Throws an error if we close and open in the same session
//		serviceProxy.close();
//		serversResponseHandler = new ServersResponseHandlerWithoutCombine(clientId);
//		serviceProxy = new ConfidentialServiceProxy(clientId, serversResponseHandler);

		// Using a different index identifier
		indexId = "scp";
		keyGenRequest = new KeyGenRequest(indexId, secp256k1);
		signingPublicKeyResponse = (UncombinedConfidentialResponse) serviceProxy.invokeOrderedOperation(keyGenRequest.serialize());
		pk = new BigInteger(signingPublicKeyResponse.getPlainData());
		System.out.println("Signing public key for indexID " + indexId + ":\n" + pk.toString(16) + "\n");

//		serviceProxy.close();
//		serversResponseHandler = new ServersResponseHandlerWithoutCombine(clientId);
//		serviceProxy = new ConfidentialServiceProxy(clientId, serversResponseHandler);

		// Using a previously used index identifier
		indexId = "slb";
		keyGenRequest = new KeyGenRequest(indexId, secp256k1);
		signingPublicKeyResponse = (UncombinedConfidentialResponse) serviceProxy.invokeOrderedOperation(keyGenRequest.serialize());
		pk = new BigInteger(signingPublicKeyResponse.getPlainData());
		System.out.println("Signing public key for indexID " + indexId + ":\n" + pk.toString(16) + "\n");

		// Using a different elliptic curve
		indexId = "BLS12_381";
		keyGenRequest = new KeyGenRequest(indexId, BLS12_381);
		signingPublicKeyResponse = (UncombinedConfidentialResponse) serviceProxy.invokeOrderedOperation(keyGenRequest.serialize());
		pk = new BigInteger(signingPublicKeyResponse.getPlainData());
		System.out.println("Signing public key for indexID " + indexId + ":\n" + pk.toString(16) + "\n");

		// Using a previously used index identifier
		indexId = "secp256r1";
		keyGenRequest = new KeyGenRequest(indexId, secp256r1);
		signingPublicKeyResponse = (UncombinedConfidentialResponse) serviceProxy.invokeOrderedOperation(keyGenRequest.serialize());
		pk = new BigInteger(signingPublicKeyResponse.getPlainData());
		System.out.println("Signing public key for indexID " + indexId + ":\n" + pk.toString(16) + "\n");

		serviceProxy.close();
	}
}
