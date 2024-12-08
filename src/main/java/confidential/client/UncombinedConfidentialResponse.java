package confidential.client;

import confidential.ExtractedResponse;
import vss.secretsharing.VerifiableShare;


public class UncombinedConfidentialResponse extends ExtractedResponse {
	private final VerifiableShare[][] verifiableShares;
	private final byte[][] sharedData;

	public UncombinedConfidentialResponse(int viewID, byte[] plainData, VerifiableShare[][] verifiableShares, byte[][] sharedData) {
		super(plainData, null);
		this.setViewID(viewID);
		this.verifiableShares = verifiableShares;
		this.sharedData = sharedData;
	}

	public VerifiableShare[][] getVerifiableShares() {
		return verifiableShares;
	}

	public byte[] getPlainData() {
		return this.getContent();
	}

	public byte[][] getSharedData() {
		return sharedData;
	}
}
