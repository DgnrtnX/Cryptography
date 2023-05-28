package com.algorithms.cryptography.util;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class AESGCMUtil {
	private static final int GCM_TAG_LENGTH = 128;

	public String encrypt(String plaintext, byte[] key, byte[] nonce, List<String> associatesList)
			throws CryptoException {
		log.info("inside actual encryption");

		byte[] associatedData = associatedDataToBytes(associatesList);

		GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
		cipher.init(true, new AEADParameters(new KeyParameter(key), GCM_TAG_LENGTH, nonce, associatedData));

		byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
		byte[] ciphertext = new byte[cipher.getOutputSize(plaintextBytes.length)];
		int len = cipher.processBytes(plaintextBytes, 0, plaintextBytes.length, ciphertext, 0);

		try {
			cipher.doFinal(ciphertext, len);
		} catch (InvalidCipherTextException e) {
			throw new CryptoException("Error during encryption: " + e.getMessage(), e);
		}

		ByteBuffer buffer = ByteBuffer.allocate(nonce.length + ciphertext.length);
		buffer.put(nonce);
		buffer.put(ciphertext);

		return Base64.getEncoder().encodeToString(buffer.array());
	}

	public String decrypt(String ciphertext, byte[] key, byte[] nonce, List<String> associatesList)
			throws CryptoException {
		log.info("inside actual decryption");

		byte[] encryptedBytes = Base64.getDecoder().decode(ciphertext);

		byte[] associatedData = associatedDataToBytes(associatesList);

		ByteBuffer buffer = ByteBuffer.wrap(encryptedBytes);
		byte[] extractedNonce = new byte[nonce.length];
		buffer.get(extractedNonce);

		GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
		cipher.init(false, new AEADParameters(new KeyParameter(key), GCM_TAG_LENGTH, nonce, associatedData));

		byte[] decryptedBytes = new byte[cipher.getOutputSize(buffer.remaining())];
		int len = cipher.processBytes(buffer.array(), buffer.position(), buffer.remaining(), decryptedBytes, 0);
		try {
			cipher.doFinal(decryptedBytes, len);
		} catch (InvalidCipherTextException e) {
			throw new CryptoException("Error during decryption: " + e.getMessage(), e);
		}

		return new String(decryptedBytes, StandardCharsets.UTF_8);
	}

	private byte[] associatedDataToBytes(List<String> associatesList) {
		if (associatesList == null || associatesList.isEmpty()) {
			return null;
		}

		ByteBuffer buffer = ByteBuffer.allocate(associatedDataLength(associatesList));
		for (String data : associatesList) {
			byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
			buffer.putInt(dataBytes.length);
			buffer.put(dataBytes);
		}

		return buffer.array();
	}

	private int associatedDataLength(List<String> associatesList) {
		int length = 0;
		for (String data : associatesList) {
			if (data != null) {
				length += data.length() + 4;
			}
		}
		return length;
	}

	public static class CryptoException extends Exception {

		private static final long serialVersionUID = 1885426599586334070L;

		public CryptoException(String message) {
			super(message);
		}

		public CryptoException(String message, Throwable cause) {
			super(message, cause);
		}
	}
}
