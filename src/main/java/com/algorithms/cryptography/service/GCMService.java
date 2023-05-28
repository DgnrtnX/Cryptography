package com.algorithms.cryptography.service;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.algorithms.cryptography.model.RequestDataModel;
import com.algorithms.cryptography.util.AESGCMUtil;
import com.algorithms.cryptography.util.AESGCMUtil.CryptoException;
import com.algorithms.cryptography.util.HashUtil;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class GCMService {

	@Autowired
	private AESGCMUtil aesgcmUtil;

	@Autowired
	private HashUtil hashUtil;

	public void encryptGCM(RequestDataModel requestData) {
		log.info("ENCRYPTING DATA");
		try {
			long epochTime = ZonedDateTime.parse(requestData.getRequestTime()).toInstant().toEpochMilli();
			log.info("epochTime value is {}", epochTime);

			String nonce = hashUtil.cipherNumber(epochTime);

			byte[] key = null;
			try {
				key = hashUtil.generatePBKDF2Key(requestData.getRequestorId(), nonce, nonce.length());
			} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			List<String> associatesList = Arrays.asList(requestData.getRequestorId(), requestData.getDs(),
					requestData.getRequestTime());

			String encrptedData = aesgcmUtil.encrypt(requestData.getEncData(), key, nonce.getBytes(), associatesList);
			log.info("encrypted data is {}", encrptedData);

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void decryptGCM(RequestDataModel requestData) {
		log.info("DECRYPTING DATA");
		try {
			long epochTime = ZonedDateTime.parse(requestData.getRequestTime()).toInstant().toEpochMilli();
			log.info("epochTime value is {}", epochTime);

			String nonce = hashUtil.cipherNumber(epochTime);

			byte[] key = null;
			try {
				key = hashUtil.generatePBKDF2Key(requestData.getRequestorId(), nonce, nonce.length());
			} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			List<String> associatesList = Arrays.asList(requestData.getRequestorId(), requestData.getDs(),
					requestData.getRequestTime());

			String decryptedData = aesgcmUtil.decrypt(requestData.getEncData(), key, nonce.getBytes(), associatesList);
			log.info("Decrypted Data is {}", decryptedData);

		} catch (CryptoException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
