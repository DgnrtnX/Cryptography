package com.algorithms.cryptography.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.algorithms.cryptography.model.RequestDataModel;
import com.algorithms.cryptography.service.GCMService;

@RestController
public class AlgoController {

	@Autowired
	private GCMService gcmService;

	@PostMapping(value = "/aes-gcm/encrypt", consumes = "application/json")
	public void encAESGCM(@RequestBody RequestDataModel requestData) {
		gcmService.encryptGCM(requestData);
	}

	@PostMapping(value = "/aes-gcm/decrypt", consumes = "application/json")
	public void decAESGCM(@RequestBody RequestDataModel requestData) {
		gcmService.decryptGCM(requestData);
	}
}
