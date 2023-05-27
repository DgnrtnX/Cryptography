package com.algorithms.cryptography.model;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class RequestDataModel {
	private String requestorId;
	private String ds;
	private String requestTime;
	private String encData;
}
