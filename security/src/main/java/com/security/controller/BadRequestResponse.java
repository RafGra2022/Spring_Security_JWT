package com.security.controller;

import java.util.List;

public record BadRequestResponse(List<ErrorDetail> errors) {

}
