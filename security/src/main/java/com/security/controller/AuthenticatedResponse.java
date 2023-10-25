package com.security.controller;

import java.util.Date;

public record AuthenticatedResponse(String user ,String access_token, Date validTo ) {

}
