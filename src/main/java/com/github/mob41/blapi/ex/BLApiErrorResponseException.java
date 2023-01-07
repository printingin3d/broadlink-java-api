package com.github.mob41.blapi.ex;

public class BLApiErrorResponseException extends BLApiRuntimeException {
    private static final long serialVersionUID = -2282068764282969897L;

    public BLApiErrorResponseException(String function, int err) {
        super("RM2 "+function+" received error: " + Integer.toHexString(err) + " / " + err);
    }
}
