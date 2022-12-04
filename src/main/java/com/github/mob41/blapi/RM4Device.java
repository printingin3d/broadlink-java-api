package com.github.mob41.blapi;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import com.github.mob41.blapi.mac.Mac;
import com.github.mob41.blapi.pkt.CmdPayload;

public class RM4Device extends RM2Device {

    protected RM4Device(short deviceType, String deviceDesc, String host, Mac mac) throws IOException {
        super(deviceType, deviceDesc, host, mac);
    }
    
    @Override
    protected byte[] createPayload(CmdPayload cmdPayload) {
        int l = cmdPayload.getPayload().getData().length;
        ByteBuffer b = ByteBuffer.allocate(6+l);
        b.order(ByteOrder.LITTLE_ENDIAN);
        b.putShort((short)(l+4));
        b.putInt(cmdPayload.getCommand());
        b.put(cmdPayload.getPayload().getData());
        return b.array();
    }
}
