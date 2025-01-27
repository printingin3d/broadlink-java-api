/*******************************************************************************
 * MIT License
 *
 * Copyright (c) 2016, 2017 Anthony Law
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Contributors:
 *      - Anthony Law (mob41) - Initial API Implementation
 *      - bwssytems
 *      - Christian Fischer (computerlyrik)
 *******************************************************************************/

package com.github.mob41.blapi;

import java.net.DatagramPacket;

import javax.xml.bind.DatatypeConverter;

import com.github.mob41.blapi.mac.Mac;
import com.github.mob41.blapi.pkt.cmd.rm2.RMTempCmdPayload;
import com.github.mob41.blapi.pkt.cmd.rm2.SendDataCmdPayload;

public class SP2Device extends BLDevice {

    public SP2Device(short deviceType, String deviceDesc, String host, Mac mac) {
        super(deviceType, deviceDesc, host, mac);
    }

    public void setState(final boolean state) throws Exception {
        DatagramPacket packet = sendCmdPkt(new SendDataCmdPayload(new byte[] { (byte) (state ? 1 : 0) }));

        byte[] data = packet.getData();

        log.debug("SP2 set state received encrypted bytes: " + DatatypeConverter.printHexBinary(data));

        int err = data[0x22] | (data[0x23] << 8);

        if (err != 0) {
            log.warn("SP2 set state received returned err: " + Integer.toHexString(err) + " / " + err);        	
        }
    }

    public boolean getState() throws Exception {
        DatagramPacket packet = sendCmdPkt(new RMTempCmdPayload());
        byte[] data = packet.getData();

        log.debug("SP2 get state received encrypted bytes: " + DatatypeConverter.printHexBinary(data));

        int err = data[0x22] | (data[0x23] << 8);

        if (err == 0) {
            byte[] pl = decryptFromDeviceMessage(data);
            log.debug("SP2 get state  received bytes (decrypted): " + DatatypeConverter.printHexBinary(pl));
            return pl[0x4] == 1 ? true : false;
        } else {
            log.warn("SP2 get state received an error: " + Integer.toHexString(err) + " / " + err);
        }

        return false;
    }
}
