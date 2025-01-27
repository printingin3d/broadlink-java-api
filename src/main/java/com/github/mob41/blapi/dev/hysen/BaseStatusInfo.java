package com.github.mob41.blapi.dev.hysen;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base set of status codes
 * 
 * Adapted from https://github.com/mjg59/python-broadlink
 * 
 * @author alpapad
 */
public class BaseStatusInfo {
    /**
     * The specific logger for this class
     */
    protected static final Logger log = LoggerFactory.getLogger(BaseStatusInfo.class);	
    // remote_lock
    protected final boolean remoteLock;
    protected final boolean power;
    protected final boolean active;
    // temp_manual
    protected final boolean manualTemp;
    // room_temp
    protected final double roomTemp;
    // thermostat_temp
    protected final double thermostatTemp;
    // auto_mode
    protected final boolean autoMode;
    // loop_mode
    protected final LoopMode loopMode;
    // sensor
    protected final SensorControl sensorControl;
    // osv
    protected final short osv;
    // dif
    protected final short dif;
    // svh
    protected final short svh;
    // svl
    protected final short svl;
    // room_temp_adj
    protected final double roomTempAdjustment;
    // fre
    protected final AntiFreezing antiFreezing;
    // pon
    protected final PowerOnMemory powerOnMemory;

    // unsure
    protected final short fac;
    // external_temp
    protected final double externalTemp;

	private static String bytesToString(byte[] hashInBytes) {

        StringBuilder sb = new StringBuilder();
        for (byte b : hashInBytes) {
            sb.append(String.format("%04d ", b));
        }
        return sb.toString();

    }
	
    protected BaseStatusInfo(byte[] payload) {
    	log.debug("payload: {}",bytesToString(payload));
        this.remoteLock = byteToBool((byte) (payload[3] & 0x1));
        this.power = byteToBool((byte) (payload[4] & 1));
        this.active = byteToBool((byte) ((payload[4] >> 4) & 1));
        this.manualTemp = byteToBool((byte) ((payload[4] >> 6) & 1));
        this.roomTemp = (payload[5] & 0xff) / 2.0;
        this.thermostatTemp = (payload[6] & 0xff) / 2.0;
        this.autoMode = (byte)(payload[7] & 15) != 0;
        this.loopMode = LoopMode.fromValue((byte) (((payload[7] >> 4)) - 1));
        this.sensorControl = SensorControl.fromValue(payload[8]);
        this.osv = payload[9];
        this.dif = payload[10];
        this.svh = payload[11];
        this.svl = payload[12];
        double tempAdj = (((payload[13] << 8) + payload[14]) / 2.0);
        if (tempAdj > 32767) {
            tempAdj = (32767 - tempAdj);
        }
        this.roomTempAdjustment = tempAdj;

        this.antiFreezing = AntiFreezing.fromValue(payload[15]);
        this.powerOnMemory = PowerOnMemory.fromValue(payload[16]);
        this.fac = payload[17];
        this.externalTemp = (payload[18] & 255) / 2.0;
    }

    public boolean getRemoteLock() {
        return remoteLock;
    }

    public boolean getPower() {
        return power;
    }

    public boolean getActive() {
        return active;
    }

    public boolean getManualTemp() {
        return manualTemp;
    }

    public double getRoomTemp() {
        return roomTemp;
    }

    public double getThermostatTemp() {
        return thermostatTemp;
    }

    public boolean getAutoMode() {
        return autoMode;
    }

    /**
     * loopMode refers to index in [ "12345,67", "123456,7", "1234567" ] E.g.
     * loop_mode = 0 ("12345,67") means Saturday and Sunday follow the "weekend"
     * schedule loop_mode = 2 ("1234567") means every day (including Saturday and
     * Sunday) follows the "weekday" schedule
     * 
     * @return loopMode
     */
    public LoopMode getLoopMode() {
        return loopMode;
    }

    /**
     * Sensor control option 0:internal sensor
     * 
     * 1:external sensor
     * 
     * 2:internal control temperature,external limit temperature
     * 
     * default: 0:internal sensor
     * 
     * @return Sensor control enum
     */
    public SensorControl getSensorControl() {
        return sensorControl;
    }

    /**
     * Limit temperature value of external sensor
     * 
     * values: 5-99ºC
     * 
     * default: 42ºC
     * 
     * @return osv 
     */

    public short getOsv() {
        return osv;
    }

    /**
     * Return difference of limit temperature value of external sensor
     * 
     * 
     * values: 1-9ºC
     * 
     * default: 2ºC
     * 
     * @return the difference in Celsius
     */
    public short getDif() {
        return dif;
    }

    /**
     * Set upper limit temperature value
     * 
     * 
     * values: 5-99ºC
     * 
     * default: 35ºC
     * 
     * @return upper limit in Celsius
     */
    public short getSvh() {
        return svh;
    }

    /**
     * Set lower limit temperature value
     * 
     * values: 5-99ºC
     * 
     * default: 5ºC
     * 
     * @return lower limit in Celsius
     */
    public short getSvl() {
        return svl;
    }

    /**
     * Measure temperature
     * 
     * Measure temperature,check and calibration
     * 
     * 0.1ºC precision Calibration (actual temperature)
     * 
     * @return adjustment in Celsius
     */
    public double getRoomTempAdjustment() {
        return roomTempAdjustment;
    }

    /**
     * Anti-freezing function
     * 
     * 00:anti-freezing function shut down
     * 
     * 01:anti-freezing function open
     * 
     * 00:anti-freezing function shut down
     * 
     * @return anti-freezing enum
     */
    public AntiFreezing getAntiFreezing() {
        return antiFreezing;
    }

    /**
     * Power on memory
     * 
     * 00:Power on no need memory
     * 
     * 01:Power on need memory
     * 
     * default: 00:Power on no need memory
     * 
     * @return PowerOnMemory enum
     */
    public PowerOnMemory getPowerOnMemory() {
        return powerOnMemory;
    }

    /**
     * NOT SURE Factory default
     * 
     * 08:just display,no other meaning
     * 
     * 00:Restore factory default
     * 
     * default: 08
     * 
     * @return Factory default ?
     */
    public short getFac() {
        return fac;
    }

    public double getExternalTemp() {
        return externalTemp;
    }

    @Override
    public String toString() {
        return "BaseStatusInfo [\nremote lock=" + remoteLock + ",\n power=" + power + ",\n active=" + active
                + ",\n manual temp=" + manualTemp + ",\n room temp=" + roomTemp + ",\n thermostat temp="
                + thermostatTemp + ",\n auto_mode=" + autoMode + ",\n loop_mode=" + loopMode + ",\n sensor="
                + sensorControl + ",\n osv=" + osv + ",\n dif=" + dif + ",\n svh=" + svh + ",\n svl=" + svl
                + ",\n room_temp_adj=" + roomTempAdjustment + ",\n anti freeze=" + antiFreezing + ",\n powerOnMemory="
                + powerOnMemory + ",\n fac?=" + fac + ",\n external temp=" + externalTemp + "]";
    }

    protected static byte boolToByte(boolean v) {
        return (byte) (v ? 1 : 0);
    }

    protected static boolean byteToBool(byte v) {
        return v == (byte) 1;
    }
}
