package dtls;
import java.io.Serializable;

public class SSPPacket implements Serializable {

    /**
     * 
     *
     */

    private static final long serialVersionUID = 1L;

    private byte[] version = { 0x01, 0x01 };

    private byte contentType = 0x01;

    private byte payloadType = 0x01;

    private int payloadSize;

    private byte[] ciphered;

    public SSPPacket(byte[] payload, int payloadSize) {
        this.payloadSize = payloadSize;
        this.ciphered = payload;
    }

    public byte[] getVersion() {

        return this.version;

    }

    public byte getContentType(){
        return contentType;
    }


    public byte getPayloadType(){
        return payloadType;
    } 


    public int getPayloadSize(){
        return payloadSize;
    }

    public byte[] getPayload(){
        return ciphered;
    }
}