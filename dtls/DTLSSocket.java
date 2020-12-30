package dtls;

/*
 * Created by
 * Joao Peres n 48320, Luis Silva 54449 
 */

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;

public class DTLSSocket {
	private SSLContext sslCont;
	private SSLEngine sslEng;
	private DatagramSocket dSocket;
	private SocketAddress otherAddr;
	private static Exception clientException = null;
	private static Exception serverException = null;
	private String selfType;
	// CONSTANTS
	private static int SOCKET_TIMEOUT = 2 * 10000; // 20 seconds
	private static int MAX_HANDSHAKE_LOOPS = 60;
	private static int MAX_APP_READ_LOOPS = 60;
	private static int BUFFER_SIZE = 5 * 1024;
	private static int MAXIMUM_PACKET_SIZE = 5 * 1024;

	public DTLSSocket(String protocolVersion, String sideType, String authType, String[] cipherSuites, String ksName,
			String ksPass, String tsName, String tsPass, DatagramSocket sock, SocketAddress otherSideAddr)
			throws Exception {
		dSocket = sock;
		dSocket.setSoTimeout(SOCKET_TIMEOUT);
		selfType = sideType;
		otherAddr = otherSideAddr;
		sslCont = getSSLContext(protocolVersion, ksName, ksPass, tsName, tsPass);
		sslEng = sslCont.createSSLEngine();
		setDTLSConfigurations(protocolVersion, authType, cipherSuites);
		handshake();
	}

	private SSLContext getSSLContext(String protocol, String ksName, String ksPass, String tsName, String tsPass) {
		SSLContext res = null;
		try {
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(new FileInputStream(ksName), ksPass.toCharArray());
			KeyStore ksTrust = KeyStore.getInstance("JKS");
			ksTrust.load(new FileInputStream(tsName), tsPass.toCharArray());

			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(ks, ksPass.toCharArray());
			TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
			tmf.init(ksTrust);
			
			res = SSLContext.getInstance(protocol);
			res.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return res;
	}

	private void setDTLSConfigurations(String protocolVersion, String authType, String[] cipherSuites) {
		String[] protocols = { protocolVersion };
		sslEng.setEnabledProtocols(protocols);
		sslEng.setEnabledCipherSuites(cipherSuites);

		if (authType.equals("PROXY") && selfType.equals("PROXY")) { // Client only authentication
			sslEng.setUseClientMode(false);
			sslEng.setWantClientAuth(false);
		} else if (authType.equals("PROXY") && selfType.equals("SERVER")) {
			sslEng.setUseClientMode(true);
			sslEng.setWantClientAuth(true);
		} else if (authType.equals("SERVER") && selfType.equals("SERVER")) { // Server only authentication
			sslEng.setUseClientMode(false);
			sslEng.setWantClientAuth(false);
		} else if (authType.equals("SERVER") && selfType.equals("PROXY")) { // Server only authentication
			sslEng.setUseClientMode(true);
			sslEng.setWantClientAuth(true);
		} else if (authType.equals("MUTUAL") && selfType.equals("PROXY")) {
			sslEng.setUseClientMode(true);
			sslEng.setWantClientAuth(true);
		} else {
			sslEng.setUseClientMode(false);
			sslEng.setWantClientAuth(true);
		}

		SSLParameters params = sslEng.getSSLParameters();
		params.setMaximumPacketSize(MAXIMUM_PACKET_SIZE);
	}

	void handshake() throws Exception {
		boolean endLoops = false;
		int loops = MAX_HANDSHAKE_LOOPS;
		sslEng.beginHandshake();
		System.out.println("SERVER:Handshake has STARTED");
		while (!endLoops && (serverException == null) && (clientException == null)) {

			if (--loops < 0) {
				throw new RuntimeException("Too much loops to produce handshake packets");
			}

			HandshakeStatus hs = sslEng.getHandshakeStatus();
			if (hs == SSLEngineResult.HandshakeStatus.NEED_UNWRAP
					|| hs == SSLEngineResult.HandshakeStatus.NEED_UNWRAP_AGAIN) {
				//System.out.println(selfType + ":" + "Received DTLS records, handshake status is " + hs);
				ByteBuffer iNet;
				ByteBuffer iApp;
				if (hs == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
					byte[] buf = new byte[BUFFER_SIZE];
					DatagramPacket packet = new DatagramPacket(buf, buf.length);
					try {
						dSocket.receive(packet);
					} catch (SocketTimeoutException ste) {
						// System.out.println(selfType+":"+"TIMEOUT occured when expecting dtls
						// record");
						List<DatagramPacket> packets = new ArrayList<>();
						boolean finished = onReceiveTimeout(packets);

						// System.out.println(selfType+":"+"Reproduced, "+packets.size()+" packets");
						for (DatagramPacket p : packets) {
							dSocket.send(p);
						}

						if (finished) {
							// System.out.println(selfType + ":Handshake status is FINISHED after calling
							// onReceiveTimeout()");
							endLoops = true;
						}

						// System.out.println(selfType+":New handshake status is " +
						// sslEng.getHandshakeStatus());
						continue;
					}

					iNet = ByteBuffer.wrap(buf, 0, packet.getLength());
					iApp = ByteBuffer.allocate(BUFFER_SIZE);
				} else {
					iNet = ByteBuffer.allocate(0);
					iApp = ByteBuffer.allocate(BUFFER_SIZE);
				}

				SSLEngineResult r = sslEng.unwrap(iNet, iApp);
				iNet.flip();
				SSLEngineResult.Status rs = r.getStatus();
				hs = r.getHandshakeStatus();
				if (rs == SSLEngineResult.Status.OK) {
					// Do nothing
				} else if (rs == SSLEngineResult.Status.BUFFER_OVERFLOW) {
					// System.out.println(selfType+":BUFFER_OVERFLOW, handshake status is " + hs);
					// the client maximum fragment size config does not work?
					throw new Exception("Buffer overflow: " + "incorrect client maximum fragment size");
				} else if (rs == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
					// System.out.println(selfType+":BUFFER_UNDERFLOW, handshake status is " + hs);
					// bad packet, or the client maximum fragment size
					// config does not work?
					if (hs != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
						//System.out.println("here");
						// throw new Exception("Buffer underflow: " + "incorrect client maximum fragment
						// size");
					} // otherwise, ignore this packet
				} else if (rs == SSLEngineResult.Status.CLOSED) {
					throw new Exception("SSL engine closed, handshake status is " + hs);
				} else {
					throw new Exception("Can't reach here, result is " + rs);
				}

				if (hs == SSLEngineResult.HandshakeStatus.FINISHED) {
					// System.out.println(selfType+":Handshake status is FINISHED, finish the
					// loop");
					endLoops = true;
				}
			} else if (hs == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
				List<DatagramPacket> packets = new ArrayList<>();
				boolean finished = produceHandshakePackets(packets);

				// System.out.println(selfType+":Produced " + packets.size() + " packets");
				for (DatagramPacket p : packets) {
					dSocket.send(p);
				}
				if (finished) {
					System.out.println(selfType + ":Handshake status is FINISHED "
							+ "after producing handshake packets, " + "finish the loop");
					endLoops = true;
				}
			} else if (hs == SSLEngineResult.HandshakeStatus.NEED_TASK) {
				runDelegatedTasks();
			} else if (hs == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
				// System.out.println(selfType+":Handshake status is NOT_HANDSHAKING, finish the
				// loop");
				endLoops = true;
			} else if (hs == SSLEngineResult.HandshakeStatus.FINISHED) {
				throw new Exception(selfType + ":Unexpected status shouldn't return FINISHED");
			} else {
				throw new Exception(selfType + ":Can't reach here, handshake status is " + hs);
			}
		}

		HandshakeStatus hs = sslEng.getHandshakeStatus();
		// System.out.println(selfType+":Handshake finished, status is " + hs);

		if (sslEng.getHandshakeSession() != null) {
			throw new Exception("Handshake finished, but handshake session is not null");
		}

		SSLSession session = sslEng.getSession();
		if (session == null) {
			throw new Exception("Handshake finished, but session is null");
		}
		System.out.println(selfType+":Negotiated protocol is " + session.getProtocol());
		System.out.println(selfType+":Negotiated cipher suite is " + session.getCipherSuite());

		// handshake status should be NOT_HANDSHAKING
		//
		// According to the spec, SSLEngine.getHandshakeStatus() can't
		// return FINISHED.
		if (hs != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
			throw new Exception("Unexpected handshake status " + hs);
		}
	}

	public void send(byte[] frame, int frameLen) throws Exception {
		try {
			SSPPacket packetToSend = new SSPPacket(frame, frameLen);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			ObjectOutputStream oos = new ObjectOutputStream(baos);
			oos.writeObject(packetToSend);
			oos.flush();
			byte[] res = baos.toByteArray();

			// System.out.println("Sending frame: "+ new
			// String(src.array(),StandardCharsets.UTF_8));
			// Note: have not consider the packet loses
			ByteBuffer src = ByteBuffer.wrap(res, 0, res.length);
			ByteBuffer appNet = ByteBuffer.allocate(32768);
			SSLEngineResult r = sslEng.wrap(src, appNet);
			appNet.flip();

			SSLEngineResult.Status rs = r.getStatus();
			if (rs == SSLEngineResult.Status.BUFFER_OVERFLOW) {
				// the client maximum fragment size config does not work?
				throw new Exception("Buffer overflow: " + "incorrect server maximum fragment size");
			} else if (rs == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
				// unlikely
				throw new Exception("Buffer underflow during wraping");
			} else if (rs == SSLEngineResult.Status.CLOSED) {
				throw new Exception("SSLEngine has closed");
			} else if (rs == SSLEngineResult.Status.OK) {
				// OK
			} else {
				throw new Exception("Can't reach here, result is " + rs);
			}

			// SSLEngineResult.Status.OK:
			if (appNet.hasRemaining()) {
				byte[] ba = new byte[appNet.remaining()];
				appNet.get(ba);
				// System.out.println("frame for socket: "+ new
				// String(ba,StandardCharsets.UTF_8));
				DatagramPacket packet = new DatagramPacket(ba, ba.length, otherAddr);
				dSocket.send(packet);
			}

		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	public void receive(DatagramPacket p) throws Exception {
		int loops = MAX_APP_READ_LOOPS;
		while ((serverException == null) && (clientException == null)) {
			if (--loops < 0) {
				throw new RuntimeException("Too much loops to receive application data");
			}
			byte[] buf = new byte[BUFFER_SIZE];
			DatagramPacket packet = new DatagramPacket(buf, buf.length);
			dSocket.receive(packet);
			// System.out.println("Received frame: "+ new
			// String(packet.getData(),StandardCharsets.UTF_8));
			ByteBuffer netBuffer = ByteBuffer.wrap(buf, 0, packet.getLength());
			ByteBuffer recBuffer = ByteBuffer.allocate(BUFFER_SIZE);
			SSLEngineResult rs = sslEng.unwrap(netBuffer, recBuffer);
			recBuffer.flip();
			if (recBuffer.remaining() != 0) {
				//System.out.println("Received application data... " + recBuffer);
				byte[] received = new byte[recBuffer.remaining()];
				recBuffer.get(received);

				// Rebuild object
				ByteArrayInputStream bais = new ByteArrayInputStream(received, 0, received.length);
				ObjectInputStream ois = new ObjectInputStream(bais);
				SSPPacket pack = (SSPPacket) ois.readObject();
				byte[] original = pack.getPayload();
				p.setData(original);
				return;
			}
		}
		return;
	}

	boolean onReceiveTimeout(List<DatagramPacket> packets) throws Exception {
		HandshakeStatus hs = sslEng.getHandshakeStatus();
		// IF its not handshaking longer then no need to create handshake packets
		if (hs == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
			return false;
		} else { // produce lost packets
			return produceHandshakePackets(packets);
		}
	}

	boolean produceHandshakePackets(List<DatagramPacket> packets) throws Exception {
		boolean endLoops = false;
		int loops = MAX_HANDSHAKE_LOOPS / 2;
		while (!endLoops && (serverException == null) && (clientException == null)) {

			if (--loops < 0) {
				throw new RuntimeException("Too much loops to produce handshake packets");
			}

			ByteBuffer oNet = ByteBuffer.allocate(32768);
			ByteBuffer oApp = ByteBuffer.allocate(0);
			SSLEngineResult r = sslEng.wrap(oApp, oNet);
			oNet.flip();

			Status rs = r.getStatus();
			HandshakeStatus hs = r.getHandshakeStatus();
			// System.out.println(selfType + ": " + "Reproducing lost packets.. CURRENT
			// HANDSHAKE STATUS is " + hs);
			if (rs == Status.BUFFER_OVERFLOW) {

				// System.out.println(selfType + ": " + "Buffer overflow- incorrect server
				// maximum frag size");
				throw new Exception("Buffer overflow: incorrect server maximum fragment size (SIDE:" + selfType
						+ ", HandshakeStats:" + hs + ")");

			} else if (rs == Status.BUFFER_UNDERFLOW) {
				// System.out.println(selfType + ": " + "Buffer overflow- incorrect server
				// maximum frag size");
				if (hs != HandshakeStatus.NOT_HANDSHAKING) {
					throw new Exception("Buffer underflow: incorrect server maximum fragment size (SIDE:" + selfType
							+ ", HandshakeStats:" + hs + ")");
				} // otherwise, ignore this packet
			} else if (rs == Status.CLOSED) {
				throw new Exception("SSLEngine has closed");
			} else if (rs == Status.OK) {
				// nothing, continues method
			} else {
				throw new Exception("Invalid Status Code: " + rs);
			}

			// SSLEngineResult.Status.OK:
			if (oNet.hasRemaining()) {
				byte[] ba = new byte[oNet.remaining()];
				oNet.get(ba);
				DatagramPacket packet = new DatagramPacket(ba, ba.length, otherAddr);
				packets.add(packet);
			}

			if (hs == SSLEngineResult.HandshakeStatus.FINISHED) {
				// System.out.println(selfType + ": " + "Reproducing lost packets.. HANDSHAKE
				// STATUS is FINISHED");
				return true;
			}

			boolean endInnerLoop = false;
			HandshakeStatus nhs = hs;
			while (!endInnerLoop) {
				if (nhs == HandshakeStatus.NEED_TASK) {
					runDelegatedTasks();
				} else if (nhs == HandshakeStatus.NEED_UNWRAP || nhs == HandshakeStatus.NEED_UNWRAP_AGAIN
						|| nhs == HandshakeStatus.NOT_HANDSHAKING) {
					endInnerLoop = true;
					endLoops = true;
				} else if (nhs == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
					endInnerLoop = true;
				} else if (nhs == SSLEngineResult.HandshakeStatus.FINISHED) {
					throw new Exception(
							"Unexpected status, SSLEngine.getHandshakeStatus() " + "shouldn't return FINISHED");
				} else {
					throw new Exception("Can't reach here, handshake status is " + nhs);
				}
				nhs = sslEng.getHandshakeStatus();
			}
		}
		return false;
	}

	// Runs needed tasks required by the handshake
	void runDelegatedTasks() throws Exception {
		Runnable runnable;
		while ((runnable = sslEng.getDelegatedTask()) != null) {
			runnable.run();
		}
		HandshakeStatus hs = sslEng.getHandshakeStatus();
		if (hs == HandshakeStatus.NEED_TASK) {
			throw new Exception("handshake shouldn't need additional tasks");
		}
	}
}
