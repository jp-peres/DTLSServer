package server;

/*
 * Created by
 * Joao Peres n 48320, Luis Silva n 54449 
 */

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Random;

import dtls.DTLSSocket;

class DTLSStreamServer {
	
	private static final int ID_LENGTH = 6;
	private static final int NONCE_LENGTH = 4;
	
	static public void main( String []args ) throws Exception {
		if (args.length != 6)
		{
			System.out.println("Erro, usar: DTLSStreamServer <proxy-ip:port> <server-ip:port> <keystore-name> <keystore-pass> <truststore-name> <truststore-pass>");
			System.exit(-1);
		}
		InputStream dtlsconf = null;
		try {
			dtlsconf = new FileInputStream("dtls.conf");
		} 
		catch(Exception ex) {
			System.err.println("dtls.conf file not found!");
			System.exit(1);
		}
		SocketAddress proxyAddr = parseSocketAddress(args[0]);
		SocketAddress serverAddr = parseSocketAddress(args[1]);
		
		Map<String, String> accounts = new HashMap<String, String>();
		accounts.put("48320", "43f3379a50140fe8584199603ab30e5d2170e3ba3c7d3e37f8ce9936d0190df1");
		accounts.put("54449", "82f20a16898eae335cd221dd5c320e5d608580e8fba48ab08a8f327d4a34df63");
		
		String ksName = args[2];
		String ksPass = args[3];
		String tsName = args[4];
		String tsPass = args[5];
		
		String sideType = "SERVER";
		//TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
		Properties properties = new Properties();
		properties.load(dtlsconf);
		String protocol = properties.getProperty("TLS-PROT-ENF");
		String authType = properties.getProperty("TLS-AUTH");
		String ciphersuites = properties.getProperty("CIPHERSUITES");
		String[] listCiphers = ciphersuites.split(",");
		
		int size;
		int count = 0;
		long time;
		byte[] buff = new byte[4096];
		
		long t0 = System.nanoTime(); // tempo de referencia para este processo
		long q0 = 0;
		
		// has to be done internally
		DatagramSocket serverSock = new DatagramSocket(serverAddr);
		
		DTLSSocket imp = null;
		try {
			imp = new DTLSSocket(protocol,sideType, authType, listCiphers, ksName, ksPass, tsName, tsPass, serverSock, proxyAddr);
		} catch(Exception ex) {
			ex.printStackTrace();
		}
		
		String movie = imp.receiveAuthProxy(accounts);
		DataInputStream g = new DataInputStream( new FileInputStream(movie) );
		
		while ( g.available() > 0 ) {
			buff = new byte[4096];
			Random r = new Random();
			size = g.readShort();
			time = g.readLong();
			if ( count == 0 ) q0 = time; // tempo de referencia no stream
			count += 1;

			g.readFully(buff, 0, size);
			long t = System.nanoTime();
			Thread.sleep( Math.max(0, ((time-q0)-(t-t0))/1000000) );

			// send buffer
			imp.send(buff,size);
			System.out.print( "." );
		}
		g.close();
		serverSock.close();
		System.out.println("DONE! all frames sent: "+count);
	}
	
	private static InetSocketAddress parseSocketAddress(String socketAddress) {
		String[] split = socketAddress.split(":");
		String host = split[0];
		int port = Integer.parseInt(split[1]);
		return new InetSocketAddress(host, port);
	}
}