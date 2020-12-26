package server;
/*
 * hjStreamServer.java 
 * Streaming server: streams video frames in UDP packets
 * for clients to play in real time the transmitted movies
 */

import java.io.*;
import java.net.*;
import java.util.Properties;
import java.util.Random;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import dtls.DTLSImpl;

class hjStreamServer {
	
	private static final int ID_LENGTH = 6;
	private static final int NONCE_LENGTH = 4;
	
	static public void main( String []args ) throws Exception {
		if (args.length != 5)
		{
			System.out.println("Erro, usar: SSPStreamServer <movie> <ip-multicast-address> <port> <keystore-name> <keystore-pass>");
			System.out.println("        or: SSPStreamServer <movie> <ip-unicast-address> <port> <keystore-name> <keystore-pass>");
			System.exit(-1);
		}
		InputStream dtlsconf = new FileInputStream("src/main/java/dtls.conf");
		if (dtlsconf == null) {
			System.err.println("dtls.conf file not found!");
			System.exit(1);
		}
		String ksName = null;
		String ksPass = null;
		
		if (args.length == 5) {
			ksName = args[3];
			ksPass = args[4];
		}
		
		
		String peerType = "SERVER";
		
		Properties properties = new Properties();
		properties.load(dtlsconf);
		String protocol = properties.getProperty("TLS-PROT-ENF");
		String authType = properties.getProperty("TLS-AUTH");
		String ciphersuites = properties.getProperty("CIPHERSUITES");
		String[] listCiphers = ciphersuites.split(",");
		
		
		

		int size;
		int count = 0;
		long time;
		DataInputStream g = new DataInputStream( new FileInputStream(args[0]) );
		byte[] buff = new byte[4096];

		InetSocketAddress addr = new InetSocketAddress( args[1], Integer.parseInt(args[2]));
		//DatagramPacket p = new DatagramPacket(buff, buff.length, addr );
		long t0 = System.nanoTime(); // tempo de referencia para este processo
		long q0 = 0;
		
		DTLSImpl imp = null;
		try {
		imp = new DTLSImpl(protocol,peerType, authType, listCiphers, ksName, ksPass, addr);
		} catch(Exception ex) {
			ex.printStackTrace();
		}
		// has to be done internally
		//DatagramSocket inSocket = new DatagramSocket(inSocketAddress);
		SSLServerSocket ss = imp.getServSocket();
		SSLSocket s = (SSLSocket) ss.accept();
		
		OutputStream os = s.getOutputStream();
		
		while ( g.available() > 0 ) {
			buff = new byte[4096];
			Random r = new Random();
			size = g.readShort();
			time = g.readLong();
			if ( count == 0 ) q0 = time; // tempo de referencia no stream
			count += 1;

			g.readFully(buff, 0, size);
			//p.setData(buff,0,size);
			//p.setSocketAddress( addr );
			long t = System.nanoTime();
			Thread.sleep( Math.max(0, ((time-q0)-(t-t0))/1000000) );
			// send packet (with a frame payload)
			// Frames sent in clear (no encryption)
			os.write(buff,0,size);
			System.out.print( "." );
		}
		g.close();
		s.close();
		System.out.println("DONE! all frames sent: "+count);
	}
}