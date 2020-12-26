package dtls;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class DTLSImpl {
	private SSLContext sslCont;
	private SSLEngine sslEng;
	private SSLSocket sock;
	private SSLServerSocket sock_serv;

	public DTLSImpl(String protocolVersion, String peerType, String authType, String[] cipherSuites, String ksName,
			String ksPass, InetSocketAddress addr) throws UnknownHostException, IOException {
		sslCont = getSSLContext(protocolVersion, ksName, ksPass);
		sslEng = sslCont.createSSLEngine();
		setDTLSConfigurations(protocolVersion, peerType, authType, cipherSuites);
		createSocket(peerType, addr);
	}

	private void createSocket(String peerType, InetSocketAddress addr) throws IOException, UnknownHostException {
		if (peerType == "SERVER") {
			SSLServerSocketFactory sf = sslCont.getServerSocketFactory();
			sock_serv = (SSLServerSocket) sf.createServerSocket(addr.getPort());
		} else {
			SSLSocketFactory sf = sslCont.getSocketFactory();
			sock = (SSLSocket) sf.createSocket(addr.getHostName(), addr.getPort());
		}
	}

	private void setDTLSConfigurations(String protocolVersion, String peerType, String authType,
			String[] cipherSuites) {
		String[] protocols = { protocolVersion };
		sslEng.setEnabledProtocols(protocols);
		sslEng.setEnabledCipherSuites(cipherSuites);

		if (authType.equals("PROXY") && peerType.equals("PROXY")) { // Client only authentication
			sslEng.setUseClientMode(false);
			sslEng.setWantClientAuth(true);
		} else if (authType.equals("PROXY") && peerType.equals("SERVER")) // Client only authentication
			sslEng.setUseClientMode(true);
		else if (authType.equals("SERVER") && peerType.equals("SERVER")) { // Server only authentication
			sslEng.setUseClientMode(false);
			sslEng.setWantClientAuth(true);
		} else if (authType.equals("SERVER") && peerType.equals("PROXY")) // Server only authentication
			sslEng.setUseClientMode(true);
		// Mutual needs two truststores
	}

	public SSLSocket getSocket() {
		return sock;
	}

	public SSLServerSocket getServSocket() {
		return sock_serv;
	}

	private SSLContext getSSLContext(String protocol, String ksName, String ksPass) {
		SSLContext res = null;
		try {
			if (ksName != null || ksPass != null) {
				KeyStore ks = KeyStore.getInstance("JKS");
				ks.load(new FileInputStream(ksName), ksPass.toCharArray());
				KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
				kmf.init(ks, ksPass.toCharArray());
				res = SSLContext.getInstance(protocol);
				// TODO: Most likely will have to code trustedstoremanager
				res.init(kmf.getKeyManagers(), null, null);
			} else {
				res = SSLContext.getInstance(protocol);
				res.init(null,null,null);
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return res;
	}
}
