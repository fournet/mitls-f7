/* ------------------------------------------------------------------------ */
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Random;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;

/* ------------------------------------------------------------------------ */
public class JSSE {
	private static byte[] data = new byte[1024 * 1024];
	
	static {
		(new Random()).nextBytes(JSSE.data);
	}

	private static SSLContext sslcontext = null;

	private static class MyKeyManager implements X509KeyManager {
		protected X509KeyManager target;
		
		public MyKeyManager(X509KeyManager target) {
			this.target = target;
		}

		public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
			return target.chooseClientAlias(keyType, issuers, socket);
		}

		public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
			String certname = System.getenv("CERTNAME");

			if (certname == null)
				throw new RuntimeException("CERTNAME not set");
			return String.format("utls pki (%s)", certname);
		}

		public X509Certificate[] getCertificateChain(String alias) {
			return target.getCertificateChain(alias);
		}

		public String[] getClientAliases(String keyType, Principal[] issuers) {
			return target.getClientAliases(keyType, issuers);
		}

		public PrivateKey getPrivateKey(String alias) {
			return target.getPrivateKey(alias);
		}

		public String[] getServerAliases(String keyType, Principal[] issuers) {
			return target.getServerAliases(keyType, issuers);
		}
	}
	
	static {
		try {
			String pki = System.getenv("PKI");
			
			if (pki == null)
				throw new RuntimeException("PKI not set");

			TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			KeyStore ks = KeyStore.getInstance("JKS");
			
			ks.load(new FileInputStream(pki + "/JSK.db"), "123456".toCharArray());
			kmf.init(ks, new char[] {});
			tmf.init(ks);
			
			sslcontext = SSLContext.getInstance("TLSv1.2");
			sslcontext.init(
					new KeyManager[] { new MyKeyManager((X509KeyManager) kmf.getKeyManagers()[0]) },
					tmf.getTrustManagers(), null);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	private static void configureSSLSocket(SSLSocket socket, boolean isserver) {
		String cipher = System.getenv("CIPHERSUITE");

		if (cipher == null)
			throw new RuntimeException("CIPHERSUITE not set");
		socket.setEnabledCipherSuites(new String[] { cipher });
	}
	
	private static SSLServerSocket createServerSocket() throws IOException {
        SSLServerSocketFactory sslserversocketfactory =
                (SSLServerSocketFactory) sslcontext.getServerSocketFactory();
        return (SSLServerSocket) sslserversocketfactory.createServerSocket(5000);
	}
	
	private static class ServerThread extends Thread {
		private SSLServerSocket socket;

		public ServerThread(SSLServerSocket socket) {
			this.socket = socket;
			this.setDaemon(true);
		}

		@Override
		public synchronized void run() {
			try {
				
				SSLSocket sslsocket = (SSLSocket) this.socket.accept();

				JSSE.configureSSLSocket(sslsocket, true);
				InputStream input = sslsocket.getInputStream();
				
				this.socket.close();
				this.socket = null;

				final byte[] buffer = new byte[1024 * 1024];
				
				while (true) {
					if (input.read(buffer) == 0)
						break ;
				}
				sslsocket.close();
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
		}
	}
	
	private static class ClientThread extends Thread {
		private long totalsent  = 0;
		private long totalticks = 0;
		
		@Override
		public synchronized void run() {
			final int blksize = 1024;
			
			try {
				SSLSocketFactory sslsocketfactory = (SSLSocketFactory) sslcontext.getSocketFactory();
				SSLSocket socket = (SSLSocket) sslsocketfactory.createSocket("localhost", 5000);

				JSSE.configureSSLSocket(socket, false);
				
	            OutputStream output = socket.getOutputStream();

	            int sent = 0;
	            int upos = 0;
	            
	            final long t1 = System.nanoTime();
	            
            	while (sent < 64 * 1024 * 1024) {
	            	if (JSSE.data.length - upos < blksize)
	            		upos = 0;
	            	output.write(JSSE.data, upos, blksize);
	            	sent += blksize;
	            	upos += blksize;
	            }
	            output.flush();

	            final long t2 = System.nanoTime();

	            this.totalsent  = sent;
	            this.totalticks = t2 - t1;
	            
	            socket.close();
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
        }

		public long getTotalsent() {
			return this.totalsent;
		}

		public long getTotalticks() {
			return this.totalticks;
		}
	}
	
	static public void main(String[] args) throws Exception {
		ServerThread server = new ServerThread(JSSE.createServerSocket());
		ClientThread client = new ClientThread();

		server.start();
		client.start();
		client.join();
		
		if (client.getTotalticks() > 0) {
			System.out.format("%s: %.2f MiB/s\n",
					System.getenv("CIPHERSUITE"),
						client.getTotalsent()
						/ (((double) client.getTotalticks()) / 1000000000)
						/ (1024 * 1024));
		}
	}
}
