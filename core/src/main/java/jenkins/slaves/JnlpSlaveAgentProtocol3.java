package jenkins.slaves;

import hudson.AbortException;
import hudson.Extension;
import hudson.TcpSlaveAgentListener;
import hudson.Util;
import hudson.remoting.Channel;
import hudson.remoting.ChannelBuilder;
import hudson.slaves.SlaveComputer;
import jenkins.AgentProtocol;
import jenkins.model.Jenkins;
import org.jenkinsci.remoting.engine.Jnlp3Ciphers;
import org.jenkinsci.remoting.engine.JnlpProtocol;
import org.jenkinsci.remoting.engine.JnlpProtocol3;
import org.jenkinsci.remoting.engine.MyOutputStream;
import org.jenkinsci.remoting.nio.NioChannelHub;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.inject.Inject;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;

/**
 * Comment here.
 */
@Extension
public class JnlpSlaveAgentProtocol3 extends AgentProtocol {
    @Inject
    NioChannelSelector hub;

    @Override
    public String getName() {
        return "JNLP3-connect";
    }

    @Override
    public void handle(Socket socket) throws IOException, InterruptedException {
        new Handler(hub.getHub(), socket).run();
    }

    static class Handler extends JnlpSlaveHandshake {

        public Handler(NioChannelHub hub, Socket socket) throws IOException {
            super(hub,socket,
                    new DataInputStream(socket.getInputStream()),
                    new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), "UTF-8")), true));
        }

        protected void run() throws IOException, InterruptedException {
            request.load(new ByteArrayInputStream(in.readUTF().getBytes("UTF-8")));
            String nodeName = request.getProperty(JnlpProtocol3.SLAVE_NAME_KEY);
            String encryptedChallenge = request.getProperty(JnlpProtocol3.CHALLENGE_KEY);
            IvParameterSpec spec = new IvParameterSpec(request.getProperty(JnlpProtocol3.SPEC_KEY).getBytes("ISO-8859-1"));
            String cookie = request.getProperty(JnlpProtocol3.COOKIE_KEY);

            SlaveComputer computer = (SlaveComputer) Jenkins.getInstance().getComputer(nodeName);
            if(computer == null) {
                error("Slave trying to register for invalid node: " + nodeName);
                return;
            }
            String secretKey = computer.getJnlpMac();

            Jnlp3Ciphers ciphers = null;
            try {
                ciphers = Jnlp3Ciphers.createForSlave(nodeName, secretKey, spec);
            } catch (Exception e) {
                error("Unable to create ciphers for node: " + nodeName);
                return;
            }

            LOGGER.info(request.getProperty(JnlpProtocol3.SPEC_KEY));
            LOGGER.info("" + request.getProperty(JnlpProtocol3.SPEC_KEY).getBytes("ISO-8859-1").length);
            String challenge = null;
            try {
                challenge = new String(ciphers.getDecryptCipher().doFinal(encryptedChallenge.getBytes("ISO-8859-1")), "UTF-8");
            } catch (Exception e) {
                throw new IOException("Unable to decrypt challenge", e);
            }
            LOGGER.info(challenge);
            if (!challenge.startsWith(JnlpProtocol3.CHALLENGE_PREFIX)) {
                error("Received invalid challenge");
                return;
            }

            // At this point the slave looks legit, check if we think they are already connected.
            Channel oldChannel = computer.getChannel();
            if(oldChannel != null) {
                if (cookie != null && cookie.equals(oldChannel.getProperty(COOKIE_NAME))) {
                    // we think we are currently connected, but this request proves that it's from the party
                    // we are supposed to be communicating to. so let the current one get disconnected
                    LOGGER.info("Disconnecting " + nodeName + " as we are reconnected from the current peer");
                    try {
                        computer.disconnect(new TcpSlaveAgentListener.ConnectionFromCurrentPeer()).get(15, TimeUnit.SECONDS);
                    } catch (ExecutionException e) {
                        throw new IOException("Failed to disconnect the current client",e);
                    } catch (TimeoutException e) {
                        throw new IOException("Failed to disconnect the current client",e);
                    }
                } else {
                    error(nodeName + " is already connected to this master. Rejecting this connection.");
                    return;
                }
            }

            // Send challenge response.
            String challengeReverse = new StringBuilder(challenge.substring(JnlpProtocol3.CHALLENGE_PREFIX.length())).reverse().toString();
            String challengeResponse = JnlpProtocol3.CHALLENGE_PREFIX + challengeReverse;
            LOGGER.info(challengeResponse);
            String encryptedChallengeResponse = null;
            try {
                encryptedChallengeResponse = new String(ciphers.getEncryptCipher().doFinal(challengeResponse.getBytes("UTF-8")), "ISO-8859-1");
            } catch (Exception e) {
                throw new IOException("Error encrypting response", e);
            }
            LOGGER.info(encryptedChallengeResponse);
            LOGGER.info("" + encryptedChallengeResponse.length());
            LOGGER.info("" + encryptedChallengeResponse.getBytes("UTF-8").length);

            String newCookie = generateCookie();
            out.println(encryptedChallengeResponse.getBytes("UTF-8").length);
            out.print(encryptedChallengeResponse);
            out.flush();

            String challengeVerificationMessage = in.readUTF();
            if (!challengeVerificationMessage.equals(JnlpProtocol.GREETING_SUCCESS)) {
                error("Slave did not accept our challenge response");
                return;
            }

            out.println(newCookie);

            try {
                ciphers.getEncryptCipher().init(Cipher.ENCRYPT_MODE, ciphers.getSecretKey(), ciphers.getIvParameterSpec());
            } catch (Exception e) {
                e.printStackTrace();
            }
            Channel establishedChannel = jnlpConnect(computer, ciphers);
            establishedChannel.setProperty(COOKIE_NAME, newCookie);
        }

        protected Channel jnlpConnect(SlaveComputer computer, Jnlp3Ciphers ciphers) throws InterruptedException, IOException {
            final String nodeName = computer.getName();
            final OutputStream log = computer.openLogFile();
            PrintWriter logw = new PrintWriter(log,true);
            logw.println("JNLP agent connected from "+ socket.getInetAddress());

            try {
                ChannelBuilder cb = createChannelBuilder(nodeName);

                computer.setChannel(cb.withHeaderStream(log).build(
                                new CipherInputStream(new BufferedInputStream(socket.getInputStream()), ciphers.getDecryptCipher()),
                                new MyOutputStream(new BufferedOutputStream(socket.getOutputStream()), ciphers.getEncryptCipher(), ciphers.getSecretKey(), ciphers.getIvParameterSpec())
                        ), log,
                        new Channel.Listener() {
                            @Override
                            public void onClosed(Channel channel, IOException cause) {
                                if(cause!=null)
                                    LOGGER.log(Level.WARNING, Thread.currentThread().getName()+" for + " + nodeName + " terminated",cause);
                                try {
                                    socket.close();
                                } catch (IOException e) {
                                    // ignore
                                }
                            }
                        });
                return computer.getChannel();
            } catch (AbortException e) {
                logw.println(e.getMessage());
                logw.println("Failed to establish the connection with the slave");
                throw e;
            } catch (IOException e) {
                logw.println("Failed to establish the connection with the slave " + nodeName);
                e.printStackTrace(logw);
                throw e;
            }
        }

        private String generateCookie() {
            byte[] cookie = new byte[32];
            new SecureRandom().nextBytes(cookie);
            return Util.toHexString(cookie);
        }
    }

    //static final String SPEC_KEY = "Spec";
    //static final String CHALLENGE_KEY = "Challenge";
    //static final String SLAVE_NAME_KEY = "Node-Name";
    //static final String COOKIE_KEY = "Cookie";
    //static final String CHALLENGE_PREFIX = "JNLP3";
    static final String COOKIE_NAME = JnlpSlaveAgentProtocol3.class.getName()+".cookie";
}
