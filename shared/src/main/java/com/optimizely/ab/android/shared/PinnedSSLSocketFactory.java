package com.optimizely.ab.android.shared;


import android.content.Context;
import android.content.res.AssetManager;
import android.util.Log;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;


/**
 * Factory for creating pinned SSLSocketFactory instances, that only accept a trusted CA.
 */
public class PinnedSSLSocketFactory {

    private Logger logger = LoggerFactory.getLogger(PinnedSSLSocketFactory.class);

    public enum HostType {
        LOGX,
        CDN,
        API
    }

    private static final String EVENT_CERT_FILENAME = "DigiCertHighAssuranceEVRootCA.crt";
    private static final String DATAFILE_CERT_FILENAME = "DigiCertGlobalRootCA.crt";
    private static final String REST_API_CERT_FILENAME = "AmazonRootCA1.crt";

    public SSLSocketFactory getPinnedSslSocket(Context context, HostType hostType) {
        InputStream certificate = null;
        switch (hostType){
            case LOGX:
                Log.d("harika", "im in logx host");
                certificate = getCert(context, EVENT_CERT_FILENAME);
                Log.d("harika", "returning logx host");
                break;
            case CDN:
                Log.d("harika", "im in cdn host");
                certificate = getCert(context, DATAFILE_CERT_FILENAME);
                 Log.d("harika", "returning cdn host");
                break;
            case API:
                certificate = getCert(context, REST_API_CERT_FILENAME);
                break;
            default:
                break;
        }

        // Return null, if no certificate exists
        if (certificate != null) {
             Log.d("harika", "returning valid socket factory");
            return getSSLSocketFactory(certificate);
        } else {
            logger.error("Failed to create sslsocketfactory for the certificate");
            Log.d("harika", "no host");
            return null;
        }
    }

    private InputStream getCert(Context context, String certFilename) {
        InputStream certificate = null;
        try {
             Log.d("harika", "opening cert file");
            certificate = context.getAssets().open(certFilename);
        } catch (IOException e) {
            e.printStackTrace();
        }
         Log.d("harika", "returning cert file");
        return certificate;
    }

    /**
     * Creates a new SSLSocketFactory instance
     *
     * @param input InputStream with CA certificate.
     * @return The new SSLSocketFactory instance.
     *
     */
    private SSLSocketFactory getSSLSocketFactory(InputStream input) {
        try {

            // Load trusted CAs from the input stream - Could be from a resource or ByteArrayInputStream
            Log.d("harika", "loading certificate...");
            Certificate ca;
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            ca = cf.generateCertificate(input);
            input.close();
            Log.d("harika", "loaded certificate");

            // Create a keystore containing trusted certificates
            Log.d("harika", "creating keystore");
            KeyStore keyStore;
            String keyStoreType = KeyStore.getDefaultType();
            keyStore = KeyStore.getInstance(keyStoreType);
            keyStore.load(null, null);
            keyStore.setCertificateEntry("ca", ca);
            Log.d("harika", "created key store");

            // Create a custom TrustManager from the trusted CAs in the keystore
            Log.d("harika", "creating trust managers");
            TrustManager[] trustManagers;
            String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
            tmf.init(keyStore);
            trustManagers = tmf.getTrustManagers();
            Log.d("harika", "created trust managers");

            // Create a SSLContext from the TrustManager
            Log.d("harika", "creating ssl context");
            SSLContext mSslContext = SSLContext.getInstance("TLS");
            mSslContext.init(null, trustManagers, null);

             Log.d("harika", "created sslcontext and returning socket factory");
            // Return a SocketFactory object for the SSLContext
            return mSslContext.getSocketFactory();
        } catch (CertificateException e) {
            logger.error("Failed to create certificate factory", e);
        } catch (KeyStoreException e) {
            logger.error("Failed to get key store instance", e);
        } catch (KeyManagementException e) {
            logger.error("Failed to initialize SSL Context", e);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
}
