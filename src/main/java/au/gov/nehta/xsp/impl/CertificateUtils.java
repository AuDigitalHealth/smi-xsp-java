package au.gov.nehta.xsp.impl;

import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import javax.crypto.Cipher;

import au.gov.nehta.xsp.XspException;

/**
 * A collection of utility functions for X.509 certificates.
 */
public final class CertificateUtils {

    static {
        try {
            checkJCEpolicyIsUnlimited();
        } catch (XspException e) {
            System.err.println("[WARNING] " + e.getMessage());
        }
    }

    /**
     * Returns the distinguished name of a certificate's subject.
     *
     * @param certificate The {@code X509Certificate} to get the subject name from.
     * @return The subject name of the {@code X509Certificate}. Or null if the
     * certificate is null or the subject name is not set on the
     * certificate.
     */
    public static String getSubjectName(X509Certificate certificate) {
        if (certificate == null) {
            return null;
        }
        return certificate.getSubjectX500Principal().getName();
    }

    /**
     * Checks that AES-256 and RSA key lengths required by XSP are allowed by the
     * JCE policy on this JVM. On Java 17 and later, unlimited strength is the
     * default.
     *
     * @throws XspException Thrown if the encryption ciphers used by XSP are not supported.
     */
    public static void checkJCEpolicyIsUnlimited() throws XspException {
        try {
            if (Cipher.getMaxAllowedKeyLength("AES") < 256) {
                throw new XspException("JCE policy limits cryptography strength"
                        + ": cannot perform AES-256");
            }
        } catch (NoSuchAlgorithmException e) {
            throw new XspException("AES encryption not supported");
        }

        try {
            if (Cipher.getMaxAllowedKeyLength("RSA") < 1024) {
                throw new XspException("JCE policy limits cryptography strength"
                        + ": cannot perform RSA with key size >= 1024");
            }
        } catch (NoSuchAlgorithmException e) {
            throw new XspException("RSA encryption not supported");
        }
    }

    private CertificateUtils() {
    }

}
