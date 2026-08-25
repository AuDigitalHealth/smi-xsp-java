package au.gov.nehta.xsp.impl.v1;

import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500PrivateCredential;

import org.apache.xml.security.Init;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.EncryptionMethod;
import org.apache.xml.security.encryption.Reference;
import org.apache.xml.security.encryption.ReferenceList;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509SKI;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import au.gov.nehta.common.utils.ArgumentUtils;
import au.gov.nehta.common.utils.DomUtils;
import au.gov.nehta.xsp.KeyMismatchException;
import au.gov.nehta.xsp.XmlEncryptionProfileService;
import au.gov.nehta.xsp.XspException;
import au.gov.nehta.xsp.impl.CertificateUtils;
import au.gov.nehta.xsp.impl.TextUtils;

/**
 * Implementation of XmlEncryptionProfileService interface that supports
 * <em>XML Secured Payload Profile</em>, NEHTA version 1.2 (30 June 2009) and
 * Standards Australia version 2010.
 * <p>
 * Note: "Exception" is caught because the Apache XML Security library throws
 * several NullPointerException and IllegalArgumentException without any error
 * message. At least by catching these and rethrowing them within an
 * XspException, we can provide additional information by explaining the action
 * that led to the exception being thrown.
 */
public class XmlEncryptionProfileServiceImpl implements XmlEncryptionProfileService {

    static {
        /*
         * The Apache XML Security library must be initialised before its first use.
         */
        if (!Init.isInitialized()) {
            Init.init();
        }
    }

    @Override
    public void encrypt(Element elementToAddEncKeysTo,
            Element elementToEncrypt,
            X509Certificate certificate) throws XspException {

        ArgumentUtils.checkNotNull(elementToAddEncKeysTo, "elementToAddEncKeysTo");
        ArgumentUtils.checkNotNull(elementToEncrypt, "elementToEncrypt");
        ArgumentUtils.checkNotNull(certificate, "certificate");

        encrypt(elementToAddEncKeysTo, List.of(elementToEncrypt), generateRandomSessionKey(),
                List.of(certificate));
    }

    @Override
    public void encrypt(Element elementToAddEncKeysTo,
            List<Element> elementsToEncrypt,
            X509Certificate certificate) throws XspException {

        ArgumentUtils.checkNotNull(elementToAddEncKeysTo, "elementToAddEncKeysTo");
        ArgumentUtils.checkNotNull(certificate, "certificate");

        encrypt(elementToAddEncKeysTo, elementsToEncrypt, generateRandomSessionKey(),
                List.of(certificate));
    }

    @Override
    public void encrypt(Element elementToAddEncKeysTo,
            Element elementToEncrypt,
            List<X509Certificate> certificates) throws XspException {

        ArgumentUtils.checkNotNull(elementToAddEncKeysTo, "elementToAddEncKeysTo");
        ArgumentUtils.checkNotNull(elementToEncrypt, "elementToEncrypt");

        encrypt(elementToAddEncKeysTo, List.of(elementToEncrypt), generateRandomSessionKey(),
                certificates);
    }

    @Override
    public void encrypt(Element elementToAddEncKeysTo,
            List<Element> elementsToEncrypt,
            List<X509Certificate> certificates) throws XspException {

        ArgumentUtils.checkNotNull(elementToAddEncKeysTo, "elementToAddEncKeysTo");
        ArgumentUtils.checkNotNullNorEmpty(elementsToEncrypt, "elementsToEncrypt");
        ArgumentUtils.checkNotNullNorEmpty(certificates, "certificates");

        encrypt(elementToAddEncKeysTo, elementsToEncrypt, generateRandomSessionKey(), certificates);
    }

    @Override
    public void encrypt(Element elementToAddEncKeysTo,
            Element elementToEncrypt,
            SecretKey sessionKey,
            X509Certificate certificate) throws XspException {

        ArgumentUtils.checkNotNull(elementToAddEncKeysTo, "elementToAddEncKeysTo");
        ArgumentUtils.checkNotNull(elementToEncrypt, "elementToEncrypt");
        ArgumentUtils.checkNotNull(certificate, "certificate");

        encrypt(elementToAddEncKeysTo, List.of(elementToEncrypt), sessionKey,
                List.of(certificate));
    }

    @Override
    public void encrypt(Element elementToAddEncKeysTo,
            List<Element> elementsToEncrypt,
            SecretKey sessionKey,
            X509Certificate certificate) throws XspException {

        ArgumentUtils.checkNotNull(elementToAddEncKeysTo, "elementToAddEncKeysTo");
        ArgumentUtils.checkNotNullNorEmpty(elementsToEncrypt, "elementsToEncrypt");
        ArgumentUtils.checkNotNull(sessionKey, "sessionKey");
        ArgumentUtils.checkNotNull(certificate, "certificate");

        encrypt(elementToAddEncKeysTo, elementsToEncrypt, sessionKey, List.of(certificate));
    }

    @Override
    public void encrypt(Element elementToAddEncKeysTo,
            Element elementToEncrypt,
            SecretKey sessionKey,
            List<X509Certificate> certificates) throws XspException {

        ArgumentUtils.checkNotNull(elementToAddEncKeysTo, "elementToAddEncKeysTo");
        ArgumentUtils.checkNotNull(elementToEncrypt, "elementToEncrypt");
        ArgumentUtils.checkNotNull(sessionKey, "sessionKey");
        ArgumentUtils.checkNotNullNorEmpty(certificates, "certificates");

        encrypt(elementToAddEncKeysTo, List.of(elementToEncrypt), sessionKey, certificates);
    }

    @Override
    public void encrypt(Element elementToAddEncKeysTo,
            List<Element> elementsToEncrypt,
            SecretKey sessionKey,
            List<X509Certificate> certificates) throws XspException {

        ArgumentUtils.checkNotNull(elementToAddEncKeysTo, "elementToAddEncKeysTo");
        ArgumentUtils.checkNotNullNorEmpty(elementsToEncrypt, "elementsToEncrypt");
        ArgumentUtils.checkNotNull(sessionKey, "sessionKey");
        ArgumentUtils.checkNotNullNorEmpty(certificates, "certificates");

        // Get container document
        Document containerDoc = elementToAddEncKeysTo.getOwnerDocument();

        // Check element to encrypt must be in the same document as the element to
        // add encrypted keys to
        for (Element elementToEncrypt : elementsToEncrypt) {
            if (containerDoc != elementToEncrypt.getOwnerDocument()) {
                String errMsg = "The element to encrypt must belong to the same document as the element to add the EncryptedKeys to.";
                throw new XspException(errMsg);
            }
        }

        List<String> referenceIdList = new ArrayList<>();
        for (Element elementToEncrypt : elementsToEncrypt) {
            // Generate a unique reference identifier.
            // This reference identifier must be unique within the message.
            String referenceId = "_" + UUID.randomUUID().toString();

            // Add the generated reference ID to the list
            referenceIdList.add(referenceId);

            // Encrypt the element using the session key
            Element encryptedDataElem;
            try {
                // Create the cipher with the session key
                XMLCipher dataCipher = XMLCipher.getInstance(XMLCipher.AES_256);
                dataCipher.init(XMLCipher.ENCRYPT_MODE, sessionKey);

                // Encrypt the data using the cipher
                EncryptedData encryptedData = dataCipher.encryptData(containerDoc, elementToEncrypt);

                // Add an 'Id' attribute to the 'encryptedData' object.
                encryptedData.setId(referenceId);

                // Convert the 'encryptedData' object to a DOM Element.
                encryptedDataElem = dataCipher.martial(encryptedData);
            } catch (Exception e) {
                throw new XspException("Couldn't encrypt element, " + TextUtils.getDesc(elementToEncrypt)
                        + ".", e);
            }

            // Replace the original element with the 'encryptedData' element
            Node parentNode = elementToEncrypt.getParentNode();
            if (parentNode == null) {
                throw new XspException("Couldn't retrieve the parent of the element to encrypt, "
                        + TextUtils.getDesc(elementToEncrypt) + ".");
            }
            parentNode.replaceChild(encryptedDataElem, elementToEncrypt);
        }

        // Encrypt the session key with each certificate of the receiver
        for (X509Certificate certificate : certificates) {
            Element encryptedKeyElem = encryptKey(containerDoc, sessionKey, certificate, referenceIdList);

            // Add the encrypted key element
            elementToAddEncKeysTo.appendChild(encryptedKeyElem);
        }
    }

    @Override
    public void decrypt(Element encryptedKeyElem,
            Element encryptedDataElem,
            X500PrivateCredential credential) throws KeyMismatchException, XspException {

        ArgumentUtils.checkNotNull(encryptedKeyElem, "encryptedKeyElem");
        ArgumentUtils.checkNotNull(encryptedDataElem, "encryptedDataElem");
        ArgumentUtils.checkNotNull(credential, "credential");

        decrypt(List.of(encryptedKeyElem), List.of(encryptedDataElem), credential);
    }

    @Override
    public void decrypt(List<Element> encryptedKeyElems,
            Element encryptedDataElem,
            X500PrivateCredential credential) throws KeyMismatchException, XspException {

        ArgumentUtils.checkNotNullNorEmpty(encryptedKeyElems, "encryptedKeyElems");
        ArgumentUtils.checkNotNull(encryptedDataElem, "encryptedDataElem");
        ArgumentUtils.checkNotNull(credential, "credential");

        decrypt(encryptedKeyElems, List.of(encryptedDataElem), credential);
    }

    @Override
    public void decrypt(Element encryptedKeyElem,
            List<Element> encryptedDataElems,
            X500PrivateCredential credential) throws KeyMismatchException, XspException {

        ArgumentUtils.checkNotNull(encryptedKeyElem, "encryptedKeyElem");
        ArgumentUtils.checkNotNullNorEmpty(encryptedDataElems, "encryptedDataElems");
        ArgumentUtils.checkNotNull(credential, "credential");

        decrypt(List.of(encryptedKeyElem), encryptedDataElems, credential);
    }

    @Override
    public void decrypt(List<Element> encryptedKeyElems,
            List<Element> encryptedDataElems,
            X500PrivateCredential credential) throws KeyMismatchException, XspException {

        ArgumentUtils.checkNotNullNorEmpty(encryptedKeyElems, "encryptedKeyElems");
        ArgumentUtils.checkNotNullNorEmpty(encryptedDataElems, "encryptedDataElems");
        ArgumentUtils.checkNotNull(credential, "credential");

        // Get the container document
        Document containerDoc = encryptedKeyElems.get(0).getOwnerDocument();

        // Check 'encryptedKeyElems'
        for (Element encryptedKeyElem : encryptedKeyElems) {
            // Check the tag of the EncryptedKey element
            DomUtils.checkElement(encryptedKeyElem, XmlEncConstants.ENCRYPTED_KEY_TAG,
                    XmlEncConstants.XMLENC_NS);

            // Check EncryptedKey elements belong to the same document
            if (containerDoc != encryptedKeyElem.getOwnerDocument()) {
                String errMsg = "The 'EncryptedKey' elements must belong to the same DOM document.";
                throw new XspException(errMsg);
            }
        }

        // Check 'encryptedDataElems'
        for (Element encryptedDataElem : encryptedDataElems) {
            // Check the tag of the EncryptedData element
            DomUtils.checkElement(encryptedDataElem, XmlEncConstants.ENCRYPTED_DATA_TAG,
                    XmlEncConstants.XMLENC_NS);

            // Check EncryptedData elements belong to the same document
            if (containerDoc != encryptedDataElem.getOwnerDocument()) {
                String errMsg = "The 'EncryptedData' elements must belong to the same DOM document as the 'EncryptedKey' elements.";
                throw new XspException(errMsg);
            }
        }

        // Get the private key and X.509 certificate
        PrivateKey decryptKey = credential.getPrivateKey();
        X509Certificate decryptCert = credential.getCertificate();

        // Loop through 'xenc:EncryptedKey' elements to find one that matches
        // the certificate in the key pair that was passed in.
        EncryptedKey encryptedKey = null;
        for (Element encryptedKeyElem : encryptedKeyElems) {
            EncryptedKey currentEncryptedKey = unmarshalEncryptedKey(encryptedKeyElem);

            // Check if the public key in the certificate passed in was used to
            // create the current 'EncryptedKey'
            if (matchesCertificate(currentEncryptedKey, decryptCert)) {
                encryptedKey = currentEncryptedKey;
                break;
            }
        }

        // Didn't find an 'xenc:EncryptedKey' that matched the certificate key pair
        // that was passed in
        if (encryptedKey == null) {
            throw new KeyMismatchException("The credential ("
                    + TextUtils.getDesc(credential.getCertificate()) + ") wasn't used to encrypt the data.");
        }

        // Create the cipher
        XMLCipher xmlCipher;
        try {
            xmlCipher = XMLCipher.getInstance();
            xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
        } catch (Exception e) {
            throw new XspException("Couldn't create the cipher to decrypt the data.", e);
        }

        // Loop through 'xenc:EncryptedData' elements to decrypt each one.
        for (Element encryptedDataElem : encryptedDataElems) {
            // Load the 'encryptedData' object
            EncryptedData encryptedData;
            try {
                encryptedData = xmlCipher.loadEncryptedData(containerDoc, encryptedDataElem);
            } catch (Exception e) {
                throw new XspException("Couldn't load the 'xenc:EncryptedData' element.", e);
            }

            // Get the encryption method
            EncryptionMethod encryptionMethod = encryptedData.getEncryptionMethod();
            if (encryptionMethod == null) {
                throw new XspException(
                        "The 'xenc:EncryptionMethod' wasn't provided in an 'xenc:EncryptedData' element.");
            }

            // Determine the data encryption algorithm
            String dataEncryptionAlgorithm = encryptionMethod.getAlgorithm();
            if (dataEncryptionAlgorithm == null) {
                throw new XspException(
                        "The data encryption algorithm for an 'xenc:EncryptedData' element wasn't provided.");
            }

            // Decrypt the session key
            Key sessionKey;
            try {
                xmlCipher.init(XMLCipher.DECRYPT_MODE, decryptKey);
                sessionKey = xmlCipher.decryptKey(encryptedKey, dataEncryptionAlgorithm);
            } catch (Exception e) {
                throw new XspException(
                        "Couldn't decrypt the session key with the matching 'EncryptedKey'.", e);
            }

            // Decrypt the data
            try {
                xmlCipher.init(XMLCipher.DECRYPT_MODE, sessionKey);
                xmlCipher.doFinal(containerDoc, encryptedDataElem);
            } catch (Exception e) {
                throw new XspException("Couldn't decrypt the data.", e);
            }
        }
    }

    @Override
    public void decrypt(Element encryptedKeyElem,
            Element encryptedDataElem,
            SecretKey sessionKey)
            throws KeyMismatchException, XspException {

        ArgumentUtils.checkNotNull(encryptedKeyElem, "encryptedKeyElem");
        ArgumentUtils.checkNotNull(encryptedDataElem, "encryptedDataElem");
        ArgumentUtils.checkNotNull(sessionKey, "sessionKey");

        decrypt(List.of(encryptedKeyElem), List.of(encryptedDataElem), sessionKey);
    }

    @Override
    public void decrypt(List<Element> encryptedKeyElems,
            Element encryptedDataElem,
            SecretKey sessionKey)
            throws KeyMismatchException, XspException {

        ArgumentUtils.checkNotNullNorEmpty(encryptedKeyElems, "encryptedKeyElems");
        ArgumentUtils.checkNotNull(encryptedDataElem, "encryptedDataElem");
        ArgumentUtils.checkNotNull(sessionKey, "sessionKey");

        decrypt(encryptedKeyElems, List.of(encryptedDataElem), sessionKey);
    }

    @Override
    public void decrypt(Element encryptedKeyElem,
            List<Element> encryptedDataElems,
            SecretKey sessionKey) throws KeyMismatchException, XspException {

        ArgumentUtils.checkNotNull(encryptedKeyElem, "encryptedKeyElem");
        ArgumentUtils.checkNotNullNorEmpty(encryptedDataElems, "encryptedDataElems");
        ArgumentUtils.checkNotNull(sessionKey, "sessionKey");

        decrypt(List.of(encryptedKeyElem), encryptedDataElems, sessionKey);
    }

    @Override
    public void decrypt(List<Element> encryptedKeyElems,
            List<Element> encryptedDataElems,
            SecretKey sessionKey) throws KeyMismatchException, XspException {

        ArgumentUtils.checkNotNullNorEmpty(encryptedKeyElems, "encryptedKeyElems");
        ArgumentUtils.checkNotNullNorEmpty(encryptedDataElems, "encryptedDataElems");
        ArgumentUtils.checkNotNull(sessionKey, "sessionKey");

        // Get the container document
        Document containerDoc = encryptedKeyElems.get(0).getOwnerDocument();

        // Check 'encryptedKeyElems'
        for (Element encryptedKeyElem : encryptedKeyElems) {
            // Check the tag of the EncryptedKey element
            DomUtils.checkElement(encryptedKeyElem, XmlEncConstants.ENCRYPTED_KEY_TAG,
                    XmlEncConstants.XMLENC_NS);

            // Check EncryptedKey elements belong to the same document
            if (containerDoc != encryptedKeyElem.getOwnerDocument()) {
                String errMsg = "The 'EncryptedKey' elements must belong to the same DOM document.";
                throw new XspException(errMsg);
            }
        }

        // Check 'encryptedDataElems'
        for (Element encryptedDataElem : encryptedDataElems) {
            // Check the tag of the EncryptedData element
            DomUtils.checkElement(encryptedDataElem, XmlEncConstants.ENCRYPTED_DATA_TAG,
                    XmlEncConstants.XMLENC_NS);

            // Check EncryptedData elements belong to the same document
            if (containerDoc != encryptedDataElem.getOwnerDocument()) {
                String errMsg = "The 'EncryptedData' elements must belong to the same DOM document as the 'EncryptedKey' elements.";
                throw new XspException(errMsg);
            }
        }

        // Create the cipher
        XMLCipher xmlCipher;
        try {
            xmlCipher = XMLCipher.getInstance();
            xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
        } catch (Exception e) {
            throw new XspException("Couldn't create the cipher to decrypt the data.", e);
        }

        // Loop through 'xenc:EncryptedData' elements to decrypt each one.
        for (Element encryptedDataElem : encryptedDataElems) {
            // Load the 'encryptedData' object
            EncryptedData encryptedData;
            try {
                encryptedData = xmlCipher.loadEncryptedData(containerDoc, encryptedDataElem);
            } catch (Exception e) {
                throw new XspException("Couldn't load the 'xenc:EncryptedData' element.", e);
            }

            // Get the encryption method
            EncryptionMethod encryptionMethod = encryptedData.getEncryptionMethod();
            if (encryptionMethod == null) {
                throw new XspException(
                        "The 'xenc:EncryptionMethod' wasn't provided in an 'xenc:EncryptedData' element.");
            }

            // Determine the data encryption algorithm
            String dataEncryptionAlgorithm = encryptionMethod.getAlgorithm();
            if (dataEncryptionAlgorithm == null) {
                throw new XspException(
                        "The data encryption algorithm for an 'xenc:EncryptedData' element wasn't provided.");
            }

            // Decrypt the data
            try {
                xmlCipher.init(XMLCipher.DECRYPT_MODE, sessionKey);
                xmlCipher.doFinal(containerDoc, encryptedDataElem);
            } catch (Exception e) {
                throw new XspException("Couldn't decrypt the data.", e);
            }
        }
    }

    @Override
    public Key getSessionKey(List<Element> encryptedKeyElems,
            Element encryptedDataElem,
            X500PrivateCredential credential)
            throws KeyMismatchException, XspException {

        ArgumentUtils.checkNotNullNorEmpty(encryptedKeyElems, "encryptedKeyElems");
        ArgumentUtils.checkNotNull(encryptedDataElem, "encryptedDataElem");
        ArgumentUtils.checkNotNull(credential, "credential");

        // Get the container document
        Document containerDoc = encryptedKeyElems.get(0).getOwnerDocument();

        // Check 'encryptedKeyElems'
        for (Element encryptedKeyElem : encryptedKeyElems) {
            // Check the tag of the EncryptedKey element
            DomUtils.checkElement(encryptedKeyElem, XmlEncConstants.ENCRYPTED_KEY_TAG,
                    XmlEncConstants.XMLENC_NS);

            // Check EncryptedKey elements belong to the same document
            if (containerDoc != encryptedKeyElem.getOwnerDocument()) {
                String errMsg = "The 'EncryptedKey' elements must belong to the same DOM document.";
                throw new XspException(errMsg);
            }
        }

        // Check the tag of the EncryptedData element
        DomUtils.checkElement(encryptedDataElem, XmlEncConstants.ENCRYPTED_DATA_TAG,
                XmlEncConstants.XMLENC_NS);

        // Check EncryptedData elements belong to the same document
        if (containerDoc != encryptedDataElem.getOwnerDocument()) {
            String errMsg = "The 'EncryptedData' elements must belong to the same DOM document as the 'EncryptedKey' elements.";
            throw new XspException(errMsg);
        }

        // Get the private key and X.509 certificate
        PrivateKey decryptKey = credential.getPrivateKey();
        X509Certificate decryptCert = credential.getCertificate();

        // Loop through 'xenc:EncryptedKey' elements to find one that matches
        // the certificate in the key pair that was passed in.
        EncryptedKey encryptedKey = null;
        for (Element encryptedKeyElem : encryptedKeyElems) {
            EncryptedKey currentEncryptedKey = unmarshalEncryptedKey(encryptedKeyElem);

            // Check if the public key in the certificate passed in was used to
            // create the current 'EncryptedKey'
            if (matchesCertificate(currentEncryptedKey, decryptCert)) {
                encryptedKey = currentEncryptedKey;
                break;
            }
        }

        // Didn't find an 'xenc:EncryptedKey' that matched the certificate key pair
        // that was passed in
        if (encryptedKey == null) {
            throw new KeyMismatchException("The credential ("
                    + TextUtils.getDesc(credential.getCertificate()) + ") wasn't used to encrypt the data.");
        }

        // Create the cipher
        XMLCipher xmlCipher;
        try {
            xmlCipher = XMLCipher.getInstance();
            xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
        } catch (Exception e) {
            throw new XspException("Couldn't create the cipher to decrypt the data.", e);
        }

        EncryptedData encryptedData;
        try {
            encryptedData = xmlCipher.loadEncryptedData(containerDoc, encryptedDataElem);
        } catch (Exception e) {
            throw new XspException("Couldn't load the 'xenc:EncryptedData' element.", e);
        }

        // Get the encryption method
        EncryptionMethod encryptionMethod = encryptedData.getEncryptionMethod();
        if (encryptionMethod == null) {
            throw new XspException(
                    "The 'xenc:EncryptionMethod' wasn't provided in an 'xenc:EncryptedData' element.");
        }

        // Determine the data encryption algorithm
        String dataEncryptionAlgorithm = encryptionMethod.getAlgorithm();
        if (dataEncryptionAlgorithm == null) {
            throw new XspException(
                    "The data encryption algorithm for an 'xenc:EncryptedData' element wasn't provided.");
        }

        // Decrypt the session key
        Key sessionKey;
        try {
            xmlCipher.init(XMLCipher.DECRYPT_MODE, decryptKey);
            sessionKey = xmlCipher.decryptKey(encryptedKey, dataEncryptionAlgorithm);
        } catch (Exception e) {
            throw new XspException("Couldn't decrypt the session key with the matching 'EncryptedKey'.",
                    e);
        }

        return sessionKey;
    }

    @Override
    public X509Certificate getEncryptingCertificate(Element encryptedKeyElem,
            KeyStore keyStore)
            throws XspException {

        ArgumentUtils.checkNotNull(encryptedKeyElem, "encryptedKeyElem");
        ArgumentUtils.checkNotNull(keyStore, "keyStore");

        List<X509Certificate> certificates = getEncryptingCertificates(List.of(encryptedKeyElem),
                keyStore);
        if (certificates.isEmpty()) {
            return null;
        }
        return certificates.get(0);
    }

    @Override
    public List<X509Certificate> getEncryptingCertificates(List<Element> encryptedKeyElems,
            KeyStore keyStore) throws XspException {

        ArgumentUtils.checkNotNullNorEmpty(encryptedKeyElems, "encryptedKeyElems");
        ArgumentUtils.checkNotNull(keyStore, "keyStore");

        List<X509Certificate> resultList = new ArrayList<>();
        try {
            for (String currentAlias : Collections.list(keyStore.aliases())) {
                X509Certificate currentCert = (X509Certificate) keyStore.getCertificate(currentAlias);
                if (isEncryptingCertificate(encryptedKeyElems, currentCert)) {
                    resultList.add(currentCert);
                }
            }
        } catch (KeyStoreException e) {
            String errorMsg = "Couldn't retrieve certificates from key store.";
            throw new XspException(errorMsg, e);
        }

        return resultList;
    }

    @Override
    public boolean isEncryptingCertificate(List<Element> encryptedKeyElems,
            X509Certificate certificate) throws XspException {

        ArgumentUtils.checkNotNullNorEmpty(encryptedKeyElems, "encryptedKeyElems");
        ArgumentUtils.checkNotNull(certificate, "certificate");

        for (Element encryptedKeyElem : encryptedKeyElems) {
            // Unmarshal the 'xenc:EncryptedKey' XML element into an EncryptedKey
            // object
            EncryptedKey currentEncryptedKey = unmarshalEncryptedKey(encryptedKeyElem);

            // Find the matching cert for the EncryptedKey in the key store
            if (matchesCertificate(currentEncryptedKey, certificate)) {
                return true;
            }
        }

        return false;
    }

    private Element encryptKey(Document containerDoc,
            SecretKey sessionKey,
            X509Certificate certificate,
            List<String> referenceIdList) throws XspException {

        // Create a cipher used to encrypt the session key
        XMLCipher keyCipher;
        try {
            keyCipher = XMLCipher.getInstance(XMLCipher.RSA_v1dot5);
            keyCipher.init(XMLCipher.WRAP_MODE, certificate.getPublicKey());
        } catch (Exception e) {
            throw new XspException(
                    "Couldn't create a cipher to encrypt the session key with certificate: "
                            + CertificateUtils.getSubjectName(certificate) + ".",
                    e);
        }

        // Create an 'encryptedKey' object
        EncryptedKey encryptedKey;
        try {
            encryptedKey = keyCipher.encryptKey(containerDoc, sessionKey);
        } catch (Exception e) {
            throw new XspException("Couldn't create an 'xenc:EncryptedKey' with certificate: "
                    + CertificateUtils.getSubjectName(certificate) + ".", e);
        }

        // Create a 'keyInfo' object and add it to the 'encryptedKey' object
        KeyInfo keyInfo = new KeyInfo(containerDoc);
        encryptedKey.setKeyInfo(keyInfo);

        // Create an 'x509Data' and add it to the 'keyInfo'
        X509Data x509Data = new X509Data(containerDoc);
        keyInfo.add(x509Data);

        // Add the certificate to the 'x509Data' object
        try {
            x509Data.addSKI(certificate);
        } catch (Exception e) {
            throw new XspException(
                    "Couldn't create the 'SKI' element within the 'X509Data' element for certificate: "
                            + CertificateUtils.getSubjectName(certificate) + ".",
                    e);
        }

        if ((referenceIdList != null) && !referenceIdList.isEmpty()) {
            // Create a 'referenceList' object and add it to the 'encryptedKey'
            // object
            ReferenceList referenceList = keyCipher.createReferenceList(ReferenceList.DATA_REFERENCE);
            encryptedKey.setReferenceList(referenceList);
            for (String referenceId : referenceIdList) {
                Reference dataReference = referenceList.newDataReference("#" + referenceId);
                referenceList.add(dataReference);
            }
        }

        // Convert the 'encryptedKey' object to a DOM Element
        return keyCipher.martial(encryptedKey);
    }

    private SecretKey generateRandomSessionKey() throws XspException {
        // Generate a random session key. Uses AES-256.
        SecretKey sessionKey;
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            sessionKey = keyGenerator.generateKey();
        } catch (Exception e) {
            throw new XspException("Couldn't generate a random session key.", e);
        }
        return sessionKey;
    }

    private EncryptedKey unmarshalEncryptedKey(Element encryptedKeyElem) throws XspException {
        EncryptedKey encryptedKey;
        try {
            XMLCipher xmlCipher = XMLCipher.getInstance();
            xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
            encryptedKey = xmlCipher.loadEncryptedKey(encryptedKeyElem);
        } catch (Exception e) {
            throw new XspException("Couldn't unmarshal an 'EncryptedKey' element.", e);
        }
        return encryptedKey;
    }

    /*
     * Returns true if the public key of a given certificate was used to encrypt
     * the session key in an 'EncryptedKey' element, and false otherwise.
     */
    private static boolean matchesCertificate(EncryptedKey encryptedKey,
            X509Certificate certificate)
            throws XspException {

        assert (encryptedKey != null);
        assert (certificate != null);

        // Get the SKI value of the 'encryptedKey' object
        byte[] encryptedKeySki = getEncryptedKeySki(encryptedKey);

        // Get the SKI value from the certificate
        byte[] certificateSki;
        try {
            certificateSki = XMLX509SKI.getSKIBytesFromCert(certificate);
        } catch (Exception ex) {
            throw new XspException(
                    "Error getting the subject key identifier value from from certificate: "
                            + CertificateUtils.getSubjectName(certificate) + ".",
                    ex);
        }

        // Compare SKI values
        return (Arrays.equals(encryptedKeySki, certificateSki));
    }

    /*
     * Returns the SKI value embedded in the 'EncryptedKey' object. The
     * "Encrypted Container Profile" in the "XML Secured Payload Profile"
     * specification requires that the public key that was used to encrypt the
     * session key is referred to by its SKI value in the KeyInfo of the
     * EncryptedKey element.
     */
    private static byte[] getEncryptedKeySki(EncryptedKey encryptedKey) throws XspException {

        assert (encryptedKey != null);

        // Get the 'keyInfo' from the 'encryptedKey' object
        KeyInfo keyInfo = encryptedKey.getKeyInfo();
        if (keyInfo == null) {
            throw new XspException("An 'EncryptedKey' doesn't have a 'KeyInfo'.");
        }

        // Check there is one 'X509Data' within the 'keyInfo' object
        if (keyInfo.lengthX509Data() == 0) {
            throw new XspException("The 'KeyInfo' in an 'EncryptedKey' doesn't specify an 'X509Data'.");
        }
        if (keyInfo.lengthX509Data() > 1) {
            throw new XspException("The 'KeyInfo' in an 'EncryptedKey' specifies multiple 'X509Data'.");
        }

        // Get the 'x509Data' from the 'keyInfo' object
        X509Data x509Data;
        try {
            x509Data = keyInfo.itemX509Data(0);
        } catch (Exception ex) {
            throw new XspException(
                    "Couldn't retrieve the 'X509Data' from the 'KeyInfo' in an 'EncryptedKey'. "
                            + ex.getMessage(),
                    ex);
        }

        // Check there is a 'X509SKI' within the 'x509Data' object
        if (x509Data.lengthSKI() == 0) {
            throw new XspException("The 'X509Data' in an 'EncryptedKey' doesn't specify an 'X509SKI'.");
        }
        if (x509Data.lengthSKI() > 1) {
            throw new XspException("The 'X509Data' in an 'EncryptedKey' specifies multiple 'X509SKI'.");
        }

        // Get the SKI value in bytes
        try {
            return x509Data.itemSKI(0).getSKIBytes();
        } catch (Exception ex) {
            throw new XspException("Couldn't retrieve the SKI value from an 'EncryptedKey. "
                    + ex.getMessage(), ex);
        }
    }
}
