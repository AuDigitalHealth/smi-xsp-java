/*
 * Copyright 2008 NEHTA
 *
 * Licensed under the NEHTA Open Source (Apache) License; you may not use this
 * file except in compliance with the License. A copy of the License is in the
 * 'LICENSE.txt' file, which should be provided with this work.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package au.gov.nehta.xsp.impl.v1;

import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.crypto.SecretKey;
import javax.security.auth.x500.X500PrivateCredential;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import au.gov.nehta.common.utils.ArgumentUtils;
import au.gov.nehta.common.utils.DomUtils;
import au.gov.nehta.xsp.EncryptedContainerProfileService;
import au.gov.nehta.xsp.KeyMismatchException;
import au.gov.nehta.xsp.XmlEncryptionProfileService;
import au.gov.nehta.xsp.XspException;

/**
 * Implementation of EncryptedContainerProfileService interface that supports
 * <em>XML Secured Payload Profile</em>, NEHTA version 1.2 (30 June 2009) and
 * Standards Australia version 2010.
 * <p>
 * It uses the Apache XML Security library to perform encryption.
 */
public class EncryptedContainerProfileServiceImpl implements EncryptedContainerProfileService {

    /*
     * XML namespace of the encrypted payload.
     */
    private final String encryptedPayloadXmlns;

    /*
     * Implementation that encrypts and decrypts using XML Encryption
     */
    private final XmlEncryptionProfileService xmlEncService;

    /**
     * Constructor that sets the XML Encryption profile service.
     *
     * @param encryptedPayloadXmlns XML namespace of the encrypted payload.
     * @param xmlEncService         Implementation that encrypts and decrypts using XML Encryption.
     */
    public EncryptedContainerProfileServiceImpl(String encryptedPayloadXmlns,
                                                XmlEncryptionProfileService xmlEncService) {

        ArgumentUtils.checkNotNullNorBlank(encryptedPayloadXmlns, "encryptedPayloadXmlns");
        ArgumentUtils.checkNotNull(xmlEncService, "xmlEncService");

        this.encryptedPayloadXmlns = encryptedPayloadXmlns;
        this.xmlEncService = xmlEncService;
    }

    @Override
    public Document create(Document payloadDoc, X509Certificate certificate) throws XspException {

        DomUtils.checkNotNullOrEmpty(payloadDoc, "payloadDoc");
        ArgumentUtils.checkNotNull(certificate, "certificate");

        return create(payloadDoc, List.of(certificate));
    }

    @Override
    public Document create(Document payloadDoc, List<X509Certificate> certificates) throws XspException {

        DomUtils.checkNotNullOrEmpty(payloadDoc, "payloadDoc");
        ArgumentUtils.checkNotNullNorEmpty(certificates, "certificates");

        // Clone payload document so that the input parameter doesn't get modified
        Document clonePayloadDoc = (Document) payloadDoc.cloneNode(true);

        // Ensure that the payload document has been normalized. If this is not
        // done, namespaces may be missing from the encrypted document.
        clonePayloadDoc.normalizeDocument();

        // Create an empty container document.
        // This document is used as the context in the encryption operations and
        // will contain the EncryptedPayload.
        Document containerDoc;
        try {
            containerDoc = DomUtils.newDocument();
        } catch (ParserConfigurationException e) {
            throw new XspException("Couldn't create the encrypted payload container XML document.", e);
        }

        // Create the 'ep:encryptedPayload' root element.
        Element encryptedPayloadElem = containerDoc.createElementNS(this.encryptedPayloadXmlns,
                XspTagConstants.ENCRYPTED_PAYLOAD_QNAME);
        containerDoc.appendChild(encryptedPayloadElem);

        // Create the 'ep:keys' element.
        Element keysElem = containerDoc.createElementNS(this.encryptedPayloadXmlns, XspTagConstants.KEYS_QNAME);
        encryptedPayloadElem.appendChild(keysElem);

        // Create the 'ep:encryptedPayloadData' element
        Element encryptedPayloadDataElem = containerDoc.createElementNS(this.encryptedPayloadXmlns,
                XspTagConstants.ENCRYPTED_PAYLOAD_DATA_QNAME);
        encryptedPayloadElem.appendChild(encryptedPayloadDataElem);

        // Add root element of payload document to 'ep:encryptedPayloadData' element
        Element rootPayloadElem = clonePayloadDoc.getDocumentElement();
        Element importedPayloadElem = (Element) containerDoc.importNode(rootPayloadElem, true);
        encryptedPayloadDataElem.appendChild(importedPayloadElem);

        // Carry out encryption
        this.xmlEncService.encrypt(keysElem, importedPayloadElem, certificates);

        return containerDoc;
    }

    @Override
    public Document create(Document payloadDoc, SecretKey sessionKey, X509Certificate certificate)
            throws XspException {

        DomUtils.checkNotNullOrEmpty(payloadDoc, "payloadDoc");
        ArgumentUtils.checkNotNull(sessionKey, "sessionKey");
        ArgumentUtils.checkNotNull(certificate, "certificate");

        return create(payloadDoc, sessionKey, List.of(certificate));
    }

    @Override
    public Document create(Document payloadDoc, SecretKey sessionKey, List<X509Certificate> certificates)
            throws XspException {

        DomUtils.checkNotNullOrEmpty(payloadDoc, "payloadDoc");
        ArgumentUtils.checkNotNull(sessionKey, "sessionKey");
        ArgumentUtils.checkNotNullNorEmpty(certificates, "certificates");

        // Clone payload document so that the input parameter doesn't get modified
        Document clonePayloadDoc = (Document) payloadDoc.cloneNode(true);

        // Ensure that the payload document has been normalized. If this is not
        // done, namespaces may be missing from the encrypted document.
        clonePayloadDoc.normalizeDocument();

        // Create an empty container document.
        // This document is used as the context in the encryption operations and
        // will contain the EncryptedPayload.
        Document containerDoc;
        try {
            containerDoc = DomUtils.newDocument();
        } catch (ParserConfigurationException e) {
            throw new XspException("Couldn't create the encrypted payload container XML document.", e);
        }

        // Create the 'ep:encryptedPayload' root element.
        Element encryptedPayloadElem = containerDoc.createElementNS(this.encryptedPayloadXmlns,
                XspTagConstants.ENCRYPTED_PAYLOAD_QNAME);
        containerDoc.appendChild(encryptedPayloadElem);

        // Create the 'ep:keys' element.
        Element keysElem = containerDoc.createElementNS(this.encryptedPayloadXmlns, XspTagConstants.KEYS_QNAME);
        encryptedPayloadElem.appendChild(keysElem);

        // Create the 'ep:encryptedPayloadData' element
        Element encryptedPayloadDataElem = containerDoc.createElementNS(this.encryptedPayloadXmlns,
                XspTagConstants.ENCRYPTED_PAYLOAD_DATA_QNAME);
        encryptedPayloadElem.appendChild(encryptedPayloadDataElem);

        // Add root element of payload document to 'ep:encryptedPayloadData' element
        Element rootPayloadElem = clonePayloadDoc.getDocumentElement();
        Element importedPayloadElem = (Element) containerDoc.importNode(rootPayloadElem, true);
        encryptedPayloadDataElem.appendChild(importedPayloadElem);

        // Carry out encryption
        this.xmlEncService.encrypt(keysElem, importedPayloadElem, sessionKey, certificates);

        return containerDoc;
    }

    @Override
    public Document getData(Document encryptedPayloadDoc, X500PrivateCredential credential)
            throws KeyMismatchException, XspException {

        DomUtils.checkNotNullOrEmpty(encryptedPayloadDoc, "encryptedPayloadDoc");
        ArgumentUtils.checkNotNull(credential, "credential");

        return getData(encryptedPayloadDoc.getDocumentElement(), credential);
    }

    @Override
    public Document getData(Element encryptedPayloadElem, X500PrivateCredential credential)
            throws KeyMismatchException, XspException {

        ArgumentUtils.checkNotNull(encryptedPayloadElem, "encryptedPayloadElem");
        DomUtils.checkElement(encryptedPayloadElem, XspTagConstants.ENCRYPTED_PAYLOAD_TAG,
                this.encryptedPayloadXmlns);
        ArgumentUtils.checkNotNull(credential, "credential");

        // Clone payload so that the input parameter doesn't get modified
        Element clonedPayloadElem = (Element) encryptedPayloadElem.cloneNode(true);

        // Get the 'ep:keys' element.
        Element keysElem = DomUtils.getChildElement(clonedPayloadElem, this.encryptedPayloadXmlns,
                XspTagConstants.KEYS_TAG);

        // Get the list of 'xenc:EncryptedKey' elements.
        List<Element> encryptedKeyElems = DomUtils.getChildElements(keysElem, XmlEncConstants.XMLENC_NS,
                XmlEncConstants.ENCRYPTED_KEY_TAG);

        // Get the 'ep:encryptedPayloadData' element.
        Element encryptedPayloadDataElem = DomUtils.getChildElement(clonedPayloadElem, this.encryptedPayloadXmlns,
                XspTagConstants.ENCRYPTED_PAYLOAD_DATA_TAG);

        // Get the 'xenc:EncryptedData' element.
        Element encryptedDataElem = DomUtils.getChildElement(encryptedPayloadDataElem, XmlEncConstants.XMLENC_NS,
                XmlEncConstants.ENCRYPTED_DATA_TAG);

        // Decrypt the payload
        this.xmlEncService.decrypt(encryptedKeyElems, encryptedDataElem, credential);

        // Get the 'ep:encryptedPayloadData' element from the decrypted container
        // decryptedContainerDoc
        encryptedPayloadDataElem = DomUtils.getChildElement(clonedPayloadElem, this.encryptedPayloadXmlns,
                XspTagConstants.ENCRYPTED_PAYLOAD_DATA_TAG);

        // Get the payload from the 'ep:encryptedPayloadData' element
        Element payloadElem = DomUtils.getFirstChildElement(encryptedPayloadDataElem);

        // Create a new document containing the payload
        try {
            return DomUtils.newDocument(payloadElem);
        } catch (ParserConfigurationException ex) {
            throw new XspException("Couldn't create new document containing the payload.", ex);
        }
    }

    @Override
    public Document getData(Document encryptedPayloadDoc, SecretKey sessionKey)
            throws KeyMismatchException, XspException {

        DomUtils.checkNotNullOrEmpty(encryptedPayloadDoc, "encryptedPayloadDoc");
        ArgumentUtils.checkNotNull(sessionKey, "sessionKey");

        return getData(encryptedPayloadDoc.getDocumentElement(), sessionKey);
    }

    @Override
    public Document getData(Element encryptedPayloadElem, SecretKey sessionKey)
            throws KeyMismatchException, XspException {

        ArgumentUtils.checkNotNull(encryptedPayloadElem, "encryptedPayloadElem");
        DomUtils.checkElement(encryptedPayloadElem, XspTagConstants.ENCRYPTED_PAYLOAD_TAG, this.encryptedPayloadXmlns);
        ArgumentUtils.checkNotNull(sessionKey, "sessionKey");

        // Clone payload so that the input parameter doesn't get modified
        Element clonedPayloadElem = (Element) encryptedPayloadElem.cloneNode(true);

        // Get the 'ep:keys' element.
        Element keysElem = DomUtils.getChildElement(clonedPayloadElem, this.encryptedPayloadXmlns, XspTagConstants.KEYS_TAG);

        // Get the list of 'xenc:EncryptedKey' elements.
        List<Element> encryptedKeyElems = DomUtils.getChildElements(keysElem, XmlEncConstants.XMLENC_NS, XmlEncConstants.ENCRYPTED_KEY_TAG);

        // Get the 'ep:encryptedPayloadData' element.
        Element encryptedPayloadDataElem = DomUtils.getChildElement(clonedPayloadElem, this.encryptedPayloadXmlns,
                XspTagConstants.ENCRYPTED_PAYLOAD_DATA_TAG);

        // Get the 'xenc:EncryptedData' element.
        Element encryptedDataElem = DomUtils.getChildElement(encryptedPayloadDataElem, XmlEncConstants.XMLENC_NS,
                XmlEncConstants.ENCRYPTED_DATA_TAG);

        // Decrypt the payload
        this.xmlEncService.decrypt(encryptedKeyElems, encryptedDataElem, sessionKey);

        // Get the 'ep:encryptedPayloadData' element from the decrypted container
        // decryptedContainerDoc
        encryptedPayloadDataElem = DomUtils.getChildElement(clonedPayloadElem, this.encryptedPayloadXmlns, XspTagConstants.ENCRYPTED_PAYLOAD_DATA_TAG);

        // Get the payload from the 'ep:encryptedPayloadData' element
        Element payloadElem = DomUtils.getFirstChildElement(encryptedPayloadDataElem);

        // Create a new document containing the payload
        try {
            return DomUtils.newDocument(payloadElem);
        } catch (ParserConfigurationException ex) {
            throw new XspException("Couldn't create new document containing the payload.", ex);
        }
    }

    @Override
    public Key getSessionKey(Element encryptedPayloadElem, X500PrivateCredential credential)
            throws KeyMismatchException, XspException {

        ArgumentUtils.checkNotNull(encryptedPayloadElem, "encryptedPayloadElem");
        ArgumentUtils.checkNotNull(credential, "credential");

        // Clone payload so that the input parameter doesn't get modified
        Element clonedPayloadElem = (Element) encryptedPayloadElem.cloneNode(true);

        List<Element> encryptedKeyElems = getEncryptedKeyElements(clonedPayloadElem);
        Element encryptedDataElem = getEncryptedDataElement(clonedPayloadElem);
        return this.xmlEncService.getSessionKey(encryptedKeyElems, encryptedDataElem, credential);
    }

    @Override
    public Key getSessionKey(Document encryptedPayloadDoc, X500PrivateCredential credential)
            throws KeyMismatchException, XspException {

        // Gets the session key
        return getSessionKey(encryptedPayloadDoc.getDocumentElement(), credential);
    }

    @Override
    public List<X509Certificate> getEncryptingCertificates(Element encryptedPayloadElem, KeyStore keyStore)
            throws XspException {

        ArgumentUtils.checkNotNull(encryptedPayloadElem, "encryptedPayloadElem");
        ArgumentUtils.checkNotNull(keyStore, "keyStore");

        // Clone payload so that the input parameter doesn't get modified
        Element clonedPayloadElem = (Element) encryptedPayloadElem.cloneNode(true);

        List<Element> encryptedKeyElems = getEncryptedKeyElements(clonedPayloadElem);
        return this.xmlEncService.getEncryptingCertificates(encryptedKeyElems, keyStore);
    }

    @Override
    public List<X509Certificate> getEncryptingCertificates(Document encryptedPayloadDoc, KeyStore keyStore)
            throws XspException {

        ArgumentUtils.checkNotNull(encryptedPayloadDoc, "encryptedPayloadDoc");

        return getEncryptingCertificates(encryptedPayloadDoc.getDocumentElement(), keyStore);
    }

    @Override
    public boolean isEncryptingCertificate(Element encryptedPayloadElem, X509Certificate certificate)
            throws XspException {

        ArgumentUtils.checkNotNull(encryptedPayloadElem, "encryptedPayloadElem");
        DomUtils.checkElement(encryptedPayloadElem, XspTagConstants.ENCRYPTED_PAYLOAD_TAG, this.encryptedPayloadXmlns);
        ArgumentUtils.checkNotNull(certificate, "certificate");

        // Clone payload so that the input parameter doesn't get modified
        Element clonedPayloadElem = (Element) encryptedPayloadElem.cloneNode(true);

        List<Element> encryptedKeyElems = getEncryptedKeyElements(clonedPayloadElem);
        return this.xmlEncService.isEncryptingCertificate(encryptedKeyElems, certificate);
    }

    @Override
    public boolean isEncryptingCertificate(Document encryptedPayloadDoc, X509Certificate certificate)
            throws XspException {

        ArgumentUtils.checkNotNull(encryptedPayloadDoc, "encryptedPayloadDoc");
        ArgumentUtils.checkNotNull(certificate, "certificate");

        return isEncryptingCertificate(encryptedPayloadDoc.getDocumentElement(), certificate);
    }

    private List<Element> getEncryptedKeyElements(Element encryptedPayloadElem) {
        // Get the 'ep:keys' element.
        Element keysElem = DomUtils.getChildElement(encryptedPayloadElem, this.encryptedPayloadXmlns, XspTagConstants.KEYS_TAG);

        // Get the list of 'xenc:EncryptedKey' elements.
        return DomUtils.getChildElements(keysElem, XmlEncConstants.XMLENC_NS, XmlEncConstants.ENCRYPTED_KEY_TAG);
    }

    private Element getEncryptedDataElement(Element encryptedPayloadElem) {
        // Get the 'ep:encryptedPayloadData' element.
        Element encryptedPayloadDataElem = DomUtils.getChildElement(encryptedPayloadElem, this.encryptedPayloadXmlns,
                XspTagConstants.ENCRYPTED_PAYLOAD_DATA_TAG);

        // Get the 'xenc:EncryptedData' element.
        return DomUtils.getChildElement(encryptedPayloadDataElem, XmlEncConstants.XMLENC_NS, XmlEncConstants.ENCRYPTED_DATA_TAG);
    }

}
