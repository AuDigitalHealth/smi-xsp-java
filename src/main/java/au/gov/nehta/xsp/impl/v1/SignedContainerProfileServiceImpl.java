/*
 * Copyright 2008 NEHTA
 *
 * Licensed under the NEHTA Open Source (Apache) License; you may not use this file except in compliance with the
 * License. A copy of the License is in the 'LICENSE.txt' file, which should be provided with this work.
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package au.gov.nehta.xsp.impl.v1;

import java.security.cert.X509Certificate;
import java.util.*;

import javax.security.auth.x500.X500PrivateCredential;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import au.gov.nehta.common.utils.ArgumentUtils;
import au.gov.nehta.common.utils.DomUtils;
import au.gov.nehta.xsp.CertificateValidationException;
import au.gov.nehta.xsp.CertificateValidator;
import au.gov.nehta.xsp.SignatureValidationException;
import au.gov.nehta.xsp.SignedContainerProfileService;
import au.gov.nehta.xsp.XmlSignatureProfileService;
import au.gov.nehta.xsp.XspException;

/**
 * Implementation of SignedContainerProfileService interface that supports
 * <em>XML Secured Payload Profile</em>, NEHTA version 1.2 (30 June 2009) and
 * Standards Australia version 2010.
 */
public class SignedContainerProfileServiceImpl implements SignedContainerProfileService {

        /*
         * XML namespace of the signed payload.
         */
        private final String signedPayloadXmlns;

        /*
         * Implementation that creates and checks the XML signatures
         */
        private final XmlSignatureProfileService xmlSigService;

        /**
         * Constructor that sets the XML Signature Profile service.
         *
         * @param signedPayloadXmlns XML namespace of the signed payload.
         * @param xmlSigService      Implementation that will create and check XML
         *                           signatures.
         */
        public SignedContainerProfileServiceImpl(String signedPayloadXmlns,
                        XmlSignatureProfileService xmlSigService) {
                ArgumentUtils.checkNotNullNorBlank(signedPayloadXmlns, "signedPayloadXmlns");
                ArgumentUtils.checkNotNull(xmlSigService, "xmlSigService");

                this.signedPayloadXmlns = signedPayloadXmlns;
                this.xmlSigService = xmlSigService;
        }

        /**
         * @see au.gov.nehta.xsp.SignedContainerProfileService#create(org.w3c.dom.Document,
         *      javax.security.auth.x500.X500PrivateCredential)
         */
        @Override
        public Document create(Document payloadDoc, X500PrivateCredential credential) throws XspException {
                ArgumentUtils.checkNotNull(credential, "credential");

                return create(payloadDoc, List.of(credential));
        }

        /**
         * @see au.gov.nehta.xsp.SignedContainerProfileService#create(org.w3c.dom.Document,
         *      java.util.List)
         */
        @Override
        public Document create(Document payloadDoc, List<X500PrivateCredential> credentials)
                        throws XspException {
                DomUtils.checkNotNullOrEmpty(payloadDoc, "payloadDoc");
                ArgumentUtils.checkNotNullNorEmpty(credentials, "credentials");

                // Create an empty container document.
                // This document is used as the context in the signing operations and
                // will contain the SignedPayload.
                Document containerDoc;
                try {
                        containerDoc = DomUtils.newDocument();
                } catch (ParserConfigurationException e) {
                        throw new XspException("Couldn't create signed payload container XML document.", e);
                }

                // Create the 'sp:signedPayload' root element.
                Element signedPayloadElem = containerDoc.createElementNS(this.signedPayloadXmlns,
                                XspTagConstants.SIGNED_PAYLOAD_QNAME);
                containerDoc.appendChild(signedPayloadElem);

                // Create the 'sp:signatures' element.
                Element signaturesElem = containerDoc.createElementNS(this.signedPayloadXmlns,
                                XspTagConstants.SIGNATURES_QNAME);
                signedPayloadElem.appendChild(signaturesElem);

                // Create the 'sp:signedPayloadData' element.
                Element signedPayloadDataElem = containerDoc.createElementNS(this.signedPayloadXmlns,
                                XspTagConstants.SIGNED_PAYLOAD_DATA_QNAME);

                // Import the payload as a child element of the 'sp:signedPayloadData'
                // element.
                Node payloadNode = containerDoc.importNode(payloadDoc.getDocumentElement(), true);
                signedPayloadDataElem.appendChild(payloadNode);

                // Add the 'sp:signedPayloadData' element to the root element.
                signedPayloadElem.appendChild(signedPayloadDataElem);

                // Generate a unique reference identifier.
                // The reference id cannot begin with a digit, hence the underscore.
                String referenceId = "_" + UUID.randomUUID().toString();

                // Add the 'id' attribute (of type ID) to the 'sp:signedPayloadData'
                // element.
                signedPayloadDataElem.setAttribute(XspTagConstants.ID_TAG, referenceId);
                signedPayloadDataElem.setIdAttribute(XspTagConstants.ID_TAG, true);

                // Perform XML signature
                this.xmlSigService.sign(signaturesElem, signedPayloadDataElem, credentials);

                return containerDoc;
        }

        @Override
        public void check(Document containerDoc, CertificateValidator certificateValidator)
                        throws SignatureValidationException, CertificateValidationException, XspException {
                DomUtils.checkNotNullOrEmpty(containerDoc, "containerDoc");
                DomUtils.checkElement(containerDoc.getDocumentElement(), XspTagConstants.SIGNED_PAYLOAD_TAG,
                                this.signedPayloadXmlns);
                ArgumentUtils.checkNotNull(certificateValidator, "certificateValidator");

                // Get the 'sp:signatures' element.
                Element signaturesElem = DomUtils.getChildElement(containerDoc.getDocumentElement(),
                                this.signedPayloadXmlns, XspTagConstants.SIGNATURES_TAG);
                if (signaturesElem == null) {
                        String errMsg = "No '" + XspTagConstants.SIGNATURES_TAG + "' element was found within the '"
                                        + XspTagConstants.SIGNED_PAYLOAD_TAG + "' element.";
                        throw new XspException(errMsg);
                }

                // Get the 'ds:Signature' elements.
                List<Element> dsSignatureElems = DomUtils.getChildElements(signaturesElem,
                                XmlSigConstants.XMLDSIG_NS, XmlSigConstants.SIGNATURE_TAG);
                if (dsSignatureElems.isEmpty()) {
                        String errMsg = "No XML Signature elements were found within the '"
                                        + XspTagConstants.SIGNATURES_TAG + "' element.";
                        throw new XspException(errMsg);
                }

                // Check the signatures
                this.xmlSigService.check(dsSignatureElems, certificateValidator);
        }

        @Override
        public Document getData(Document containerDoc) throws XspException {
                DomUtils.checkNotNullOrEmpty(containerDoc, "containerDoc");
                DomUtils.checkElement(containerDoc.getDocumentElement(), XspTagConstants.SIGNED_PAYLOAD_TAG,
                                this.signedPayloadXmlns);

                // Get the 'sp:signedPayloadData' element.
                Element signedPayloadDataElem = DomUtils.getChildElement(containerDoc.getDocumentElement(),
                                this.signedPayloadXmlns, XspTagConstants.SIGNED_PAYLOAD_DATA_TAG);
                if (signedPayloadDataElem == null) {
                        String errMsg = "No '" + XspTagConstants.SIGNED_PAYLOAD_DATA_TAG
                                        + "' element was found within the '" + XspTagConstants.SIGNED_PAYLOAD_TAG
                                        + "' element.";
                        throw new XspException(errMsg);
                }

                // Get the payload element (the first child of the 'sp:signedPayloadData'
                // element)
                Element payloadElem = DomUtils.getFirstChildElement(signedPayloadDataElem);
                if (payloadElem == null) {
                        String errMsg = "No payload element was found within the '"
                                        + XspTagConstants.SIGNED_PAYLOAD_DATA_TAG + "' element.";
                        throw new XspException(errMsg);
                }

                // Return payload in a new document
                try {
                        return DomUtils.newDocument(payloadElem);
                } catch (ParserConfigurationException ex) {
                        throw new XspException("Couldn't create a new document containing the payload.", ex);
                }
        }

        @Override
        public List<X509Certificate> getSigningCertificates(Document containerDoc) throws XspException {
                DomUtils.checkNotNullOrEmpty(containerDoc, "containerDoc");
                DomUtils.checkElement(containerDoc.getDocumentElement(), XspTagConstants.SIGNED_PAYLOAD_TAG,
                                this.signedPayloadXmlns);

                // Get the 'sp:signatures' element.
                Element signaturesElem = DomUtils.getChildElement(containerDoc.getDocumentElement(),
                                this.signedPayloadXmlns, XspTagConstants.SIGNATURES_TAG);
                if (signaturesElem == null) {
                        String errMsg = "No '" + XspTagConstants.SIGNATURES_TAG + "' element was found within the '"
                                        + XspTagConstants.SIGNED_PAYLOAD_TAG + "' element.";
                        throw new XspException(errMsg);
                }

                // Get the 'ds:Signature' elements.
                List<Element> dsSignatureElems = DomUtils.getChildElements(signaturesElem,
                                XmlSigConstants.XMLDSIG_NS, XmlSigConstants.SIGNATURE_TAG);
                if (dsSignatureElems.isEmpty()) {
                        String errMsg = "No XML Signature elements were found within the '"
                                        + XspTagConstants.SIGNATURES_TAG + "' element.";
                        throw new XspException(errMsg);
                }

                // Extract the X509Certificate from each 'ds:Signature' element.
                List<X509Certificate> signingCertificates = new ArrayList<>();
                for (Element dsSignatureElem : dsSignatureElems) {
                        signingCertificates.add(this.xmlSigService.getSigningCertificate(dsSignatureElem));
                }

                return signingCertificates;
        }

        @Override
        public List<byte[]> getDigestValues(Document containerDoc) throws XspException {
                DomUtils.checkNotNullOrEmpty(containerDoc, "containerDoc");
                DomUtils.checkElement(containerDoc.getDocumentElement(), XspTagConstants.SIGNED_PAYLOAD_TAG,
                                this.signedPayloadXmlns);

                // Get the 'sp:signatures' element.
                Element signaturesElem = DomUtils.getChildElement(containerDoc.getDocumentElement(),
                                this.signedPayloadXmlns, XspTagConstants.SIGNATURES_TAG);
                if (signaturesElem == null) {
                        String errMsg = "No '" + XspTagConstants.SIGNATURES_TAG + "' element was found within the '"
                                        + XspTagConstants.SIGNED_PAYLOAD_TAG + "' element.";
                        throw new XspException(errMsg);
                }

                // Get the 'ds:Signature' elements.
                List<Element> dsSignatureElems = DomUtils.getChildElements(signaturesElem,
                                XmlSigConstants.XMLDSIG_NS, XmlSigConstants.SIGNATURE_TAG);
                if (dsSignatureElems.isEmpty()) {
                        String errMsg = "No XML Signature elements were found within the '"
                                        + XspTagConstants.SIGNATURES_TAG + "' element.";
                        throw new XspException(errMsg);
                }

                // Extract the 'DigestValue' from each 'ds:Signature' element.
                List<byte[]> digestValues = new ArrayList<>();
                for (Element dsSignatureElem : dsSignatureElems) {
                        Map<String, byte[]> dvMap = this.xmlSigService.getDigestValues(dsSignatureElem);
                        if (dvMap.size() > 1) {
                                String errMsg = "There were multiple references in a signature.";
                                throw new XspException(errMsg);
                        }
                        digestValues.add(dvMap.values().iterator().next());
                }

                return digestValues;
        }

}
