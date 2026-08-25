package au.gov.nehta.xsp.impl.v1;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.security.auth.x500.X500PrivateCredential;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.NodeList;

import au.gov.nehta.common.utils.ArgumentUtils;
import au.gov.nehta.common.utils.DomUtils;
import au.gov.nehta.xsp.CertificateValidationException;
import au.gov.nehta.xsp.CertificateValidator;
import au.gov.nehta.xsp.SignatureValidationException;
import au.gov.nehta.xsp.XmlSignatureProfileService;
import au.gov.nehta.xsp.XspException;
import au.gov.nehta.xsp.impl.CertificateUtils;
import au.gov.nehta.xsp.impl.TextUtils;

/**
 * Implementation of XmlSignatureProfileService interface that supports
 * <em>XML Secured Payload Profile</em>, NEHTA version 1.2 (30 June 2009) and
 * Standards Australia version 2010.
 *
 * See https://bugs.java.com/bugdatabase/view_bug.do?bug_id=8017169
 * JVM bug JDK-8017169 : XML Signature Validation throws URIReferenceException
 * JDK-8017265 : XMLSignature Cannot Resolve ID
 */
public class XmlSignatureProfileServiceImpl implements XmlSignatureProfileService {

    private static final XMLSignatureFactory XML_SIGNATURE_FACTORY = XMLSignatureFactory
            .getInstance("DOM");

    private static final KeyInfoFactory KEY_INFO_FACTORY = XML_SIGNATURE_FACTORY.getKeyInfoFactory();
    private final String signedPayloadNamespace;

    public XmlSignatureProfileServiceImpl(String nsSignedPayloadV12) {
        this.signedPayloadNamespace = nsSignedPayloadV12;
    }

    @Override
    public void sign(Element elementToAddSigTo, Element elementToSign, X500PrivateCredential credential) throws XspException {
        ArgumentUtils.checkNotNull(elementToSign, "elementToSign");
        ArgumentUtils.checkNotNull(credential, "credential");

        sign(elementToAddSigTo, List.of(elementToSign), List.of(credential));
    }

    @Override
    public void sign(Element elementToAddSigTo,
                     List<Element> elementsToSign,
                     X500PrivateCredential credential) throws XspException {
        ArgumentUtils.checkNotNull(credential, "credential");

        sign(elementToAddSigTo, elementsToSign, List.of(credential));
    }

    @Override
    public void sign(Element elementToAddSigTo,
                     Element elementToSign,
                     List<X500PrivateCredential> credentials) throws XspException {
        ArgumentUtils.checkNotNull(elementToSign, "elementToSign");

        sign(elementToAddSigTo, List.of(elementToSign), credentials);
    }

    @Override
    public void sign(Element elementToAddSigTo,
                     List<Element> elementsToSign,
                     List<X500PrivateCredential> credentials) throws XspException {
        ArgumentUtils.checkNotNull(elementToAddSigTo, "elementToAddSigTo");
        ArgumentUtils.checkNotNullNorEmpty(elementsToSign, "elementsToSign");
        ArgumentUtils.checkNotNullNorEmpty(credentials, "credentials");

        // Get the container document
        Document containerDoc = elementToAddSigTo.getOwnerDocument();

        // Check elements to sign are in the same document as the element to add
        // signatures to
        for (Element elementToSign : elementsToSign) {
            if (containerDoc != elementToSign.getOwnerDocument()) {
                String errMsg = "The element to sign, " + TextUtils.getDesc(elementToSign)
                        + ", must belong to the same document as the element to add " + "the signatures to, "
                        + TextUtils.getDesc(elementToAddSigTo) + ".";
                throw new IllegalArgumentException(errMsg);
            }
        }

        // For each element to sign, create a reference.
        List<Reference> referenceList = new ArrayList<>();
        for (Element elementToSign : elementsToSign) {
            // Get reference ID to the element to sign
            String referenceId;
            List<String> elemIdValues = getIdValues(elementToSign);
            if (!elemIdValues.isEmpty()) {
                // Element has an ID value, pick the first one
                referenceId = elemIdValues.get(0);
            } else {
                referenceId = elementToSign.getAttributeNS(XmlSigConstants.XML_NS,
                        XmlSigConstants.XML_ID_QNAME);
                if (ArgumentUtils.isNullOrBlank(referenceId)) {
                    // Element has no ID value, so add one to the element

                    // Generate a UUID for the reference ID value
                    referenceId = "_" + UUID.randomUUID().toString();

                    // Set the 'xml:id' attribute on element
                    elementToSign.setAttributeNS(XmlSigConstants.XML_NS, XmlSigConstants.XML_ID_QNAME,
                            referenceId);
                }

                // Give the 'xml:id' attribute the 'ID type.
                elementToSign.setIdAttribute(XmlSigConstants.XML_ID_QNAME, true);
            }

            // Create an XML DSIG Reference containing the reference ID
            Reference reference = newReference(referenceId);
            referenceList.add(reference);
        }

        // Create an XML DSIG SignedInfo containing the list of References.
        SignedInfo signedInfo = newSignedInfo(referenceList);

        // Note: the following line is important when serializing the container.
        // If it is not called and the container is serialized, the signature
        // will become invalid.
        containerDoc.normalizeDocument();

        // For each credential, generate a signature
        for (X500PrivateCredential credential : credentials) {
            X509Certificate signingCertificate = credential.getCertificate();
            PrivateKey signingPrivateKey = credential.getPrivateKey();

            // Create an XML DSIG KeyInfo
            KeyInfo keyInfo = newKeyInfo(signingCertificate);

            // Create the XMLSignature object
            XMLSignature signature = XML_SIGNATURE_FACTORY.newXMLSignature(signedInfo, keyInfo);

            // Create a signing context
            DOMSignContext signContext = new DOMSignContext(signingPrivateKey, elementToAddSigTo);
            signContext.setDefaultNamespacePrefix(XmlSigConstants.XMLDSIG_NS_PREFIX);

            // Generated XML DSIG signature. It will be added as a child element to
            // the 'sp:signatures' element.
            try {
                signature.sign(signContext);
            } catch (Exception e) {
                throw new XspException("Couldn't create signature with credential, "
                        + TextUtils.getDesc(signingCertificate) + ".", e);
            }
        }
    }

    /**
     * Check the Digital Signature of an XML Element.
     * <p>
     * IMPORTANT: Elements with 'id' attributes that are referenced in the signature
     * must be marked with element.setIdAttribute(attribute, true) or else the Java
     * Signature check will not be able to resolve the URI reference
     *
     * @param signatureElem        a 'Signature' XML Element to validate
     * @param certificateValidator custom business logic to decide if a certificate is acceptable
     * @throws SignatureValidationException   if the Signature is invalid
     * @throws XspException                   on problems interpreting the XMLSignature element
     * @throws CertificateValidationException from the supplied CertificateValidator
     */
    @Override
    public void check(Element signatureElem, CertificateValidator certificateValidator)
            throws SignatureValidationException, CertificateValidationException, XspException {
        ArgumentUtils.checkNotNull(signatureElem, "signatureElem");
        ArgumentUtils.checkNotNull(certificateValidator, "certificateValidator");

        check(List.of(signatureElem), certificateValidator);
    }

    /**
     * Check the Digital Signature of an XML Element.
     * <p>
     * IMPORTANT: Elements with 'id' attributes that are referenced in the signature
     * must be marked with element.setIdAttribute(attribute, true) or else the Java
     * Signature check will not be able to resolve the URI reference
     *
     * @param signatureElems       a List of 'Signature' XML Elements to validate
     * @param certificateValidator custom business logic to decide if a certificate is acceptable
     * @throws SignatureValidationException   if the Signature is invalid
     * @throws XspException                   on problems interpreting the XMLSignature element
     * @throws CertificateValidationException from the supplied CertificateValidator
     */
    @Override
    public void check(List<Element> signatureElems, CertificateValidator certificateValidator)
            throws SignatureValidationException, CertificateValidationException, XspException {
        ArgumentUtils.checkNotNullNorEmpty(signatureElems, "signatureElems");
        ArgumentUtils.checkNotNull(certificateValidator, "certificateValidator");


        //JVM bug JDK-8017169 : XML Signature Validation throws URIReferenceException
        //        JDK-8017265 : XMLSignature Cannot Resolve ID
        // setting the namespace to resolve.
        markSignedPayloadIDs(signatureElems);


        // Verify each of the signatures.
        for (final Element signatureElem : signatureElems) {

            // Get the signing certificate from the XMLSignature.
            X509Certificate certificate = getSigningCertificate(signatureElem);

            // Create a validation context
            DOMValidateContext validateContext = new DOMValidateContext(certificate.getPublicKey(), signatureElem);

            //unmarshall
            XMLSignature signature = unmarshalSignature(signatureElem);


            // Validate the XMLSignature using the validation context.
            boolean valid;
            try {
                valid = signature.validate(validateContext);
            } catch (XMLSignatureException e) {
                throw new XspException("Couldn't do validation on an XML Signature.", e);
            }
            if (!valid) {
                throw new SignatureValidationException("Invalid XML Signature signed by certificate: "
                        + CertificateUtils.getSubjectName(certificate));
            }

            // Validate the certificate in the signature
            certificateValidator.validate(certificate);
        }
    }

    /**
     * Private helper method to mark the SignedPayload 'id' as xml:ID
     * assumes List<Element> is not null and has at least 1 element.
     */
    private void markSignedPayloadIDs(List<Element> signatureElems) {
        NodeList payloads = signatureElems.get(0).getOwnerDocument().getElementsByTagNameNS(signedPayloadNamespace, XspTagConstants.SIGNED_PAYLOAD_DATA_TAG);
        for (int i = 0; i < payloads.getLength(); i++) {
            ((Element) (payloads.item(i))).setIdAttribute(XspTagConstants.ID_TAG, true);
        }
    }


    @Override
    public X509Certificate getSigningCertificate(Element signatureElem) throws XspException {
        DomUtils.checkElement(signatureElem, XmlSigConstants.SIGNATURE_TAG, XmlSigConstants.XMLDSIG_NS);

        // Unmarshal the DOM 'Signature' element.
        XMLSignature signature = unmarshalSignature(signatureElem);

        return getSigningCertificate(signature);
    }

    @Override
    public Map<String, byte[]> getDigestValues(Element signatureElem) throws XspException {
        DomUtils.checkElement(signatureElem, XmlSigConstants.SIGNATURE_TAG, XmlSigConstants.XMLDSIG_NS);

        // Unmarshal the DOM 'Signature' element.
        XMLSignature signature = unmarshalSignature(signatureElem);

        return getDigestValues(signature);
    }

    /**
     * Return the list of values of attributes of the element that are of type ID.
     * Note, that attributes with name "id" etc are not necessarily of type ID.
     *
     * @param element The element for which to get the list.
     * @return the list of values of attributes of the element that are of type
     * ID.
     */
    private static List<String> getIdValues(Element element) {
        assert (element != null);

        List<String> elemIdValues = new ArrayList<>();

        NamedNodeMap attrs = element.getAttributes();
        for (int i = 0; i < attrs.getLength(); ++i) {
            Attr attr = (Attr) attrs.item(i);
            if (attr.isId()) {
                elemIdValues.add(attr.getValue());
            }
        }

        return elemIdValues;
    }

    /*
     * Create a {@code Reference} object that has a URI of referenceId.
     */
    private static Reference newReference(String referenceId) throws XspException {
        assert ((referenceId != null) && (!referenceId.trim().isEmpty()));

        try {
            DigestMethod digestMethod = XML_SIGNATURE_FACTORY.newDigestMethod(DigestMethod.SHA1, null);

            Transform transform = XML_SIGNATURE_FACTORY.newTransform(CanonicalizationMethod.EXCLUSIVE,
                    (TransformParameterSpec) null);

            return XML_SIGNATURE_FACTORY.newReference("#" + referenceId, digestMethod,
                    List.of(transform), null, null);
        } catch (Exception ex) {
            throw new XspException("Unable to create 'Reference'. " + ex.getMessage());
        }
    }

    /*
     * Create a {@code SignedInfo} object that contains the given {@code
     * Reference}.
     */
    private static SignedInfo newSignedInfo(List<Reference> referenceList) throws XspException {
        assert (referenceList != null);

        try {
            SignatureMethod signatureMethod = XML_SIGNATURE_FACTORY.newSignatureMethod(
                    SignatureMethod.RSA_SHA1, null);

            CanonicalizationMethod canonicalisationMethod = XML_SIGNATURE_FACTORY
                    .newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                            (C14NMethodParameterSpec) null);

            return XML_SIGNATURE_FACTORY.newSignedInfo(canonicalisationMethod, signatureMethod,
                    referenceList);
        } catch (Exception ex) {
            throw new XspException("Unable to create 'SignedInfo'. " + ex.getMessage(), ex);
        }
    }

    /*
     * Create a {@code KeyInfo} object for a given certificate.
     */
    private static KeyInfo newKeyInfo(X509Certificate certificate) {
        assert (certificate != null);

        X509Data x509Data = KEY_INFO_FACTORY.newX509Data(List.of(certificate));
        return KEY_INFO_FACTORY.newKeyInfo(List.of(x509Data));
    }

    /*
     * Extract the {@code X509Certificate} from the {@code XMLSignature}.
     */
    private static X509Certificate getSigningCertificate(XMLSignature signature) throws XspException {
        assert (signature != null);

        // Get the KeyInfo
        KeyInfo keyInfo = signature.getKeyInfo();
        if (keyInfo == null) {
            throw new XspException("A 'Signature' doesn't have a 'KeyInfo'.");
        }

        // Get the list of 'ds:X509Data' from 'ds:KeyInfo'
        List<X509Data> x509DataObjects = new ArrayList<>();
        for (Object content : keyInfo.getContent()) {
            if (content instanceof X509Data) {
                x509DataObjects.add((X509Data) content);
            }
        }

        // Check there is only one 'ds:X509Data'
        if (x509DataObjects.isEmpty()) {
            throw new XspException("The 'KeyInfo' in a 'Signature' doesn't specify an 'X509Data'.");
        }
        if (x509DataObjects.size() > 1) {
            throw new XspException("The 'KeyInfo' in a 'Signature' specifies multiple 'X509Data'.");
        }

        // Get the 'ds:X509Data'
        X509Data x509Data = x509DataObjects.get(0);

        // Get the 'ds:X509Certificate' within the 'ds:X509Data'
        List<X509Certificate> certificates = new ArrayList<>();
        for (Object content : x509Data.getContent()) {
            if (content instanceof X509Certificate) {
                certificates.add((X509Certificate) content);
            }
        }

        // Check there is only one 'ds:X509Certificate'
        if (certificates.isEmpty()) {
            throw new XspException("The 'X509Data' in a 'Signature' doesn't "
                    + "specify an 'X509Certificate'.");
        }
        if (certificates.size() > 1) {
            throw new XspException("The 'X509Data' in a 'Signature' specifies "
                    + "multiple 'X509Certificate'.");
        }

        // Return the X.509 certificate
        return certificates.get(0);
    }

    /*
     * Extract the {@code DigestValue}s from the {@code XMLSignature}.
     */
    @SuppressWarnings("unchecked")
    private static Map<String, byte[]> getDigestValues(XMLSignature signature) throws XspException {

        assert (signature != null);

        SignedInfo signedInfo = signature.getSignedInfo();
        if (signedInfo == null) {
            throw new XspException("A 'Signature' does not have a 'SignedInfo'.");
        }

        List<Reference> referenceList = signedInfo.getReferences();
        if ((referenceList == null) || referenceList.isEmpty()) {
            throw new XspException("The 'SignedInfo' in a 'Signature' does not have a 'Reference'.");
        }
        Map<String, byte[]> resultMap = new HashMap<>();
        for (Reference reference : referenceList) {
            String uri = reference.getURI();
            if (ArgumentUtils.isNullOrBlank(uri)) {
                throw new XspException("A 'Reference' in the 'Signature/SignedInfo' does not have a 'URI'.");
            }
            byte[] digestValue = reference.getDigestValue();
            if (digestValue == null) {
                throw new XspException(
                        "A 'Reference' in the 'Signature/SignedInfo' does not have a 'DigestValue'.");
            }
            resultMap.put(uri, digestValue);
        }

        return resultMap;
    }

    /*
     * Unmarshals the 'ds:Signature' DOM element into an XMLSignature object in
     * the Apache XML Signature library.
     */
    private static XMLSignature unmarshalSignature(Element signatureElem) throws XspException {
        assert (signatureElem != null);

        try {
            DOMStructure domStructure = new DOMStructure(signatureElem);
            return XML_SIGNATURE_FACTORY.unmarshalXMLSignature(domStructure);
        } catch (MarshalException ex) {
            throw new XspException("Couldn't unmarshall signature element. " + ex.getMessage(), ex);
        }
    }

}
