package au.gov.nehta.common.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.StringReader;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class DomUtilsTest {

    @Test
    public void parseAndSerialise_roundTripsSimpleElement() throws Exception {
        Document doc = DomUtils.parse(new StringReader("<root><child>x</child></root>"));
        assertFalse(DomUtils.isDocumentEmpty(doc));
        Element child = DomUtils.getFirstChildElement(doc.getDocumentElement());
        assertEquals("child", child.getLocalName());
        assertEquals("x", child.getTextContent());
        String xml = DomUtils.serialiseToString(doc.getDocumentElement());
        assertTrue(xml.contains("child"));
        assertTrue(xml.contains("x"));
    }

    @Test
    public void removeFormatting_stripsWhitespaceOnlyTextNodes() throws Exception {
        Document doc = DomUtils.parse(new StringReader("<root>\n  <child> text </child>\n</root>"));
        DomUtils.removeFormatting(doc);
        Element child = DomUtils.getFirstChildElement(doc.getDocumentElement());
        assertEquals("text", child.getTextContent());
    }
}
