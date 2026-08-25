package au.gov.nehta.xsp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class XspFactoryTest {

    @Test
    public void getInstance_exposesV12AndV2010Services() throws Exception {
        XspFactory factory = XspFactory.getInstance();
        assertTrue(factory.isXmlSignatureProfileServiceSupported(XspVersion.V_1_2));
        assertTrue(factory.isXmlSignatureProfileServiceSupported(XspVersion.V_2010));
        assertTrue(factory.isSignedContainerProfileServiceSupported(XspVersion.V_1_2));
        assertTrue(factory.isEncryptedContainerProfileServiceSupported(XspVersion.V_2010));
        assertNotNull(factory.getXmlEncryptionProfileService(XspVersion.V_1_2));
        assertEquals("1.2", XspVersion.V_1_2.getId());
        assertEquals(XspVersion.V_2010, XspVersion.getVersion("2010"));
    }
}
