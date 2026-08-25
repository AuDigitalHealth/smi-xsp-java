package au.gov.nehta.xsp.impl;

import org.junit.Test;

public class CertificateUtilsTest {

    @Test
    public void checkJCEpolicyIsUnlimited_passesOnJava17() throws Exception {
        CertificateUtils.checkJCEpolicyIsUnlimited();
    }

    @Test
    public void getSubjectName_nullCertificateReturnsNull() {
        org.junit.Assert.assertNull(CertificateUtils.getSubjectName(null));
    }
}
