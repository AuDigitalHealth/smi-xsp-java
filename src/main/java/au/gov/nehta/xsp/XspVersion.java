/*
 * Copyright 2009 NEHTA
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
package au.gov.nehta.xsp;

/**
 * Represents a version of the <em>XML Secured Payload Profile</em> document.
 */
public enum XspVersion {

    /**
     * Version 1.2 - 30 June 2009
     */
    V_1_2("1.2"),

    /**
     * Version 2010 - 7 December 2009
     */
    V_2010("2010");

    private final String id;

    XspVersion(String id) {
        assert ((id != null) && !id.isEmpty());
        this.id = id;
    }

    /**
     * Returns the version identifier.
     *
     * @return version ID.
     */
    public String getId() {
        return this.id;
    }

    @Override
    public String toString() {
        return this.id;
    }

    /**
     * Returns the XspVersion enum that matches a given version ID.
     *
     * @param versionId the version identifier to match on.
     * @return XspVersion enum or null if unknown version ID.
     */
    public static XspVersion getVersion(String versionId) {
        for (XspVersion version : values()) {
            if (version.id.equals(versionId)) {
                return version;
            }
        }
        return null;
    }

}
