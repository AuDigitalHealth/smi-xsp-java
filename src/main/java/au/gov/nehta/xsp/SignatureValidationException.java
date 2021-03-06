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
 * Exception thrown when an XML Signature is not valid.
 */
public class SignatureValidationException extends Exception {

    private static final long serialVersionUID = -4176419552208463279L;

    /**
     * Default constructor.
     */
    public SignatureValidationException() {
        super();
    }

    /**
     * Constructor that sets the error message.
     *
     * @param message the error message to set.
     */
    public SignatureValidationException(String message) {
        super(message);
    }

    /**
     * Constructor that sets the original throwable.
     *
     * @param cause the original throwable to set.
     */
    public SignatureValidationException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructor that sets the error message and the original throwable.
     *
     * @param message the error message to set.
     * @param cause   the original throwable to set.
     */
    public SignatureValidationException(String message, Throwable cause) {
        super(message, cause);
    }

}
