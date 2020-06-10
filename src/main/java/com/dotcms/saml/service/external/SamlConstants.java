package com.dotcms.saml.service.external;


/**
 * Encapsulates constants for the dot SAML SP
 *
 * @author jsanca
 */

public class SamlConstants {
	public static final char ARRAY_SEPARATOR_CHAR = ',';
	public static final String HTTP_SCHEMA = "http://";
	public static final String HTTPS_SCHEMA = "https://";
	public static final String HTTPS_SCHEMA_PREFIX = "https";
	public static final String ASSERTION_CONSUMER_ENDPOINT_DOTSAML3SP = "/dotsaml/login";
	public static final String LOGOUT_SERVICE_ENDPOINT_DOTSAML3SP = "/dotsaml/logout";
	public static final String RESPONSE_AND_ASSERTION = "responseandassertion";
	public static final String RESPONSE = "response";
	public static final String ASSERTION = "assertion";
	public static final String SAML_USER_ID = "SAMLUserId";
	public static final String DEFAULT_LOGIN_PATH = "/dotAdmin";

	public static final String SAML_NAME_ID_SESSION_ATTR = "SAML_NAME_ID";

	public static final String SAML_ART_PARAM_KEY = "SAMLart";

	/**
	 * Default value for the metadata protocol see
	 * {@link SamlConstants}.DOT_SAML_IDP_METADATA_PROTOCOL
	 */
	public static final String DOT_SAML_IDP_METADATA_PROTOCOL_DEFAULT_VALUE = "urn:oasis:names:tc:SAML:2.0:protocol";

	/**
	 * default include path
	 */
	public static final String DOT_SAML_INCLUDE_PATH_DEFAULT_VALUES = "^" + ASSERTION_CONSUMER_ENDPOINT_DOTSAML3SP
			+ "$," + "^/dotCMS/login.*$," + "^/html/portal/login.*$," + "^/c/public/login.*$,"
			+ "^/c/portal_public/login.*$," + "^/c/portal/logout.*$," + "^/dotCMS/logout.*$,"
			+ "^/application/login/login.*$," + "^/dotAdmin.*$";

	/**
	 * default logout path values
	 */
	public static final String DOT_SAML_LOGOUT_PATH_DEFAULT_VALUES = "/api/v1/logout,/c/portal/logout,/dotCMS/logout,/dotsaml/request/logout";

	/**
	 * Default SAML User role
	 */
	public static final String DOTCMS_SAML_USER_ROLE = "SAML User";
	
}
