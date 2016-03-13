<?php
/**
 * FSCAS
 *
 * FS CAS class
 */

if (!defined('IN_FS')) {
	die('Do not access this file directly.');
}

defined("CAS_VERSION_1_0") or define("CAS_VERSION_1_0", '1.0');
defined("CAS_VERSION_2_0") or define("CAS_VERSION_2_0", '2.0');
defined("CAS_VERSION_3_0") or define("CAS_VERSION_3_0", '3.0');
defined("SAML_VERSION_1_1") or define("SAML_VERSION_1_1", 'S1');

class FSCAS
{
	// Get the CAS server version (default to SAML_VERSION_1_1).
	// See: https://developer.jasig.org/cas-clients/php/1.3.4/docs/api/group__public.html
	private static $version = SAML_VERSION_1_1;
	private static $host = "";
	private static $port = 443;
	private static $context = "/cas";

	private static $cert_url = "http://curl.haxx.se/ca/cacert.pem";
	private static $cert_path = BASEDIR . "/cache/cacert.pem";

	private static $attr_email = "";
	private static $attr_first_name = "";
	private static $attr_last_name = "";
	private static $attr_user_id = "";

	public function __construct()
	{
		global $conf;

		//phpCAS::setDebug();
		if (isset( $conf['cas']['cas_host']) && strlen( $conf['cas']['cas_host'] ) > 0 ) {
			self::$host = $conf['cas']['cas_host'];
		}

		if (isset( $conf['cas']['cas_context']) && strlen( $conf['cas']['cas_context'] ) > 0 ) {
			self::$context = $conf['cas']['cas_context'];
		}

		if (isset( $conf['cas']['cas_version']) && strlen( $conf['cas']['cas_version'] ) > 0 ) {
			if ( $conf['cas']['cas_version'] === 'CAS_VERSION_3_0' ) {
				self::$version = CAS_VERSION_3_0;
			} else if ( $conf['cas']['cas_version'] === 'CAS_VERSION_2_0' ) {
				self::$version = CAS_VERSION_2_0;
			} else if ( $conf['cas']['cas_version'] === 'CAS_VERSION_1_0' ) {
				self::$version = CAS_VERSION_1_0;
			}
		}

		if (isset( $conf['cas']['cas_port']) && strlen( $conf['cas']['cas_port'] ) > 0 ) {
			self::$port = intval($conf['cas']['cas_port']);
		}

		if (isset( $conf['cas']['cas_server_ca_cert_url']) && strlen( $conf['cas']['cas_server_ca_cert_url'] ) > 0 ) {
			self::$cert_url = $conf['cas']['cas_server_ca_cert_url'];
		}

		if (isset( $conf['cas']['cas_server_ca_cert_path']) && strlen( $conf['cas']['cas_server_ca_cert_path'] ) > 0 ) {
			self::$cert_path = $conf['cas']['cas_server_ca_cert_path'];
		}

		if (isset( $conf['cas']['cas_attr_email']) && strlen( $conf['cas']['cas_attr_email'] ) > 0 ) {
			self::$attr_email = $conf['cas']['cas_attr_email'];
		}

		if (isset( $conf['cas']['cas_attr_first_name']) && strlen( $conf['cas']['cas_attr_first_name'] ) > 0 ) {
			self::$attr_first_name = $conf['cas']['cas_attr_first_name'];
		}

		if (isset( $conf['cas']['cas_attr_last_name']) && strlen( $conf['cas']['cas_attr_last_name'] ) > 0 ) {
			self::$attr_last_name = $conf['cas']['cas_attr_last_name'];
		}

		if (isset( $conf['cas']['cas_attr_user_id']) && strlen( $conf['cas']['cas_attr_user_id'] ) > 0 ) {
			self::$attr_user_id = $conf['cas']['cas_attr_user_id'];
		}
	}

	public function available()
	{
		return (strlen(self::$host) > 0 && strlen(self::$attr_email) > 0 && strlen(self::$attr_user_id) > 0);
	}

	public function init()
	{
		if (!$this->available()) {
			return;
		}
		$time_90_days = 90 * 24 * 60 * 60; // days * hours * minutes * seconds
		$time_90_days_ago = time() - $time_90_days;
		if ( ! file_exists( self::$cert_path ) || filemtime( self::$cert_path ) < $time_90_days_ago ) {
			$cert_contents = file_get_contents(self::$cert_url);
			if ( $cert_contents !== false ) {
				file_put_contents( self::$cert_path, $cert_contents );
			} else {
				Flyspray::show_error('Unable to update outdated server certificates.');
				return false;
			}
		}
		// Set the CAS client configuration
		phpCAS::client( self::$version, self::$host, self::$port, self::$context);
		phpCAS::setCasServerCACert( self::$cert_path );
	}

	public function authenticate($return_to)
	{
		// Authenticate against CAS
		try {
			if ( ! phpCAS::isAuthenticated() ) {
				phpCAS::forceAuthentication();
				die();
			}
		} catch ( CAS_AuthenticationException $e ) {
			// CAS server threw an error in isAuthenticated(), potentially because
			// the cached ticket is outdated. Try renewing the authentication.
			try {
				phpCAS::renewAuthentication();
			} catch ( CAS_AuthenticationException $e ) {
				Flyspray::show_error('CAS server returned an Authentication Exception.');
				phpCAS::logoutWithRedirectService( $return_to);
				die();
			}
		}
	}

	function userDetails()
	{
		global $conf;

		// Get the TLD from the CAS host for use in matching email addresses
		// For example: example.edu is the TLD for authn.example.edu, so user
		// 'bob' will have the following email address: bob@example.edu.
		$tld = preg_match( '/[^.]*\.[^.]*$/', self::$host, $matches ) === 1 ? $matches[0] : '';

		// Get username that successfully authenticated against the external service (CAS).
		$externally_authenticated_email = strtolower( phpCAS::getUser() ) . '@' . $tld;

		// Retrieve the user attributes (e.g., email address, first name, last name) from the CAS server.
		$cas_attributes = phpCAS::getAttributes();

		// If a CAS attribute has been specified as containing the email address, use that instead.
		// Email attribute can be a string or an array of strings.
		if (
			array_key_exists(self::$attr_email, $cas_attributes )
			&& (
				(
					is_array($cas_attributes[self::$attr_email])
					&& count($cas_attributes[self::$attr_email]) > 0
				) || (
					is_string($cas_attributes[self::$attr_email])
					&& strlen($cas_attributes[self::$attr_email]) > 0
				)
			)
		)
		{
			$externally_authenticated_email = $cas_attributes[self::$attr_email];
		}

		// Get username (as specified by the CAS server).
		$username = phpCAS::getUser();
		if (strlen($username) <= 0) {
			Flyspray::show_error('Check your cas config, "username" attritube is required');
		}

		// Get user first name and last name.
		$first_name = strlen(self::$attr_first_name) > 0
			&& array_key_exists( self::$attr_first_name, $cas_attributes )
			&& strlen( $cas_attributes[self::$attr_first_name] ) > 0 ? $cas_attributes[self::$attr_first_name] : '';

		$last_name = strlen( self::$attr_last_name) > 0
			&& array_key_exists( self::$attr_last_name, $cas_attributes )
			&& strlen( $cas_attributes[self::$attr_last_name] ) > 0 ? $cas_attributes[self::$attr_last_name] : '';

		$user_id = array_key_exists( self::$attr_user_id, $cas_attributes )
			&& strlen( $cas_attributes[self::$attr_user_id] ) > 0 ? $cas_attributes[self::$attr_user_id] : '';

		return array(
			'email' => $externally_authenticated_email,
			'username' => $username,
			'first_name' => $first_name,
			'last_name' => $last_name,
			'user_id' => $user_id,
			'authenticated_by' => 'cas',
		);
	}

	public function logout($return_to)
	{
		global $user;

		$user->logout();
		phpCAS::logoutWithRedirectService($return_to);
		Flyspray::Redirect($return_to);
	}

	public function authsync()
	{
		global $user, $baseurl, $conf;

		if (!$this->available()) {
			return;
		}
		$return_to = base64_decode(Get::val('return_to', ''));
		if (strlen($return_to) <= 0) {
			$return_to = $baseurl;
		}

		/* user has been logout from cas server */
		if (!$user->isAnon() && !phpCAS::checkAuthentication()) {
			$this->logout($return_to);
		} else if ($user->isAnon() && phpCAS::checkAuthentication()) {
			/* user has been login from cas server */
			$user_details = $this->userDetails();
			$username = $user_details['username'];
			if (($user_id = Flyspray::checkLogin($username, null, 'oauth')) > 0) {
				// user has already created for flyspray.
				$user = new User($user_id);
				// Set a couple of cookies
				$passweirded = crypt($user->infos['user_pass'], $conf['general']['cookiesalt']);
				Flyspray::setCookie('flyspray_userid', $user->id, 0,null,null,null,true);
				Flyspray::setCookie('flyspray_passhash', $passweirded, 0,null,null,null,true);
			}
		}
	}
}
