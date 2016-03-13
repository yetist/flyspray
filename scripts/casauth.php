<?php

  /********************************************************\
  | CAS authentication (no output)                        |
  | ~~~~~~~~~~~~~~~~~~~                                    |
  \********************************************************/

if (!defined('IN_FS')) {
    die('Do not access this file directly.');
}

if (! isset($_SESSION['return_to'])) {
    $_SESSION['return_to'] = base64_decode(Get::val('return_to', ''));
    $_SESSION['return_to'] = $_SESSION['return_to'] ?: $baseurl;
}

$return_to = $_SESSION['return_to'];
unset($_SESSION['return_to']);

function checkCASAttrs($user_details)
{
	if (strlen($user_details['email']) <= 0) {
		Flyspray::show_error(27);
	}else if (strlen($user_details['username']) <= 0) {
		Flyspray::show_error(27);
	}else if (strlen($user_details['user_id']) <= 0) {
		Flyspray::show_error(27);
	}
}

if (Req::val('logout')) {
	$cas->logout($return_to);
}

$cas->authenticate($return_to);
$user_details = $cas->userDetails();
checkCASAttrs($user_details);

$cas_uid = $user_details['user_id'];
$provider = $user_details['authenticated_by'];
$username = $user_details['username'];

// First time logging in
if (! Flyspray::checkForOauthUser($cas_uid, $provider)) {
	$email = $user_details['email'];
	$full_name = $user_details['last_name'].$user_details['first_name'];
	$real_name = $full_name ? $full_name : $username;

	if ($cas_uid === "1") {
		$group_in = "1";
	}else{
		$group_in = $fs->prefs['anon_group'];
	}
	$fs_uid = Flyspray::UserNameToId($username);
	if ( $fs_uid > 0 ) {
		// If username already exists, update 'users' table
		$db->Query('UPDATE {users} SET user_name = ?, email_address=?, real_name = ?, oauth_uid = ?, oauth_provider = ? WHERE user_id = ?',
			array($username, $email, $real_name, $cas_uid, $provider, $fs_uid));
		// and insert data in 'user_emails' table.
                $db->Query("INSERT INTO {user_emails}(id,email_address,oauth_uid,oauth_provider) VALUES (?,?,?,?)",
                        array($fs_uid, strtolower($email), $cas_uid, $provider));
	} else {
		Backend::create_user($username, null, $real_name, '', $email, 0, 0, $group_in, 1, $cas_uid, $provider);
	}
}

if (($user_id = Flyspray::checkLogin($username, null, 'oauth')) < 1) {
    Flyspray::show_error(23); // account disabled
}

$user = new User($user_id);

// Set a couple of cookies
$passweirded = crypt($user->infos['user_pass'], $conf['general']['cookiesalt']);
Flyspray::setCookie('flyspray_userid', $user->id, 0,null,null,null,true);
Flyspray::setCookie('flyspray_passhash', $passweirded, 0,null,null,null,true);
$_SESSION['SUCCESS'] = L('loginsuccessful');

Flyspray::Redirect($return_to);
?>
