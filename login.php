<html>
<head>
<title>Proof of work backed login page concept</title>
<meta charset="utf-8">
<body>

<?php

define('SERVER_SECRET', 'f8b5ad747742a8987b10'); // A static salt for the server nonce.  
define('NONCE_LIFE', 180); // How long a nonce is valid for
define('NONCE_CHANGE', 10); // How often to change the nonce. 
define('NONCE_LENGTH', 4);

function getServerNonce($timestamp = false, $length = NONCE_LENGTH){
	if($timestamp === false) $timestamp = time();

        //Round off to the last multiple of 10 seconds
        $seed = SERVER_SECRET.($timestamp - ($timestamp % NONCE_CHANGE));
	//get the first $length digits of the sha256 hash of the secret and hte timestamp,
	return substr(hash('sha256', $seed), 0, $length);
}

// Defaults to 3 minutes, 10 seconds each.
function getValidServerNonces($specific = false){
	$tmp = array();
	$timestamp = time();
	$timestamp = $timestamp - ($timestamp % NONCE_CHANGE);

	for($i = 0; $i < (int) (NONCE_LIFE); $i+=NONCE_CHANGE){
		$tmp[$timestamp] = getServerNonce($timestamp);
		if($specific !== false && $specific == $tmp[$timestamp]){
			return true;
			break;
		}
		$timestamp -= NONCE_CHANGE;

	}
	unset($timestamp);
	return $tmp;
}

if ( isset($_POST['username']) && isset($_POST['password']) && isset($_POST['cnonce']) && isset($_POST['nonce']) )
{
  // The usual quick and dirty sanitization
  $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
  $password = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_STRING);
  $client_nonce = filter_input(INPUT_POST, 'cnonce', FILTER_SANITIZE_NUMBER_INT);
  $server_nonce = filter_input(INPUT_POST, 'nonce', FILTER_SANITIZE_STRING);

  // Get these values from a database table
  $pw_hashes = array('meow' => '$2y$10$8LczTsopYizB3YPgO4VL0.T7U/NsEfLs.uiEYOsJPX31utOC5jHKG',
		     'evan' => '$2y$10$3DGUnd5s3Vk2s1PV1Yya6.r6XjpsB4CEEubjMczj18pbzUzng1wnS');

  // Check that the nonce we've been given is recent
  if (getValidServerNonces($server_nonce))
  {
	// Verify the nonce they gave us actually works
	$computed_hash = hash('sha256', $username . $password . $client_nonce);

	if (substr($computed_hash, 0, strlen($server_nonce)) === $server_nonce)
	{
		if (password_verify($password, $pw_hashes{$username}))
		{
			echo "Login successful for $username.<br />";
		} else {
			echo "Bad login.<br />";
		}
	} else {
		var_dump($server_nonce);
		var_dump(substr($computed_hash, 0, strlen($server_nonce)));
		var_dump($computed_hash);
		echo "Bad client nonce.<br />";
	}
  } else {
	echo "Bad server nonce.<br />";
  }
} else {

// Include inline login html
?>

<form name="login" method=POST>
<fieldset>
  <legend>Login to the darkweb</legend>
  <label for="username">Username</label><input type="text" name="username" id="username"><br />
  <label for="password">Password</label><input type="password" name="password" id="password"><br />
  <input type=hidden id="cnonce" name="cnonce">
  <input type=hidden id="nonce" name="nonce" value="<?php echo getServerNonce() ?>">
  <input type="button" name="prepare" value = "Prepare" id="prepare" onclick="update_nonce()">
  <input type="submit" name="submit" id="submit" style="display:none">
</fieldset>
</form>

<script src="sha256.js"></script>
<script>
function find_cnonce(username, password, nonce)
{
  var client_nonce = 0;
  var hash = '';
  while(! hash.startsWith(nonce)){
    client_nonce++;
    hash = Sha256.hash(username + password + client_nonce);
  }
  document.getElementById('cnonce').value = client_nonce;
  document.getElementById("prepare").style.display = 'none';
  document.getElementById("submit").style.display = '';
}

function update_nonce(){
  document.getElementById("username").disabled = true;
  document.getElementById("password").disabled = true;
  document.getElementById("prepare").disabled = true;
    find_cnonce(document.getElementById('username').value,
                document.getElementById('password').value,
                document.getElementById('nonce').value);
    return false;
}

</script>

<?php
} // end else
?>

</body></html>
