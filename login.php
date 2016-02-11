<html>
<head>
<title>Proof of work backed login page concept</title>
<meta charset="utf-8">
<body>

<?php
if ( isset($_POST['username']) && isset($_POST['password']) && isset($_POST['cnonce']) && isset($_POST['nonce']) )
{
  // The usual quick and dirty sanitization
  $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
  $password = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_STRING);
  $client_nonce = filter_input(INPUT_POST, 'cnonce', FILTER_SANITIZE_NUMBER_INT);
  $server_nonce = filter_input(INPUT_POST, 'nonce', FILTER_SANITIZE_NUMBER_INT);

  // Get these values from a database table
  $valid_server_nonce = array("00001", "00000", "00002");
  $pw_hashes = array('meow' => '$2y$10$8LczTsopYizB3YPgO4VL0.T7U/NsEfLs.uiEYOsJPX31utOC5jHKG',
		     'evan' => '$2y$10$3DGUnd5s3Vk2s1PV1Yya6.r6XjpsB4CEEubjMczj18pbzUzng1wnS');

  // Check that the nonce we've been given is recent
  if (in_array($server_nonce, $valid_server_nonce))
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
		echo "Bad client nonce.<br />";
	}
  } else {
	echo "Bad server nonce.<br />";
  }
} else {
  // Get this value from a database table
  $latest_nonce = "00000";

// Include inline login html
?>

<form name="login" method=POST>
<fieldset>
  <legend>Login to the darkweb</legend>
  <label for="username">Username</label><input type="text" name="username" id="username"><br />
  <label for="password">Password</label><input type="password" name="password" id="password"><br />
  <input type=hidden id="cnonce" name="cnonce">
  <input type=hidden id="nonce" name="nonce" value="<?php echo $latest_nonce; ?>">
  <button onclick="update_nonce()">Login</button><br />
</fieldset>
<input type="submit" name="submit" id="submit" style="visibility: hidden;" disabled>
</form>

<script src="sha256.js"></script>
<script>
function find_cnonce(username, password, nonce)
{
  var client_nonce = 0;
  var hash = Sha256.hash(username + password + client_nonce);
  while(! hash.startsWith(nonce))
  {
	client_nonce++;
	hash = Sha256.hash(username + password + client_nonce);
  }
  return client_nonce;
}

function update_nonce()
{
  var found_cnonce = find_cnonce(document.getElementById('username').value,
  	   		         document.getElementById('password').value,
			         document.getElementById('nonce').value);
  document.getElementById('cnonce').value = found_cnonce;
  document.getElementById('submit').disabled = false;
}

</script>

<?php
} // end else
?>

</body></html>
