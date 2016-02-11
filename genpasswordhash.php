<?php
echo "Password hash: " . password_hash($argv[1], PASSWORD_BCRYPT) . "\n";
?>
