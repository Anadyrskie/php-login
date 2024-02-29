<?php
$dbu = realpath(__DIR__) . '/users.db'; //database location
$sess_time = 60 * 60 * 4; //session expires in seconds before user has to login again.
$header_redirect = "index.php"; //redirect after accessful login