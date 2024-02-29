<?php
require("verify_login.php");

if(isset($_GET['logout']) AND $_GET['logout']=='y'){ //get the logout variable from login.php?logout=y
	global $salt,$sess_time,$dbu;
	if(isLoggedIn()){
		$user = isLoggedIn();
		$user_id = $user['id'];
		$dbnu = new PDO('sqlite:'.$dbu);
		$dbnu->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		$stmt = $dbnu->prepare('DELETE FROM active_users WHERE user_id = :user_id');
		$stmt->bindValue(":user_id",$user_id, PDO::PARAM_INT);
		$stmt->execute();
	}
}
if(isLoggedIn()){ // if is logged in, redirect to a script of choice and stop the script.
	$user=isLoggedIn();
	updateExpire($user['id']);
	header('location:'.$header_redirect);
	exit();
}

if(isset($_POST['submitButton'])){
	if (empty($_POST['user'])) {
		die('Error: user is required.');
			}
	elseif (empty($_POST['password'])) {
		die('Error: password is required.');
		}
    $password=$_POST['password'];
    $dbnu = new PDO('sqlite:'.$dbu);
	$dbnu->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	$stmt = $dbnu->prepare('SELECT * FROM users WHERE username = :username LIMIT 1');
	$stmt->bindParam(":username",$_POST['user'], PDO::PARAM_STR);
	$stmt->execute();
	$row = $stmt->fetch(PDO::FETCH_ASSOC);
	if(!empty($row)) {
        if (password_verify($password, $row['password'])) {
        $sessID = SQLite3::escapeString(session_id());
        $hash= SQLite3::escapeString(hash("sha512",$sessID.$_SERVER['HTTP_USER_AGENT']));
        $expires = time()+$sess_time;
        //$dbnu->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $stmt = $dbnu->prepare('INSERT INTO active_users (user_id,session_id,hash,expires) VALUES (:user_id,:session_id, :hash, :expires)');
        $stmt->bindParam(":user_id",$row['id'], PDO::PARAM_INT);
        $stmt->bindParam(":session_id",$sessID, PDO::PARAM_STR);
        $stmt->bindParam(":hash",$hash, PDO::PARAM_STR);
        $stmt->bindParam(":expires",$expires, PDO::PARAM_INT);
        $stmt->execute();
        header('Location:'.$_SERVER["PHP_SELF"]);
        exit();
        }
	}
    echo '<h1>Error:Your login credentials are wrong</h1>';
}
if (!isLoggedIn()) { //show login form if not logged in
?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
    </head>
    <style>
        .center {
            margin: auto;
            width: 50%;
            padding: 10px;
        }
    </style>
    <body>


    <form id="login" method="post" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
        <div style="margin-left:42%">
            <div class="">
                <h2>Login Form</h2>
                <form id="login" method="post" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
                    <label for="user">User</label>:<input type="text" name="user" id="user"><br>
                    <label for="password">Password</label>:<input type="password" name="password" id="password"><br>
                    <input type="submit" name="submitButton" id="submitButton" value="LOGIN">
            </div>
        </div>
    </form>

    </body>
    </html>

<?php } ?>