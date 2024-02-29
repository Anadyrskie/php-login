<?php
require("login_config.php");
session_start();//start a session



function isLoggedIn()
{

    //check if a user is logged in and return false or
    global $dbu;
    if (isset($_REQUEST['auth'])) {
        if (verifyApiKey($dbu, $_REQUEST['auth'])) {
            return true;
        } else {
            http_response_code(403);
            die("Forbidden");
        }
    }
    else {
        $sessID = SQLite3::escapeString(session_id());
        $hash = SQLite3::escapeString(hash("sha512", $sessID . $_SERVER['HTTP_USER_AGENT']));
        $dbnu = new PDO('sqlite:' . $dbu);
        $dbnu->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $stmt = $dbnu->prepare('SELECT user_id FROM active_users WHERE session_id = :sessID AND hash = :hash AND expires>' . time() . ' LIMIT 1');
        $stmt->bindValue(":sessID", $sessID, PDO::PARAM_STR);
        $stmt->bindValue(":hash", $hash, PDO::PARAM_STR);
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (empty($row)) {
            return false;
        } else {
            $user_id = $row['user_id'];
            $stmt = $dbnu->prepare('SELECT * FROM users WHERE id = :user_id LIMIT 1');
            $stmt->bindValue(":user_id", $user_id, PDO::PARAM_STR);
            $stmt->execute();
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            $user = $row;
            return $user;
        }
    }
}

function updateExpire($user)
{ //if session is valid, update expiration time to additional $sess_time
    global $sess_time, $dbu;
    $expires = time() + $sess_time;
    $dbnu = new PDO('sqlite:' . $dbu);
    $dbnu->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $stmt = $dbnu->prepare('UPDATE active_users SET expires=:expires WHERE session_id=:session_id AND user_id=:user_id');
    $stmt->bindValue(":expires", $expires, PDO::PARAM_INT);
    $stmt->bindValue(":session_id", session_id(), PDO::PARAM_STR);
    $stmt->bindValue(":user_id", $user, PDO::PARAM_INT);
    $stmt->execute();
}

function verifyApiKey($dbu, $key): bool {
    $key = urldecode($key);
    $key = SQLite3::escapeString($key);
    $dbnu = new PDO('sqlite:' . $dbu);
    $dbnu->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $stmt = $dbnu->prepare('SELECT * FROM api_keys WHERE key = :key LIMIT 1');
    $stmt->bindParam(":key", $key, PDO::PARAM_STR);
    $stmt->execute();
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (empty($row)) {
        return false;
    } else {
        return true;
    }
}

