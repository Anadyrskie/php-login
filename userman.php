<?php
global $dbu;
require("verify_login.php");
if(isLoggedIn()){
    $user=isLoggedIn();
    if (is_array($user)) {
        updateExpire($user['id']);
        // Change this if you want to allow other user types to access this page
        if ($user['user_type'] != 0) {
            echo "You do not have permission to access this page.";
            echo "<a href='index.php' type='button'>Home</a>";
            exit();
        }
    }
} else{ header('location:login.php'); }

function getApiKeys($dbu) {
    $dbnu = new PDO('sqlite:' . $dbu);
    $dbnu->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $stmt = $dbnu->prepare('SELECT * FROM api_keys');
    $stmt->execute();
    $api_keys = $stmt->fetchAll(PDO::FETCH_ASSOC);
    return $api_keys;
}

function deleteApiKey($dbu, $id) {
    $dbnu = new PDO('sqlite:' . $dbu);
    $dbnu->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $stmt = $dbnu->prepare('DELETE FROM api_keys WHERE id = :id');
    $stmt->bindParam(":id", $id, PDO::PARAM_INT);
    $stmt->execute();
}

function createApiKey($dbu, $name) {
    $key = bin2hex(random_bytes(32));
    $dbnu = new PDO('sqlite:' . $dbu);
    $dbnu->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $stmt = $dbnu->prepare('INSERT INTO api_keys (name, key) VALUES (:name, :key)');
    $stmt->bindParam(":name", $name, PDO::PARAM_STR);
    $stmt->bindParam(":key", $key, PDO::PARAM_STR);
    $stmt->execute();
}
function getUsers($dbu) {
    $dbnu = new PDO('sqlite:' . $dbu);
    $dbnu->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $stmt = $dbnu->prepare('SELECT * FROM users');
    $stmt->execute();
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
    return $users;
}



function createUser($dbu, $username, $password, $user_type, $name) {
    $passwordHash = password_hash($password, PASSWORD_DEFAULT);
    $dbnu = new PDO('sqlite:' . $dbu);
    $dbnu->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $stmt = $dbnu->prepare('INSERT INTO users (name, username, password, user_type) VALUES (:name, :username, :password, :user_type)');
    $stmt->bindParam(":name", $name, PDO::PARAM_STR);
    $stmt->bindParam(":username", $username, PDO::PARAM_STR);
    $stmt->bindParam(":password", $passwordHash, PDO::PARAM_STR);
    $stmt->bindParam(":user_type", $user_type, PDO::PARAM_STR);
    $stmt->execute();
}

function deleteUser($dbu, $id) {
    $dbnu = new PDO('sqlite:' . $dbu);
    $dbnu->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $stmt = $dbnu->prepare('DELETE FROM users WHERE id = :id');
    $stmt->bindParam(":id", $id, PDO::PARAM_INT);
    $stmt->execute();
    deleteSession($dbu, $id);
}

function updateUser($dbu, $id, $username, $password, $user_type, $name) {
    $dbnu = new PDO('sqlite:' . $dbu);
    $dbnu->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $query = 'UPDATE users SET';
    $params = array();

    if ($name) {
        $query .= ' name = :name,';
        $params[':name'] = $name;
    }
    if ($username) {
        $query .= ' username = :username,';
        $params[':username'] = $username;
    }
    if ($password) {
        $query .= ' password = :password,';
        $params[':password'] = password_hash($password, PASSWORD_DEFAULT);
    }
    if (isset($user_type)) {
        $query .= ' user_type = :user_type,';
        $params[':user_type'] = $user_type;
    }
    // Remove the trailing comma
    $query = rtrim($query, ',');
    $query .= ' WHERE id = :id';
    $params[':id'] = $id;

    $stmt = $dbnu->prepare($query);
    foreach ($params as $param => &$value) {
        $stmt->bindParam($param, $value);
    }
    $stmt->execute();
    deleteSession($dbu, $id);
}

function deleteSession($dbu, $user_id) {
    $dbnu = new PDO('sqlite:' . $dbu);
    $dbnu->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $stmt = $dbnu->prepare('DELETE FROM active_users WHERE user_id = :user_id');
    $stmt->bindParam(":user_id", $user_id, PDO::PARAM_INT);
    $stmt->execute();
}


if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if(isset($_POST['createUser'])) {
        if(!isset($_POST['username']) || !isset($_POST['password']) || !isset($_POST['user_type'])) {
            echo json_encode($_POST);
            die('Error: All fields are required.');
        }
        createUser($dbu, $_POST['username'], $_POST['password'], $_POST['user_type'], $_POST['name']);
    }
    elseif(isset($_POST['deleteUser'])) {
        if(!isset($_POST['id'])) {
            die('Error: ID is required.');
        }
        deleteUser($dbu, $_POST['id']);
    }
    elseif(isset($_POST['updateUser'])) {
        if(!isset($_POST['id'])) {
            die('Error: User ID is required.');
        }
        updateUser($dbu, $_POST['id'], $_POST['username'], $_POST['password'], $_POST['user_type'], $_POST['name']);
    }
    elseif(isset($_POST['createApiKey'])) {
        createApiKey($dbu, $_POST['name']);
    }
    elseif(isset($_POST['deleteApiKey'])) {
        if(!isset($_POST['id'])) {
            die('Error: ID is required.');
        }
        deleteApiKey($dbu, $_POST['id']);
    }
    else {
        echo("Error: Invalid request");
    }
}
?>
<!DOCTYPE html>
    <html lang="en">
<head><style>
        table {
            border-collapse:collapse;
        }
        tr {
            border:none;
        }
        th {
            border-bottom: black solid 1px;
        }
        th, td {
            border-collapse:collapse;
            padding-top:2px;
            padding-bottom:2px;
        }

        .verticalSplit {
            padding-right:5px;
            padding-left:5px;
            border: 1px solid black;
            border-top:none;
            /*border-bottom: gray dotted 1px;*/
            border-bottom: none;
        }
        .verticalSplit:first-of-type {
            border-left:none;
        }
        .verticalSplit:last-of-type {
            border-right:none;
        }
        input {
            border: 1px solid black!important;
        }
    </style></head>
        <body>
        <script>
            function deleteUser() {

            }
        </script>
            <h2>User Management</h2>
        <button type="button" onclick="window.location.href='index.php'">Home</button>
        <button type="button" onclick="window.location.href='userman.php'">Reload</button>
            <table style="margin-top: 10px">
            <thead>

            </thead>
                <tbody>
                <tr>
                    <th>Name</th>
                    <th>Username</th>
                    <th>Password</th>
                    <th>Permission Level</th>
                </tr>
            <?php
            global $dbu;
                $users = getUsers($dbu);
                foreach ($users as $user) {
                        ?>
                            <tr>
                                <form method="post" action="userman.php">
                                <td><input name="name" id="name" type="text" value="<?= $user["name"] ?>" class="verticalSplit"></input></td>
                                    <td><input name="username" id="username" type="text" value="<?= $user["username"] ?>" class="verticalSplit"></input></td>
                                    <td><input name="password" id="password" type="password" class="verticalSplit"></input></td>
                                    <td><input name="user_type" id="user_type" type="text" value="<?= $user["user_type"] ?>" class="verticalSplit"></input></td>
                                    <td><input  name="id" style="border: black" type="hidden" value="<?=$user['id']?>" /></td>
                                    <td><button type="submit" name="updateUser">Update</button></td>
                                    <td><button type="submit" name="deleteUser">Delete</button></td>
                                </form>
                            </tr>
                    <?php }
                ?>
                </tbody>
            </table>
        <table>
            <form method="post" action="userman.php">
                <tr>
                    <td><input id="name" name="name" type="text" class="verticalSplit"></input></td>
                    <td><input id="username" name="username" type="text" class="verticalSplit"></input></td>
                    <td><input id="password" name="password" type="password" class="verticalSplit"></input></td>
                    <td><input id="user_type" name="user_type" type="text" class="verticalSplit"></input></td>
                    <td><button type="submit" name="createUser">Create</button></td>
            </form>
        </table>
        <br />
        <h2>API Keys</h2>
        <table>
            <th>Name</th>
            <th>Key</th>
            <th>Action</th>
            <?php
            $api_keys = getApiKeys($dbu);
            // foreach form to list api keys and delete each line
            foreach ($api_keys as $api_key) {
                ?>
                <form method="post" action="userman.php">
                    <tr>
                        <td><?=$api_key['name']?></td>
                        <td style="padding-right:10px;"><?=$api_key['key']?></td>
                        <td><button type="submit" name="deleteApiKey">Delete</button></td>
                    </tr>
                    <input name="id" type="hidden" value="<?= $api_key['id'] ?>" />

                </form>
                <?php
            }

            ?>
            <form method="post" action="userman.php">
                <tr>
                    <td><input id="name" name="name" type="text" class="verticalSplit"></input></td>
                    <td><button type="submit" name="createApiKey">Create</button></td>
                </tr>
        </body>
    </html>

