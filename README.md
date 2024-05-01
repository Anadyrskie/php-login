# PHP Login System
This is a simple login system for PHP. It uses a SQLite database to store user information, and has a simple API key system for use with other applications. It comes with a user management panel, and a simple login page.


## Usage
add this code to anything that needs authentication. adjust the path to the `verify_login.php` file if necessary.
```php
require("verify_login.php");
$user=isLoggedIn();if($user){ updateExpire($user['id']); } else{ header('location:login.php'); }
```

## Config
You can change the login redirect in `login_config.php` if needed. Default is `index.php`.
You can also change the session timeout in `login_config.php`. Default is 4 hours.

## Users
You can manage users in the Userman panel (`userman.php`). Only user type 0 can access userman.php. Only user type 0 can access userman.php. This can be changed in `userman.php` if needed.

### User Types
Users have an integer user type. You can use this for permissions, to restrict access for example, or change the appearance of the page based on the user type.


### Userman
Userman is a simple user management panel. It allows you to add, edit, and delete users. It also allows you to change the password of a user, and change the user type.
You probably want to restrict this to admins.
```php
$permission_level = $user['user_type'] ?? 1;
<nav>
<?php
if ($permission_level == 0) {
        echo "<button type='button' onclick='" . 'window.location.href="userman.php"' . "'>Userman</button>";
    } ?>
    </nav>
```

## API Keys
You can manage API keys in the Userman panel (`userman.php`). 
### Usage
Pass the API key in the `auth` parameter of the request.
e.g. `http://example.com/index.php?auth=APIKEY`

### Security
API keys do not currently have permission scoping, so they can access everything. API Key authentication returns a bool, so if the key is used to access a page that depends on $user variables, the page will crash. This can be fixed by returning a predefined bot user block if needed in the `verify_login.php` file.

```php
function isLoggedIn()
{
$bot = array("id" => 0, "name" => "api", "username" => "api", "password" => "", "user_type" => 0);

    //check if a user is logged in and return false or
    global $dbu;
    if (isset($_REQUEST['auth'])) {
        if (verifyApiKey($dbu, $_REQUEST['auth'])) {
            return $bot;
        } else {
            http_response_code(403);
            die("Forbidden");
        }
    }
    else {
    // ... rest of the function
```

## Reset
`resetDB.sqlite` contains the script to reset the database to factory.