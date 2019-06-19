<?php

namespace Baikal\Core;

/**
 * This is an authentication backend that uses a database to manage passwords.
 *
 * Format of the database tables must match to the one of \Sabre\DAV\Auth\Backend\PDO
 *
 * @copyright Copyright (C) 2013 Lukasz Janyst. All rights reserved.
 * @author Lukasz Janyst <ljanyst@buggybrain.net>
 * @license http://code.google.com/p/sabredav/wiki/License Modified BSD License
 */
class PDOBasicAuth extends \Sabre\DAV\Auth\Backend\AbstractBasic {

    /**
     * Reference to PDO connection
     *
     * @var PDO
     */
    protected $pdo;

    /**
     * PDO table name we'll be using
     *
     * @var string
     */
    protected $tableName;

    /**
     * Authentication realm
     *
     * @var string
     */
    protected $authRealm;

    /**
     * Creates the backend object.
     *
     * If the filename argument is passed in, it will parse out the specified file fist.
     *
     * @param PDO $pdo
     * @param string $tableName The PDO table name to use
     */
    function __construct(\PDO $pdo, $authRealm, $tableName = 'users') {

        $this->pdo = $pdo;
        $this->tableName = $tableName;
        $this->authRealm = $authRealm;
    }

    /**
     * Validates a username and password
     *
     * This method should return true or false depending on if login
     * succeeded.
     *
     * @param string $username
     * @param string $password
     * @return bool
     */
    function validateUserPass($username, $password) {

        error_log("Inside validateUserPass");
        /*
        try {
            $url = "http://localhost:8081/validateUserPass";

            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_TIMEOUT, 30); //timeout after 30 seconds
            curl_setopt($ch, CURLOPT_RETURNTRANSFER,1);
            curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
            curl_setopt($ch, CURLOPT_USERPWD, "$username:$password");
            
            //curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
            $output = curl_exec($ch);
            $status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);   //get status code
            curl_close($ch);
            if ($status_code === 200) {
                return true;
            }
            else
            {
                return false;
            }
        } catch(Exception $e) {
        
            trigger_error(sprintf(
                'Curl failed with error #%d: %s',
                $e->getCode(), $e->getMessage()),
                E_USER_ERROR);
        }
        */

        $stmt = $this->pdo->prepare('SELECT username, digesta1 FROM ' . $this->tableName . ' WHERE username = ?');
        $stmt->execute([$username]);
        $result = $stmt->fetchAll();


        if (!count($result)) return false;

        $hash = md5($username . ':' . $this->authRealm . ':' . $password);
        if ($result[0]['digesta1'] === $hash)
        {
            $this->currentUser = $username;
            return true;
        }
        return false;
    }

}
