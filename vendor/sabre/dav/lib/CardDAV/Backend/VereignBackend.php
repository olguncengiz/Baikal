<?php

namespace Sabre\CardDAV\Backend;

use Sabre\CardDAV;
use Sabre\DAV;

ini_set("log_errors", 1);
error_reporting(E_ALL);

/**
 * Vereign CardDAV backend
 *
 * This CardDAV backend uses Vereign carddav-agent to store addressbooks
 *
 * @copyright Copyright (C) Vereign AG (http://www.vereign.com/)
 * @author Olgun Cengiz
 * @license AGPLv3+
 */
class VereignBackend extends AbstractBackend {

    /**
     * HTTP connection URL
     */
    protected $url;

    /**
     * The PDO table name used to store addressbooks
     */
    public $addressBooksTableName = 'addressbooks';

    /**
     * The PDO table name used to store cards
     */
    public $cardsTableName = 'cards';

    /**
     * The table name that will be used for tracking changes in address books.
     *
     * @var string
     */
    public $addressBookChangesTableName = 'addressbookchanges';

    /**
     * Sets up the object
     *
     * @param string $url
     */
    function __construct(string $url) {

        $this->url = $url;

    }

    /**
     * Returns the list of addressbooks for a specific user.
     *
     * @param string $principalUri
     * @return array
     */
    function getAddressBooksForUser($principalUri) {
        //error_log("getAddressBooksForUser", 0);

        /*
        $stmt = $this->pdo->prepare('SELECT id, uri, displayname, principaluri, description, synctoken FROM ' . $this->addressBooksTableName . ' WHERE principaluri = ?');
        $stmt->execute([$principalUri]);
        */

        $addressBooks = [];

        $addressBooks[] = [
            'id'                                                          => 1, //$row['id'],
            'uri'                                                         => "principals", //$row['uri'],
            'principaluri'                                                => $principalUri, //$row['principaluri'],
            '{DAV:}displayname'                                           => "Default Addressbook", //$row['displayname'],
            '{' . CardDAV\Plugin::NS_CARDDAV . '}addressbook-description' => "Default Addressbook for Vereign", //$row['description'],
            '{http://calendarserver.org/ns/}getctag'                      => 4, //$row['synctoken'],
            '{http://sabredav.org/ns}sync-token'                          => 4, //$row['synctoken'] ? $row['synctoken'] : '0',
        ];

        return $addressBooks;

    }


    /**
     * Updates properties for an address book.
     *
     * The list of mutations is stored in a Sabre\DAV\PropPatch object.
     * To do the actual updates, you must tell this object which properties
     * you're going to process with the handle() method.
     *
     * Calling the handle method is like telling the PropPatch object "I
     * promise I can handle updating this property".
     *
     * Read the PropPatch documenation for more info and examples.
     *
     * @param string $addressBookId
     * @param \Sabre\DAV\PropPatch $propPatch
     * @return void
     */
    function updateAddressBook($addressBookId, \Sabre\DAV\PropPatch $propPatch) {

        error_log("updateAddressBook", 0);

        /*$supportedProperties = [
            '{DAV:}displayname',
            '{' . CardDAV\Plugin::NS_CARDDAV . '}addressbook-description',
        ];

        $propPatch->handle($supportedProperties, function($mutations) use ($addressBookId) {

            $updates = [];
            foreach ($mutations as $property => $newValue) {

                switch ($property) {
                    case '{DAV:}displayname' :
                        $updates['displayname'] = $newValue;
                        break;
                    case '{' . CardDAV\Plugin::NS_CARDDAV . '}addressbook-description' :
                        $updates['description'] = $newValue;
                        break;
                }
            }
            $query = 'UPDATE ' . $this->addressBooksTableName . ' SET ';
            $first = true;
            foreach ($updates as $key => $value) {
                if ($first) {
                    $first = false;
                } else {
                    $query .= ', ';
                }
                $query .= ' `' . $key . '` = :' . $key . ' ';
            }
            $query .= ' WHERE id = :addressbookid';

            $stmt = $this->pdo->prepare($query);
            $updates['addressbookid'] = $addressBookId;

            $stmt->execute($updates);

            $this->addChange($addressBookId, "", 2);

            return true;

        });*/
        return true;

    }

    /**
     * Creates a new address book
     *
     * @param string $principalUri
     * @param string $url Just the 'basename' of the url.
     * @param array $properties
     * @return int Last insert id
     */
    function createAddressBook($principalUri, $url, array $properties) {
        //error_log("createAddressBook", 0);

        /*
        $values = [
            'displayname'  => null,
            'description'  => null,
            'principaluri' => $principalUri,
            'uri'          => $url,
        ];

        foreach ($properties as $property => $newValue) {

            switch ($property) {
                case '{DAV:}displayname' :
                    $values['displayname'] = $newValue;
                    break;
                case '{' . CardDAV\Plugin::NS_CARDDAV . '}addressbook-description' :
                    $values['description'] = $newValue;
                    break;
                default :
                    throw new DAV\Exception\BadRequest('Unknown property: ' . $property);
            }

        }

        $query = 'INSERT INTO ' . $this->addressBooksTableName . ' (uri, displayname, description, principaluri, synctoken) VALUES (:uri, :displayname, :description, :principaluri, 1)';
        $stmt = $this->pdo->prepare($query);
        $stmt->execute($values);
        return $this->pdo->lastInsertId();
        */
        return 0;

    }

    /**
     * Deletes an entire addressbook and all its contents
     *
     * @param int $addressBookId
     * @return void
     */
    function deleteAddressBook($addressBookId) {
        error_log("deleteAddressBook", 0);

        /*
        $stmt = $this->pdo->prepare('DELETE FROM ' . $this->cardsTableName . ' WHERE addressbookid = ?');
        $stmt->execute([$addressBookId]);

        $stmt = $this->pdo->prepare('DELETE FROM ' . $this->addressBooksTableName . ' WHERE id = ?');
        $stmt->execute([$addressBookId]);

        $stmt = $this->pdo->prepare('DELETE FROM ' . $this->addressBookChangesTableName . ' WHERE addressbookid = ?');
        $stmt->execute([$addressBookId]);
        */

    }

    /**
     * Returns all cards for a specific addressbook id.
     *
     * This method should return the following properties for each card:
     *   * carddata - raw vcard data
     *   * uri - Some unique url
     *   * lastmodified - A unix timestamp
     *
     * It's recommended to also return the following properties:
     *   * etag - A unique etag. This must change every time the card changes.
     *   * size - The size of the card in bytes.
     *
     * If these last two properties are provided, less time will be spent
     * calculating them. If they are specified, you can also ommit carddata.
     * This may speed up certain requests, especially with large cards.
     *
     * @param mixed $addressbookId
     * @return array
     */
    function getCards($addressbookId) {
        error_log("getCards", 0);

        $result = [];
        $url = $this->url . "/listContacts";
        $username = $_SESSION['USERNAME'];
        $password = $_SESSION['PASSWORD'];
        
        try {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_TIMEOUT, 30); //timeout after 30 seconds
            curl_setopt($ch, CURLOPT_RETURNTRANSFER,1);
            curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
            curl_setopt($ch, CURLOPT_USERPWD, "$username:$password");
            
            //curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
            $output = curl_exec($ch);
            $status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);   //get status code
            // Check the return value of curl_exec(), too
            if ($output === false) {
                error_log("Status:" . $status_code, 0);
                error_log(curl_error($ch), curl_errno($ch));
            }
            error_log("Output:" . json_encode($output), 0);
            if($output)
            {
                $obj = json_decode($output);
                $uris = $obj->{'data'};

                $i = 1;
                foreach($uris as $uri)
                {
                    $row = [];
                    $row = ['id' => $i, 'uri' => $uri, 'etag' => '"' . md5($uri) . '"', 'size' => 1, 'lastmodified' => 1560721157];
                    $i = $i + 1;
                    $result[] = $row;
                }
                
            }

            // close curl resource, and free up system resources  
            curl_close($ch);
        } catch(Exception $e) {
        
            trigger_error(sprintf(
                'Curl failed with error #%d: %s',
                $e->getCode(), $e->getMessage()),
                E_USER_ERROR);
        }

        error_log("getCards Result: " . json_encode($result));
        return $result;
        
        //------------------------------

        /*
        $stmt = $this->pdo->prepare('SELECT id, uri, lastmodified, etag, size FROM ' . $this->cardsTableName . ' WHERE addressbookid = ?');
        $stmt->execute([$addressbookId]);

        $result = [];
        error_log("getCards", 0);
        while ($row = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            error_log("ROW:" . json_encode($row), 0);
            $row['etag'] = '"' . $row['etag'] . '"';
            $result[] = $row;
        }
                
        return $result;
        */
        /*$result = [];
        $result[] = ['id' => 1, 'addressbookid' => 1, 'carddata' => 'BEGIN:VCARD\\r\\nVERSION:3.0\\r\\nEMAIL:bursa2322@vereign.cucumbermail.net\\r\\nFN:Bursa Bursa\\r\\nUID:24114c69-e047-476d-a157-6ad6f7032345\\r\\nEND:VCARD\\r\\n', 'uri' => 'cda18a1d64a39b1555732f7cec19057ece1185d8.vcf', 'etag' => '"f01f71b01d576eadb3cc846cea3daaf7"', 'size' => 224, 'lastmodified' => 1560721157];
        error_log("result: " . json_encode($result));
        return $result;
        //return [];
        */

    }

    /**
     * Returns a specfic card.
     *
     * The same set of properties must be returned as with getCards. The only
     * exception is that 'carddata' is absolutely required.
     *
     * If the card does not exist, you must return false.
     *
     * @param mixed $addressBookId
     * @param string $cardUri
     * @return array
     */
    function getCard($addressBookId, $cardUri) {
        error_log("Inside getCard Vereign", 0);

        /*
        $stmt = $this->pdo->prepare('SELECT id, carddata, uri, lastmodified, etag, size FROM ' . $this->cardsTableName . ' WHERE addressbookid = ? AND uri = ? LIMIT 1');
        $stmt->execute([$addressBookId, $cardUri]);

        $result = $stmt->fetch(\PDO::FETCH_ASSOC);
        error_log("getCard", 0);
        error_log("RESULT:" . json_encode($result), 0);

        if (!$result) return false;

        $result['etag'] = '"' . $result['etag'] . '"';
        return $result;
        */
        $result = [];
        $result[] = ['id' => 1, 'addressbookid' => 1, 'carddata' => 'BEGIN:VCARD\\r\\nVERSION:3.0\\r\\nEMAIL:bursa222@vereign.cucumbermail.net\\r\\nFN:Bursa Bursa\\r\\nUID:24114c69-e047-476d-a157-6ad6f7032345\\r\\nEND:VCARD\\r\\n', 'uri' => 'cda18a1d64a39b1555732f7cec19057ece1185d8.vcf', 'etag' => '"f01f71b01d576eadb3cc846cea3daaf7"', 'size' => 224, 'lastmodified' => 1560721157];
        error_log("result: " . json_encode($result));
        return $result;
        //return false;

    }

    /**
     * Returns a list of cards.
     *
     * This method should work identical to getCard, but instead return all the
     * cards in the list as an array.
     *
     * If the backend supports this, it may allow for some speed-ups.
     *
     * @param mixed $addressBookId
     * @param array $uris
     * @return array
     */
    function getMultipleCards($addressBookId, array $uris) {

        error_log("getMultipleCards", 0);
        error_log("uris:" . json_encode($uris));

        error_log("test");
        
        //$uids = ["39dbe2b5-e11f-4555-8338-1e35bb50acd0", "e81621a3-7b30-4b9b-a653-9f195a44b455"];
        $result = [];
        $i = 1;
        foreach ($uris as $uri) {
            //error_log("uri:" . $uri, 0);
            $row = [];
            $row = ['id' => $i, 'addressbookid' => 1, 'uri' => $uri, 'etag' => '"' . $i . 'f01f71b01d576eadb3cc846cea3daaf7"', 'size' => 224, 'lastmodified' => 1560721157];
            $i = $i + 1;

            $url = $this->url . "/getContact/" . $uri;
            error_log("URL: " . $url);
            //error_log("Session User: " . $_SESSION['USERNAME']);
            //error_log("Session Pass: " . $_SESSION['PASSWORD']);
            $username = $_SESSION['USERNAME'];
            $password = $_SESSION['PASSWORD'];
            
            try {
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $url);
                curl_setopt($ch, CURLOPT_TIMEOUT, 30); //timeout after 30 seconds
                curl_setopt($ch, CURLOPT_RETURNTRANSFER,1);
                curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
                curl_setopt($ch, CURLOPT_USERPWD, "$username:$password");
                
                //curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
                $output = curl_exec($ch);
                $status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);   //get status code
                // Check the return value of curl_exec(), too
                if ($output === false) {
                    error_log("Status:" . $status_code, 0);
                    error_log(curl_error($ch), curl_errno($ch));
                }
                error_log("Output:" . json_encode($output), 0);
                if($output)
                {
                    $row['carddata'] = $output;
                }

                // close curl resource, and free up system resources  
                curl_close($ch);
            } catch(Exception $e) {
            
                trigger_error(sprintf(
                    'Curl failed with error #%d: %s',
                    $e->getCode(), $e->getMessage()),
                    E_USER_ERROR);
            }
            
            //$row['etag'] = '"123"';

            error_log("ROW New:" . json_encode($row), 0);
            $result[] = $row;
        }
        return $result;
        //return [];

    }

    /**
     * Creates a new card.
     *
     * The addressbook id will be passed as the first argument. This is the
     * same id as it is returned from the getAddressBooksForUser method.
     *
     * The cardUri is a base uri, and doesn't include the full path. The
     * cardData argument is the vcard body, and is passed as a string.
     *
     * It is possible to return an ETag from this method. This ETag is for the
     * newly created resource, and must be enclosed with double quotes (that
     * is, the string itself must contain the double quotes).
     *
     * You should only return the ETag if you store the carddata as-is. If a
     * subsequent GET request on the same card does not have the same body,
     * byte-by-byte and you did return an ETag here, clients tend to get
     * confused.
     *
     * If you don't return an ETag, you can just return null.
     *
     * @param mixed $addressBookId
     * @param string $cardUri
     * @param string $cardData
     * @return string|null
     */
    function createCard($addressBookId, $cardUri, $cardData) {
        error_log("createCard", 0);

        /*
        $stmt = $this->pdo->prepare('INSERT INTO ' . $this->cardsTableName . ' (carddata, uri, lastmodified, addressbookid, size, etag) VALUES (?, ?, ?, ?, ?, ?)');

        $etag = md5($cardData);

        $stmt->execute([
            $cardData,
            $cardUri,
            time(),
            $addressBookId,
            strlen($cardData),
            $etag,
        ]);

        $this->addChange($addressBookId, $cardUri, 1);

        return '"' . $etag . '"';
        */
        return '"123"';

    }

    /**
     * Updates a card.
     *
     * The addressbook id will be passed as the first argument. This is the
     * same id as it is returned from the getAddressBooksForUser method.
     *
     * The cardUri is a base uri, and doesn't include the full path. The
     * cardData argument is the vcard body, and is passed as a string.
     *
     * It is possible to return an ETag from this method. This ETag should
     * match that of the updated resource, and must be enclosed with double
     * quotes (that is: the string itself must contain the actual quotes).
     *
     * You should only return the ETag if you store the carddata as-is. If a
     * subsequent GET request on the same card does not have the same body,
     * byte-by-byte and you did return an ETag here, clients tend to get
     * confused.
     *
     * If you don't return an ETag, you can just return null.
     *
     * @param mixed $addressBookId
     * @param string $cardUri
     * @param string $cardData
     * @return string|null
     */
    function updateCard($addressBookId, $cardUri, $cardData) {
        error_log("updateCard", 0);
        /*
        $stmt = $this->pdo->prepare('UPDATE ' . $this->cardsTableName . ' SET carddata = ?, lastmodified = ?, size = ?, etag = ? WHERE uri = ? AND addressbookid =?');

        $etag = md5($cardData);
        $stmt->execute([
            $cardData,
            time(),
            strlen($cardData),
            $etag,
            $cardUri,
            $addressBookId
        ]);

        $this->addChange($addressBookId, $cardUri, 2);

        return '"' . $etag . '"';
        */
        return '"123"';

    }

    /**
     * Deletes a card
     *
     * @param mixed $addressBookId
     * @param string $cardUri
     * @return bool
     */
    function deleteCard($addressBookId, $cardUri) {
        error_log("deleteCard", 0);

        /*
        $stmt = $this->pdo->prepare('DELETE FROM ' . $this->cardsTableName . ' WHERE addressbookid = ? AND uri = ?');
        $stmt->execute([$addressBookId, $cardUri]);

        $this->addChange($addressBookId, $cardUri, 3);

        return $stmt->rowCount() === 1;
        */

    }

    /**
     * The getChanges method returns all the changes that have happened, since
     * the specified syncToken in the specified address book.
     *
     * This function should return an array, such as the following:
     *
     * [
     *   'syncToken' => 'The current synctoken',
     *   'added'   => [
     *      'new.txt',
     *   ],
     *   'modified'   => [
     *      'updated.txt',
     *   ],
     *   'deleted' => [
     *      'foo.php.bak',
     *      'old.txt'
     *   ]
     * ];
     *
     * The returned syncToken property should reflect the *current* syncToken
     * of the addressbook, as reported in the {http://sabredav.org/ns}sync-token
     * property. This is needed here too, to ensure the operation is atomic.
     *
     * If the $syncToken argument is specified as null, this is an initial
     * sync, and all members should be reported.
     *
     * The modified property is an array of nodenames that have changed since
     * the last token.
     *
     * The deleted property is an array with nodenames, that have been deleted
     * from collection.
     *
     * The $syncLevel argument is basically the 'depth' of the report. If it's
     * 1, you only have to report changes that happened only directly in
     * immediate descendants. If it's 2, it should also include changes from
     * the nodes below the child collections. (grandchildren)
     *
     * The $limit argument allows a client to specify how many results should
     * be returned at most. If the limit is not specified, it should be treated
     * as infinite.
     *
     * If the limit (infinite or not) is higher than you're willing to return,
     * you should throw a Sabre\DAV\Exception\TooMuchMatches() exception.
     *
     * If the syncToken is expired (due to data cleanup) or unknown, you must
     * return null.
     *
     * The limit is 'suggestive'. You are free to ignore it.
     *
     * @param string $addressBookId
     * @param string $syncToken
     * @param int $syncLevel
     * @param int $limit
     * @return array
     */
    function getChangesForAddressBook($addressBookId, $syncToken, $syncLevel, $limit = null) {
        error_log("getChangesForAddressBook", 0);

        /*
        // Current synctoken
        $stmt = $this->pdo->prepare('SELECT synctoken FROM ' . $this->addressBooksTableName . ' WHERE id = ?');
        $stmt->execute([ $addressBookId ]);
        $currentToken = $stmt->fetchColumn(0);

        if (is_null($currentToken)) return null;

        $result = [
            'syncToken' => $currentToken,
            'added'     => [],
            'modified'  => [],
            'deleted'   => [],
        ];

        if ($syncToken) {

            $query = "SELECT uri, operation FROM " . $this->addressBookChangesTableName . " WHERE synctoken >= ? AND synctoken < ? AND addressbookid = ? ORDER BY synctoken";
            if ($limit > 0) $query .= " LIMIT " . (int)$limit;

            // Fetching all changes
            $stmt = $this->pdo->prepare($query);
            $stmt->execute([$syncToken, $currentToken, $addressBookId]);

            $changes = [];

            // This loop ensures that any duplicates are overwritten, only the
            // last change on a node is relevant.
            while ($row = $stmt->fetch(\PDO::FETCH_ASSOC)) {

                $changes[$row['uri']] = $row['operation'];

            }

            foreach ($changes as $uri => $operation) {

                switch ($operation) {
                    case 1:
                        $result['added'][] = $uri;
                        break;
                    case 2:
                        $result['modified'][] = $uri;
                        break;
                    case 3:
                        $result['deleted'][] = $uri;
                        break;
                }

            }
        } else {
            // No synctoken supplied, this is the initial sync.
            $query = "SELECT uri FROM " . $this->cardsTableName . " WHERE addressbookid = ?";
            $stmt = $this->pdo->prepare($query);
            $stmt->execute([$addressBookId]);

            $result['added'] = $stmt->fetchAll(\PDO::FETCH_COLUMN);
        }
        return $result;
        */
        return [];

    }

    /**
     * Adds a change record to the addressbookchanges table.
     *
     * @param mixed $addressBookId
     * @param string $objectUri
     * @param int $operation 1 = add, 2 = modify, 3 = delete
     * @return void
     */
    protected function addChange($addressBookId, $objectUri, $operation) {
        error_log("addChange", 0);
        /*
        $stmt = $this->pdo->prepare('INSERT INTO ' . $this->addressBookChangesTableName . ' (uri, synctoken, addressbookid, operation) SELECT ?, synctoken, ?, ? FROM ' . $this->addressBooksTableName . ' WHERE id = ?');
        $stmt->execute([
            $objectUri,
            $addressBookId,
            $operation,
            $addressBookId
        ]);
        $stmt = $this->pdo->prepare('UPDATE ' . $this->addressBooksTableName . ' SET synctoken = synctoken + 1 WHERE id = ?');
        $stmt->execute([
            $addressBookId
        ]);
        */

    }
}
