<?php

namespace Sabre\DAVACL\PrincipalBackend;

use Sabre\DAV;
use Sabre\DAV\MkCol;
use Sabre\HTTP\URLUtil;

ini_set("log_errors", 1);
error_reporting(E_ALL);

/**
 * Vereign principal backend
 *
 *
 * This backend assumes all principals are in a single collection. The default collection
 * is 'principals/', but this can be overriden.
 *
 * @copyright Copyright (C) fruux GmbH (https://fruux.com/)
 * @author Evert Pot (http://evertpot.com/)
 * @license http://sabre.io/license/ Modified BSD License
 */
class VereignPrincipalBackend extends AbstractBackend implements CreatePrincipalSupport {

    /**
     * PDO table name for 'principals'
     *
     * @var string
     */
    public $tableName = 'principals';

    /**
     * PDO table name for 'group members'
     *
     * @var string
     */
    public $groupMembersTableName = 'groupmembers';

    /**
     * url
     */
    protected $url;

    /**
     * A list of additional fields to support
     *
     * @var array
     */
    protected $fieldMap = [

        /**
         * This property can be used to display the users' real name.
         */
        '{DAV:}displayname' => [
            'dbField' => 'displayname',
        ],

        /**
         * This is the users' primary email-address.
         */
        '{http://sabredav.org/ns}email-address' => [
            'dbField' => 'email',
        ],
    ];

    /**
     * Sets up the backend.
     */
    function __construct(string $url) {

        $this->url = $url;

    }

    /**
     * Returns a list of principals based on a prefix.
     *
     * This prefix will often contain something like 'principals'. You are only
     * expected to return principals that are in this base path.
     *
     * You are expected to return at least a 'uri' for every user, you can
     * return any additional properties if you wish so. Common properties are:
     *   {DAV:}displayname
     *   {http://sabredav.org/ns}email-address - This is a custom SabreDAV
     *     field that's actualy injected in a number of other properties. If
     *     you have an email address, use this property.
     *
     * @param string $prefixPath
     * @return array
     */
    function getPrincipalsByPrefix($prefixPath) {
        /*
        $fields = [
            'uri',
        ];

        foreach ($this->fieldMap as $key => $value) {
            $fields[] = $value['dbField'];
        }
        $result = $this->pdo->query('SELECT ' . implode(',', $fields) . '  FROM ' . $this->tableName);

        $principals = [];

        while ($row = $result->fetch(\PDO::FETCH_ASSOC)) {

            // Checking if the principal is in the prefix
            list($rowPrefix) = URLUtil::splitPath($row['uri']);
            if ($rowPrefix !== $prefixPath) continue;

            $principal = [
                'uri' => $row['uri'],
            ];
            foreach ($this->fieldMap as $key => $value) {
                if ($row[$value['dbField']]) {
                    $principal[$key] = $row[$value['dbField']];
                }
            }
            $principals[] = $principal;

        }

        return $principals;
        */
        return [];

    }

    /**
     * Returns a specific principal, specified by it's path.
     * The returned structure should be the exact same as from
     * getPrincipalsByPrefix.
     *
     * @param string $path
     * @return array
     */
    function getPrincipalByPath($path) {

        $fields = [
            'id',
            'uri',
        ];

        /*
        foreach ($this->fieldMap as $key => $value) {
            $fields[] = $value['dbField'];
        }
        $stmt = $this->pdo->prepare('SELECT ' . implode(',', $fields) . '  FROM ' . $this->tableName . ' WHERE uri = ?');
        $stmt->execute([$path]);

        $row = $stmt->fetch(\PDO::FETCH_ASSOC);
        if (!$row) return;
        */

        $principal = [
            'id'  => 1,
            'uri' => $path,
        ];
        /*foreach ($this->fieldMap as $key => $value) {
            if ($row[$value['dbField']]) {
                $principal[$key] = $row[$value['dbField']];
            }
        }*/
        return $principal;

    }

    /**
     * Updates one ore more webdav properties on a principal.
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
     * @param string $path
     * @param DAV\PropPatch $propPatch
     */
    function updatePrincipal($path, DAV\PropPatch $propPatch) {

        /*
        $propPatch->handle(array_keys($this->fieldMap), function($properties) use ($path) {

            $query = "UPDATE " . $this->tableName . " SET ";
            $first = true;

            $values = [];

            foreach ($properties as $key => $value) {

                $dbField = $this->fieldMap[$key]['dbField'];

                if (!$first) {
                    $query .= ', ';
                }
                $first = false;
                $query .= $dbField . ' = :' . $dbField;
                $values[$dbField] = $value;

            }

            $query .= " WHERE uri = :uri";
            $values['uri'] = $path;

            $stmt = $this->pdo->prepare($query);
            $stmt->execute($values);

            return true;

        });
        */
        return true;

    }

    /**
     * This method is used to search for principals matching a set of
     * properties.
     *
     * This search is specifically used by RFC3744's principal-property-search
     * REPORT.
     *
     * The actual search should be a unicode-non-case-sensitive search. The
     * keys in searchProperties are the WebDAV property names, while the values
     * are the property values to search on.
     *
     * By default, if multiple properties are submitted to this method, the
     * various properties should be combined with 'AND'. If $test is set to
     * 'anyof', it should be combined using 'OR'.
     *
     * This method should simply return an array with full principal uri's.
     *
     * If somebody attempted to search on a property the backend does not
     * support, you should simply return 0 results.
     *
     * You can also just return 0 results if you choose to not support
     * searching at all, but keep in mind that this may stop certain features
     * from working.
     *
     * @param string $prefixPath
     * @param array $searchProperties
     * @param string $test
     * @return array
     */
    function searchPrincipals($prefixPath, array $searchProperties, $test = 'allof') {
        if (count($searchProperties) == 0) return [];    //No criteria
        /*

        $query = 'SELECT uri FROM ' . $this->tableName . ' WHERE ';
        $values = [];
        foreach ($searchProperties as $property => $value) {
            switch ($property) {
                case '{DAV:}displayname' :
                    $column = "displayname";
                    break;
                case '{http://sabredav.org/ns}email-address' :
                    $column = "email";
                    break;
                default :
                    // Unsupported property
                    return [];
            }
            if (count($values) > 0) $query .= (strcmp($test, "anyof") == 0 ? " OR " : " AND ");
            $query .= 'lower(' . $column . ') LIKE lower(?)';
            $values[] = '%' . $value . '%';

        }
        $stmt = $this->pdo->prepare($query);
        $stmt->execute($values);

        $principals = [];
        while ($row = $stmt->fetch(\PDO::FETCH_ASSOC)) {

            // Checking if the principal is in the prefix
            list($rowPrefix) = URLUtil::splitPath($row['uri']);
            if ($rowPrefix !== $prefixPath) continue;

            $principals[] = $row['uri'];

        }

        return $principals;
        */
        return $prefixPath;

    }

    /**
     * Finds a principal by its URI.
     *
     * This method may receive any type of uri, but mailto: addresses will be
     * the most common.
     *
     * Implementation of this API is optional. It is currently used by the
     * CalDAV system to find principals based on their email addresses. If this
     * API is not implemented, some features may not work correctly.
     *
     * This method must return a relative principal path, or null, if the
     * principal was not found or you refuse to find it.
     *
     * @param string $uri
     * @param string $principalPrefix
     * @return string
     */
    function findByUri($uri, $principalPrefix) {
        /*
        $value = null;
        $scheme = null;
        list($scheme, $value) = explode(":", $uri, 2);
        if ($value == null) return null;

        $uri = null;
        switch ($scheme){
            case "mailto":
                $query = 'SELECT uri FROM ' . $this->tableName . ' WHERE lower(email)=lower(?)';
                $stmt = $this->pdo->prepare($query);
                $stmt->execute([ $value ]);
            
                while ($row = $stmt->fetch(\PDO::FETCH_ASSOC)) {
                    // Checking if the principal is in the prefix
                    list($rowPrefix) = URLUtil::splitPath($row['uri']);
                    if ($rowPrefix !== $principalPrefix) continue;
                    
                    $uri = $row['uri'];
                    break; //Stop on first match
                }
                break;
            default:
                //unsupported uri scheme
                return null;
        }
        return $uri;
        */
        return $uri;
    }

    /**
     * Returns the list of members for a group-principal
     *
     * @param string $principal
     * @return array
     */
    function getGroupMemberSet($principal) {

        /*
        $principal = $this->getPrincipalByPath($principal);
        if (!$principal) throw new DAV\Exception('Principal not found');

        $stmt = $this->pdo->prepare('SELECT principals.uri as uri FROM ' . $this->groupMembersTableName . ' AS groupmembers LEFT JOIN ' . $this->tableName . ' AS principals ON groupmembers.member_id = principals.id WHERE groupmembers.principal_id = ?');
        $stmt->execute([$principal['id']]);

        $result = [];
        while ($row = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            $result[] = $row['uri'];
        }
        return $result;
        */
        return $principal;

    }

    /**
     * Returns the list of groups a principal is a member of
     *
     * @param string $principal
     * @return array
     */
    function getGroupMembership($principal) {

        $principal = $this->getPrincipalByPath($principal);
        if (!$principal) throw new DAV\Exception('Principal not found');

        /*
        $stmt = $this->pdo->prepare('SELECT principals.uri as uri FROM ' . $this->groupMembersTableName . ' AS groupmembers LEFT JOIN ' . $this->tableName . ' AS principals ON groupmembers.principal_id = principals.id WHERE groupmembers.member_id = ?');
        $stmt->execute([$principal['id']]);

        $result = [];
        while ($row = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            $result[] = $row['uri'];
        }
        return $result;
        */
        return [];

    }

    /**
     * Updates the list of group members for a group principal.
     *
     * The principals should be passed as a list of uri's.
     *
     * @param string $principal
     * @param array $members
     * @return void
     */
    function setGroupMemberSet($principal, array $members) {

        /*
        // Grabbing the list of principal id's.
        $stmt = $this->pdo->prepare('SELECT id, uri FROM ' . $this->tableName . ' WHERE uri IN (? ' . str_repeat(', ? ', count($members)) . ');');
        $stmt->execute(array_merge([$principal], $members));

        $memberIds = [];
        $principalId = null;

        while ($row = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            if ($row['uri'] == $principal) {
                $principalId = $row['id'];
            } else {
                $memberIds[] = $row['id'];
            }
        }
        if (!$principalId) throw new DAV\Exception('Principal not found');

        // Wiping out old members
        $stmt = $this->pdo->prepare('DELETE FROM ' . $this->groupMembersTableName . ' WHERE principal_id = ?;');
        $stmt->execute([$principalId]);

        foreach ($memberIds as $memberId) {

            $stmt = $this->pdo->prepare('INSERT INTO ' . $this->groupMembersTableName . ' (principal_id, member_id) VALUES (?, ?);');
            $stmt->execute([$principalId, $memberId]);

        }
        */

    }

    /**
     * Creates a new principal.
     *
     * This method receives a full path for the new principal. The mkCol object
     * contains any additional webdav properties specified during the creation
     * of the principal.
     *
     * @param string $path
     * @param MkCol $mkCol
     * @return void
     */
    function createPrincipal($path, MkCol $mkCol) {

        /*
        $stmt = $this->pdo->prepare('INSERT INTO ' . $this->tableName . ' (uri) VALUES (?)');
        $stmt->execute([$path]);
        $this->updatePrincipal($path, $mkCol);
        */

    }

}
