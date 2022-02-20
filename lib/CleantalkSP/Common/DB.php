<?php

namespace CleantalkSP\Common;

/**
 * CleanTalk abstract Data Base driver.
 * Shows what should be inside.
 * Uses singleton pattern.
 *
 * @version 2.0
 * @author Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see https://github.com/CleanTalk/php-antispam
*/

abstract class DB
{
	/**
	 * @var string Query string
	 */
	private $query;
	
	/**
	 * @var array Processed result
	 */
	public $result = array();
	
	/**
	 * @var string Database prefix
	 */
	public $prefix = '';
	
	/**
	 * Set $this->query string for next uses
	 *
	 * @param $query
	 */
	abstract public function set_query($query);
	
	/**
	 * Safely replace place holders
	 *
	 * @param string $query
	 * @param array $vars
	 */
	abstract public function prepare($query, $vars = array());
	
	/**
	 * Run any raw request
	 *
	 * @param $query
     *
     * @return bool|int Raw result
	 */
	abstract public function execute($query);
	
	/**
	 * Fetches first column from query.
	 * May receive raw or prepared query.
	 *
	 * @param bool $query
	 * @param bool $response_type
	 */
	abstract public function fetch($query = false, $response_type = false);
	
	/**
	 * Fetches all result from query.
	 * May receive raw or prepared query.
	 *
	 * @param bool $query
	 * @param bool $response_type
	 */
	abstract public function fetch_all($query = false, $response_type = false);
    
    /**
     * Checks if the table exists
     *
     * @param $table_name
     *
     * @return bool
     */
    public function isTableExists( $table_name ){
        return (bool) $this->execute( 'SHOW TABLES LIKE "' . $table_name . '"' );
    }
}