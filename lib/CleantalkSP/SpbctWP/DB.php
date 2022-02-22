<?php

namespace CleantalkSP\SpbctWP;

use CleantalkSP\Templates\Singleton;

/**
 * CleanTalk WordPress Data Base driver
 * Compatible only with WordPress.
 * Uses singleton pattern.
 * 
 * @depends \CleantalkSP\Common\DB
 * 
 * @version 3.2
 * @author Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see https://github.com/CleanTalk/wordpress-antispam
*/

final class DB extends \CleantalkSP\Common\DB
{
    use Singleton;
    
	/**
	 * @var string Query string
	 */
	private $query;
    
    /**
     * @var int Amount of rows affected in the last request from create, alter, truncate, drop, insert, delete, update, replace requests types
     */
	private $rows_affected;
	
	/**
	 * @var array Processed result
	 */
	public $result = array();
	
	/**
	 * @var string Database prefix
	 */
	public $prefix = '';
    
    /**
     * @return int
     */
    public function getRowsAffected(){
        global $wpdb;
        return $wpdb->rows_affected;
    }
    
    /**
     * @return string
     */
    public function getQuery()
    {
        return $this->query;
    }
    
    protected function init(){
		global $spbc;
		$this->prefix = $spbc->db_prefix;
	}
	/**
	 * Set $this->query string for next uses
	 *
	 * @param $query
	 * @return $this
	 */
	public function set_query($query)
	{
		$this->query = $query;
		return $this;
	}
	
	/**
	 * Safely replace place holders
	 *
	 * @param string $query
	 * @param array  $vars
	 *
	 * @return $this
	 */
	public function prepare($query, $vars = array())
	{
		global $wpdb;
		
		$query = $query ?: $this->query;
        
        $this->query = call_user_func(array($wpdb, 'prepare'), $query, $vars);
		
		return $this;
	}
    
    /**
     * First half of escaping for `LIKE` special characters `%` and `_` before preparing for SQL.
     *
     * @param string $text
     *
     * @return string
     */
    public function escapeLike( $text )
    {
        global $wpdb;
        
        return $wpdb->esc_like($text);
    }
	
	/**
	 * Run any raw request
	 *
	 * @param $query
	 *
	 * @return bool|int Raw result
	 */
	public function execute($query = null){
		global $wpdb;
		
		return $wpdb->query($query ?: $this->query);
	}
	
	/**
	 * Fetchs first column from query.
	 * May receive raw or prepared query.
	 *
	 * @param string $query
	 * @param string $response_type
	 *
	 * @return array|object|void|null
	 */
	public function fetch($query = '', $response_type = OBJECT){
		
		global $wpdb;
        
        $query = $query ?: $this->query;
		
		$this->result = $wpdb->get_row($query, $response_type);
		
		return $this->result;
	}
    
    /**
     * Fetches all result from query.
     * May receive raw or prepared query.
     *
     * @param string $query
     * @param string $response_type
     *
     * @return array|object|null
     */
	public function fetch_all( $query = '', $response_type = ARRAY_A ){
		
		global $wpdb;
        
        $query = $query ?: $this->query;
		
		$this->result = $wpdb->get_results($query, $response_type);
		
		return $this->result;
	}

	/**
	 * Getting last query error
	 * @return string
	 */
	public function get_last_error() {
		global $wpdb;
		return $wpdb->last_error;
	}
	
    /**
     * Getting last query error
     * @return string
     */
    public function getLastQuery() {
        global $wpdb;
        return $wpdb->last_query;
    }

}