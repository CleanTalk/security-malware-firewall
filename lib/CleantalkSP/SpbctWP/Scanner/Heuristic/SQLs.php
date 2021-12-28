<?php


namespace CleantalkSP\SpbctWP\Scanner\Heuristic;


class SQLs
{
    /**
     * @var Tokens
     */
    private $tokens;
    
    /**
     * @var Variables
     */
    private $variables;
    
    /**
     * @var array
     */
    public $requests = array();
    
    /**
     * Key words which are could contain in request
     *
     * @var string[]
     */
    private $key_words = array(
        'SELECT',
        'INSERT',
        'UPDATE',
        'LIMIT',
        'DESC',
        'ASC',
        'UNION',
        'JOIN',
    );
    
    /**
     * @var string
     */
    private $key_words_regex;
    
    public function __construct( Tokens $tokens, Variables $variables )
    {
        $this->tokens    = $tokens;
        $this->variables = $variables;
        
        $this->key_words_regex = '/';
        foreach($this->key_words as $key_word){
            $this->key_words_regex .= '|' . $key_word;
        }
        $this->key_words_regex = substr($this->key_words_regex, 0, -1) . '/';
    }
    
    /**
     * Search for SQL requests made by following libraries:
     * PDO
     * MySQLi
     * WPDB
     * MySQL
     *
     * @param int $key Current iteration array key
     */
    public function getViaFunctions($key)
    {
        $sql_start = null;
        $sql_end   = null;
        
        // WPDB
        if(
            $this->tokens->isCurrentTypeOf('T_VARIABLE') &&
            $this->tokens->isNextTypeOf('T_OBJECT_OPERATOR') &&
            $this->tokens->isNextTypeOf('T_STRING', 2) &&
            $this->tokens->isNextEqualTo(array('query', 'get_results'), 2) &&
            $this->tokens->isNextEqualTo('(', 3)
        ){
            $sql_start = $key + 4;
            $sql_end   = $this->tokens->searchForward($key, ';') - 1;
            
        // Mysqli
        }elseif(
            $this->tokens->isCurrentTypeOf('T_STRING') &&
            $this->tokens->isCurrentEqualTo(array('MYSQLI', 'mysqli')) &&
            $this->tokens->isNextTypeOf('T_STRING', 2) &&
            $this->tokens->isNextEqualTo(array('query', 'send_query', 'multi_query'), 2)
        ){
            $sql_start = $key + 4;
            $sql_end   = $this->tokens->searchForward($key, ';') - 1;
            
        // PDO
        }elseif(
            $this->tokens->isCurrentTypeOf('T_STRING') &&
            $this->tokens->isCurrentEqualTo(array('PDO', 'pdo')) &&
            $this->tokens->isNextTypeOf('T_STRING', 2) &&
            $this->tokens->isNextEqualTo(array('query', 'exec'), 2)
        ){
            $sql_start = $key + 4;
            $sql_end   = $this->tokens->searchForward($key, ';') - 1;
            
        // Mysql
        }elseif(
            $this->tokens->isCurrentTypeOf('T_STRING') &&
            $this->tokens->isCurrentEqualTo(array('mysql_query', 'mysqli_query', 'mysqli_send_query', 'mysqli_multi_query'))
        ){
            $sql_start = $key + 2;
            $sql_end   = $this->tokens->searchForward($key, ';') - 1;
        }
        
        if( $sql_start && $sql_end ){
            $sql = $this->tokens->getRange($sql_start, $sql_end);
            $this->processRequest($sql, $this->tokens->current[2]);
        }
    }
    
    /**
     * Detects SQL by SQL key words
     *
     * @param int $key Current iteration array key
     */
    public function getViaKeyWords($key){
        if(
            $this->tokens->isCurrentTypeOf('T_CONSTANT_ENCAPSED_STRING') &&
            preg_match($this->key_words_regex, $this->tokens->current[1])
        ){
            
            $sql = $this->tokens->getRange(
                $this->tokens->searchBackward($key, array('=','(')),
                $this->tokens->searchForward($key, array(')', ';'))
            );
            
            if( $sql ){
                $this->processRequest($sql, $this->tokens->current[2]);
            }
        }
    }
    
    /**
     * Formatting, checking and saving SQL request to $this->sql_requests
     *
     * @param $sql
     * @param $line_number
     */
    public function processRequest($sql, $line_number)
    {
        // Checking for bad variables in SQL request
        $good = ! $this->variables->isSetOfTokensHasBadVariables($sql);
        
        $this->requests[] = array(
            'sql'          => $sql,
            'status'       => $good,
            'good'         => $good,
            'string'       => $line_number,
            'first_string' => reset($sql)[2],
            'last_string'  => end($sql)[2],
        );
    }
}