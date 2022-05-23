<?php


namespace CleantalkSP\SpbctWP\Scanner\Heuristic;


use CleantalkSP\DataStructures\ExtendedSplFixedArray;

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
        
        $this->key_words_regex = '#' . implode( '|', $this->key_words ) . '#';
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
            $this->tokens->current->type === 'T_VARIABLE' &&
            $this->tokens->next1->type === 'T_OBJECT_OPERATOR' &&
            $this->tokens->next2->type === 'T_STRING' &&
            $this->tokens->next2->isValueIn(['query', 'get_results']) &&
            $this->tokens->next3->value === '('
        ){
            $sql_start = $key + 4;
            $sql_end   = $this->tokens->searchForward($key, ';') - 1;
            
        // Mysqli
        }elseif(
            $this->tokens->current->type === 'T_STRING' &&
            $this->tokens->current->isValueIn(['MYSQLI', 'mysqli']) &&
            $this->tokens->next2->type === 'T_STRING' &&
            $this->tokens->next2->isValueIn(['query', 'send_query', 'multi_query'])
        ){
            $sql_start = $key + 4;
            $sql_end   = $this->tokens->searchForward($key, ';') - 1;
            
        // PDO
        }elseif(
            $this->tokens->current->type === 'T_STRING' &&
            $this->tokens->current->isValueIn(['PDO', 'pdo']) &&
            $this->tokens->next2->type === 'T_STRING' &&
            $this->tokens->next2->isValueIn(['query', 'exec'])
        ){
            $sql_start = $key + 4;
            $sql_end   = $this->tokens->searchForward($key, ';') - 1;
            
        // Mysql
        }elseif(
            $this->tokens->current->type === 'T_STRING' &&
            $this->tokens->current->isValueIn(['mysql_query', 'mysqli_query', 'mysqli_send_query', 'mysqli_multi_query'])
        ){
            $sql_start = $key + 2;
            $sql_end   = $this->tokens->searchForward($key, ';') - 1;
        }
        
        if( $sql_start && $sql_end ){
            $sql = $this->tokens->getRange($sql_start, $sql_end);
            if( $sql ){
                $this->processRequest( $sql, $this->tokens->current[2] );
            }
        }
    }
    
    /**
     * Detects SQL by SQL key words
     *
     * @param int $key Current iteration array key
     */
    public function getViaKeyWords($key){
        if(
            $this->tokens->current->type === 'T_CONSTANT_ENCAPSED_STRING' &&
            preg_match($this->key_words_regex, $this->tokens->current->value) // @todo use stripos() instead of preg_match()
        ){
            
            $sql = $this->tokens->getRange(
                $this->tokens->searchBackward($key, [ '=', '(' ]),
                $this->tokens->searchForward ($key, [ ')', ';' ])
            );
            
            if( $sql ){
                $this->processRequest($sql);
            }
        }
    }
    
    /**
     * Formatting, checking and saving SQL request to $this->sql_requests
     *
     * @param ExtendedSplFixedArray $sql
     */
    public function processRequest($sql)
    {
        $sql = $sql->toArray();
        
        // Prevent from duplicating SQLs
        foreach( $this->requests as $request){
            if( $request['sql'][0] == $sql[0] ){ // '==' because we compare objects
                return;
            }
        }
        
        // Checking for bad variables in SQL request
        $good = ! $this->variables->isSetOfTokensHasBadVariables($sql);
        
        $this->requests[] = array(
            'sql'          => $sql,
            'status'       => $good,
            'good'         => $good,
            'string'       => $sql[0]->line,
            'first_string' => reset($sql)->line,
            'last_string'  => end($sql)->line,
        );
    }
}