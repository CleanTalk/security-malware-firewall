<?php


namespace CleantalkSP\SpbctWP\Scanner\Heuristic;


use CleantalkSP\DataStructures\ExtendedSplFixedArray;
use CleantalkSP\SpbctWP\Scanner\Heuristic\DataStructures\Token;

/**
 * @property Token|null $prev4 Iteration Token
 * @property Token|null $prev3 Iteration Token
 * @property Token|null $prev2 Iteration Token
 * @property Token|null $prev1 Iteration Token
 * @property Token|null $current Iteration Token
 * @property Token|null $next1 Iteration Token
 * @property Token|null $next2 Iteration Token
 * @property Token|null $next3 Iteration Token
 * @property Token|null $next4 Iteration Token
 */
class Tokens implements \Iterator, \ArrayAccess, \Countable
{
    /**
     * @var int Shows the current position in the set of tokens
     */
    private $position = 0;
    
    /**
     * @var int Shows the maximum available position in the set of tokens
     */
    public $max_position;
    
    /**
     * Amount of main cycle repetition
     *
     * @var int
     */
    public $repeats = 0;
    
    /**
     * @var bool
     */
    public $were_modified = false;
    
    /**
     * @var ExtendedSplFixedArray Contains tokens with code itself, without any junk.
     *
     * <br>
     * It's a ExtendedSplFixedArray class of Token class
     */
    public $tokens;
    
    /**
     * @var Token[] Contains tokens with inline and multiline PHP comments
     */
    public $comments = array();
    
    /**
     * @var Token[] Contains tokens with inline HTML
     */
    public $html = array();
    
    /**
     * @var TokenGroups Contain known grouped token types
     */
    private $groups;
    
    public function __construct( $content )
    {
        $this->groups = new TokenGroups();
        $this->getTokensFromText($content);
    }
    
    /**
     * Parse code and transform it to array of arrays with token like
     * <br>
     * [
     *    0 => (string) TOKEN_TYPE,
     *    1 => (mixed)  TOKEN_VALUE
     *    2 => (int)    DOCUMENT_STRING_NUMBER
     * ]
     * <br>
     * Convert all tokens to the above-mentioned format
     * <br><br>
     * Single tokens like '.' or ';' receive TOKEN_TYPE like '__SERV'<br>
     * Single tokens like '.' or ';' receive DOCUMENT_STRING_NUMBER from the previous token
     *
     * @param $text
     *
     * @return void
     */
    public function getTokensFromText( $text )
    {
        $this->tokens = ExtendedSplFixedArray::createFromArray( @token_get_all( $text ) );
        $this->convertTokensToStandard();
    }
    
    /**
     * Get the token with passed position (key)
     *
     * @param int|string|null $position
     *
     * @return Token|null
     */
    public function getTokenFromPosition( $position = null, $get_only_actual = false )
    {
        // If no position was requested, return current token
        if( ! isset($position) || $position === 'current' ){
            return $this->current;
        }
        
        $out = false;
        
        // Search forward for first actual token
        for( ; $out === false && $position <= $this->max_position; $position++ ){
            $out = isset($this->tokens[ $position ])
                ? $this->tokens[ $position ]
                : null;
        }
        
        return $out;
    }
    
    /**
     * For debug purposes
     *
     * @return Token[]
     */
    public function getIterationTokens()
    {
        return [
            'prev4'   => $this->prev4,
            'prev3'   => $this->prev3,
            'prev2'   => $this->prev2,
            'prev1'   => $this->prev1,
            'current' => $this->current,
            'next1'   => $this->next1,
            'next2'   => $this->next2,
            'next3'   => $this->next3,
            'next4'   => $this->next4,
        ];
    }
    
    /**
     * Work with $this->tokens
     * 
     * Standardizing all tokens to $this->tokens[N][
     *    0 => (string) TOKEN_TYPE,
     *    1 => (mixed)  TOKEN_VALUE
     *    2 => (int)    DOCUMENT_STRING_NUMBER
     * ]
     *
     * @return void
     */
    private function convertTokensToStandard()
    {
        // We are using for instead of foreach because we might stumble on SplFixedArray.
        // SplFixedArray doesn't support passing element by reference in 'for' cycles.
        for(
            
            // Initialization
            $key             = 0,
            $prev_token_line = 1,
            $length          = count($this->tokens);
            
            // Before each iteration
            $key < $length;
            
            // After each iteration
            $prev_token_line = $this->tokens[$key]->line, // Set previous token to compile next service(__SERV) tokens
            $key++
        ){
            
            $curr_token = $this->tokens[$key]; // Set current iteration token
            
            $this->tokens[ $key ] = is_scalar($curr_token)
                ? new Token('__SERV',              $curr_token,    $prev_token_line, $key) // For simple tokens like ';', ','...
                : new Token(token_name($curr_token[0]), $curr_token[1], $curr_token[2], $key);  // For normal token with type
        }
    }
    
    /**
     * set tokens from next{$depth} to prev{$depth}
     *
     * @param int $depth
     */
    public function setIterationTokens($depth = 4)
    {
        // Set previous tokens
        for( $i = $depth; $i !== 0; $i-- ){
            $this->{'prev'.$i} = $this->getToken( 'prev', $i );
        }
        
        // Set current token
        $this->current      = $this->tokens[ $this->position ];
        $this->current->key = $this->position;
        
        // Set next tokens
        for( $i = 1; $i <= $depth; $i++ ){
            $this->{'next'.$i} = $this->getToken( 'next', $i );
        }
    }
    
    /**
     * Gather tokens back in string
     * Using all tokens
     *
     * @return string
     */
	public function glueAllTokens()
    {
        return implode('', $this->tokens->getColumn( 1 ) );
    }

    
    /**
     * Gather tokens back in string
     * Using all tokens if nothing was passed
     *
     * @param array|ExtendedSplFixedArray $input Array of lexems
     *
     * @return string
     */
	public function glueTokens( $input = array() )
    {
        $input = $input ?: $this->tokens;
        
        return $input instanceof ExtendedSplFixedArray
	        ? implode('', $input->getColumn( 1 ) )
	        : implode('', array_column( $input, 1 ) );
    }
    
    /**
     * Returns position of the searched token
     * Search for needle === if needle is set
     *
     * @param              $start
     * @param string|array $needle
     * @param int          $depth of search. How far we should look for the token
     *
     * @return false|int Position of the needle
     */
    public function searchForward($start, $needle, $depth = 250)
    {
        if( $start === false ){
            return false;
        }
        
        // Needle is an array with strings
        if( is_array($needle) || $needle instanceof ExtendedSplFixedArray){
            for( $i = 0, $key = $start + 1; $i < $depth; $i++, $key++ ){
                if( isset($this->tokens[$key]) && in_array($this->tokens[$key]->value, $needle, true) ){
                    return $key;
                }
            }
    
        // Needle is a string
        }else{
            for( $i = 0, $key = $start + 1; $i < $depth; $i++, $key++ ){
                if( isset($this->tokens[$key]) && $this->tokens[$key]->value === $needle ){
                    return $key;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Getting prev set lexem, Search for needle === if needle is set
     *
     * @param int          $start
     * @param string|array $needle
     * @param int          $depth of search. How far we should look for the token
     *
     * @return bool|int
     */
    public function searchBackward($start, $needle, $depth = 250)
    {
        // Needle is an array with strings
        if( is_array($needle) || $needle instanceof ExtendedSplFixedArray){
            for( $i = 0, $key = $start - 1; $i < $depth && $key > 0; $i--, $key-- ){
                if( isset($this->tokens[$key]) && in_array($this->tokens[$key]->value, $needle, true) ){
                    return $key;
                }
            }
            
        // Needle is a string
        }else{
            for( $i = 0, $key = $start - 1; $i < $depth && $key > 0; $i--, $key-- ){
                if( isset($this->tokens[$key]) && $this->tokens[$key]->value === $needle ){
                    return $key;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Get next or previous token from $this->tokens
     * Try to get a token ignoring empty tokens until
     *      max key is reached ('next' direction)
     *      or
     *      zero key is reached ('prev' direction)
     *
     * @param string   $direction        'next' or 'prev' string
     * @param int      $requested_offset offset from the current token token
     * @param int|null $position
     *
     * @return Token
     */
    public function getToken($direction, $requested_offset = 0, $position = null)
    {
        $requested_offset = (int)$requested_offset;
        $out              = null;
        $current_position = isset($position)
            ? $position
            : $this->position;
        
        switch($direction){
            case 'current':
                $out = isset($this->tokens[$this->position]) ? $this->tokens[$this->position] : null;
                break;
            
            // Forward direction
            case 'next':
                for( $current_position++, $current_offset = 0; $current_position <= $this->max_position; $current_position++ ){
                    if( isset($this->tokens[$current_position]) ){
                        $current_offset++;
                    }
                    if( $current_offset === $requested_offset ){
                        $out = $this->tokens[ $current_position ];
                        $out->key = $current_position;
                        break;
                    }
                }
                break;
                
            // Backward direction
            case 'prev':
                for( $current_position--, $current_offset = 0; $current_position >= 0; $current_position-- ){
                    if( isset($this->tokens[$current_position]) ){
                        $current_offset++;
                    }
                    if( $current_offset === $requested_offset ){
                        $out      = $this->tokens[ $current_position ];
                        $out->key = $current_position;
                        break;
                    }
                }
                break;
        }
        
        return $out ?: new Token(null, null, null);
    }
    
    /**
     * Get slice from the current tokens
     *
     * @param int  $start    Start key
     * @param int  $end      End key
     * @param bool $clean_up Should we clean from null values?
     *
     * @return ExtendedSplFixedArray|false
     */
    public function getRange( $start, $end, $clean_up = true)
    {
        if( $start !== false && $end !== false ){
            
            return $this->tokens->slice(
                $start,
                $end,
                $clean_up
            );
        }
        
        return false;
    }
    
    /**
     * Unset token with given names
     *
     * @todo rename to 'unset'
     *
     * @param mixed ...$tokens_positions
     */
    public function unsetTokens(...$tokens_positions)
    {
        $out = true;
        
        foreach( $tokens_positions as $tokens_position ){
            
            if( is_numeric($tokens_position) ){
                $key_to_unset = $tokens_position;
            }else{
                $key_to_unset = $this->$tokens_position->key ?: $this->convertOffset( $tokens_position );
            }
    
            if( isset( $this->tokens[ $key_to_unset ] ) ){
                unset( $this->tokens[ $key_to_unset ] );
                continue;
            }
    
            $out = false;
        }
        
        $this->setIterationTokens();
        
        return $out;
    }
    
    /**
     * Compare passed sequence of tokens to the set of token we are work on.
     * Since all token are standardized we don't have to check guess if the token from the set is array or not.
     *
     * @param int   $position
     * @param array $sequence Array of lexemes
     *
     * @return bool
     */
    public function checkSequence( $sequence, $position = null ){
        
        $position = $position ?: $this->position;
        
        foreach( $sequence as $sequence_offset => $token_from_sequence ){
            
            $position_to_check = $position + $sequence_offset;
            $token_from_set  = $this->getTokenFromPosition($position_to_check, true);
            
            if(
                ! $token_from_set ||                                                                   // If the token from the set is not present
                ! in_array($token_from_set[0], (array) $token_from_sequence[0], true) ||          // Compare first element
                ( isset( $token_from_sequence[1] ) && $token_from_sequence[1] !== $token_from_set[1] ) // Compare second if provided
            ){
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Reindexing current tokens
     * Deletes deletes null values
     * Set new max_positions
     *
     * @return void
     */
    public function reindex(){
        $this->max_position = $this->tokens->reindex();
    }
    
    /**
     * Converts offset from human-text string to
     *
     * @param $offset_to_convert
     *
     * @return int|null
     */
    private function convertOffset( $offset_to_convert ){
        
        if( $offset_to_convert === 'current' ){
            $offset = $this->position;
            
        // By direction and offset from current position
        }elseif( is_string($offset_to_convert) ){
            
            $direction = substr($offset_to_convert, 0, 4);
            $depth     = substr($offset_to_convert, 4) ?: 1;
            $offset    = $this->getToken($direction, $depth)->key;
            
        // Direct access by numeric offset
        }elseif( is_numeric($offset_to_convert) ){
            $offset = $offset_to_convert;
            
        // Default
        }else{
            $offset = null;
        }
        
        return $offset;
    }
    
    /**
     * @return void
     */
    public function rewind()
    {
        $this->repeats++;
        $this->position     = 0;
        $this->max_position = $this->tokens->getSize();
    }
    
    /**
     * @return int
     */
    public function key()
    {
        return $this->position;
    }
    
    /**
     * @return Token
     */
    public function current()
    {
        return $this->tokens[ $this->position ];
    }
    
    /**
     * @return void
     */
    public function next()
    {
        $this->position++;
    }
    
    /**
     * @return bool
     */
    public function valid()
    {
        while(
            empty( $this->tokens[ $this->position ] ) &&
            $this->position <= $this->max_position
        ){
            $this->position++;
        }
        
        if( isset( $this->tokens[ $this->position ] ) ){
             $this->setIterationTokens();
        
            return true;
        }
    
        return false;
    }
    
    /**
     * @param $offset
     *
     * @return bool
     */
    public function offsetExists( $offset )
    {
        return isset( $this->tokens[ $offset ] );
    }
    
    /**
     * @param int|string $offset
     *
     * @return Token
     */
    public function offsetGet( $offset )
    {
        $offset = $this->convertOffset($offset);
        
        return $offset !== null
            ? $this->tokens[ $offset ]
            : new Token( null, null, null, null);
    }
    
    /**
     * @param $offset
     * @param $value
     * @return void
     */
    public function offsetSet( $offset, $value )
    {
        $offset = $this->convertOffset($offset);
        
        if( $offset !== null ){
            $this->tokens[ $offset ] = $value;
        }
    }
    
    /**
     * @param $offset
     * @return void
     */
    public function offsetUnset( $offset )
    {
        unset($this->tokens[ $offset ] );
    }
    
    /**
     * @return int
     */
    public function count()
    {
        return $this->max_position;
    }
    
    /**
     * Process only name like 'current' and (regex) /(next|prev)\d/
     * Set if not set via getToken function
     *
     * @param $name
     *
     * @return array|null
     */
    public function __get($name)
    {
        // Process names like 'next1', 'next5', 'prev4', ...
        if( strpos( $name, 'next') !== false || strpos( $name, 'prev') !== false ){
            $this->$name = $this->getToken(
                substr($name, 0, 4),
                substr($name, 4)
            );
            
            return $this->$name;
        }
    
        // Process name 'current'
        if( $name === 'current' ){
            $this->$name = $this->tokens[$this->position];
            
            return $this->$name;
        }
        
        // Get token by the given position. Name example: '_34'. Could be used for debug purposes.
        if( strpos( $name, '_')){
            $this->$name = $this->getTokenFromPosition(substr($name, 1));
            
            return $this->$name;
        }
        
        return null;
    }
    
    /**
     * @param $name
     * @param $value
     */
    public function __set($name, $value)
    {
        $this->$name = $value;
    }
    
    /**
     * Process only name like 'current' and (regex) /(next|prev)\d/
     * Set if not set via getToken function
     *
     * @param $name
     *
     * @return bool
     */
    public function __isset($name)
    {
        // Process names like 'next1', 'next5', 'prev4', ...
        if( strpos($name, 'next') !== false || strpos($name, 'prev') !== false ){
            $this->$name = $this->getToken(
                substr($name, 0, 4),
                substr($name, 4)
            );
            
            return isset( $this->$name );
            
        }
    
        // Process name 'current'
        if( $name === 'current' ){
            $this->$name = $this->tokens[$this->position];
    
            return isset( $this->$name );
        }
    
        return false;
    }
}