<?php


namespace CleantalkSP\SpbctWP\Scanner\Heuristic;


/**
 * Array with token
 * [
 *    0 => (string) TOKEN_TYPE,
 *    1 => (mixed)  TOKEN_VALUE
 *    2 => (int)    DOCUMENT_STRING_NUMBER
 * ]
 *
 * @property array|null prev4
 * @property array|null prev3
 * @property array|null prev2
 * @property array|null prev1
 * @property array|null current
 * @property array|null next1
 * @property array|null next2
 * @property array|null next3
 * @property array|null next4
 */
class Tokens
{
    /**
     * @var array of arrays with tokens with PHP code
     * [
     *    0 => (string) TOKEN_TYPE,
     *    1 => (mixed)  TOKEN_VALUE
     *    2 => (int)    DOCUMENT_STRING_NUMBER
     * ]
     */
    public $tokens;
    
    /**
     * @var int
     */
    private $max_index;
    
    /**
     * @var array of arrays without code
     * Contain tokens with comments, HTML and so on
     * [
     *    0 => (string) TOKEN_TYPE,
     *    1 => (mixed)  TOKEN_VALUE
     *    2 => (int)    DOCUMENT_STRING_NUMBER
     * ]
     */
    public $comments = array();
    
    /**
     * @var array of arrays with HTML
     * [
     *    0 => (string) TOKEN_TYPE,
     *    1 => (mixed)  TOKEN_VALUE
     *    2 => (int)    DOCUMENT_STRING_NUMBER
     * ]
     */
    public $html     = array();
    
    /**
     * @var string[] Current token
     */
    public $current;
    
    /**
     * @var int
     */
    private $current_key;
    
    public $equation__token_group = array(
        '=',
        'T_CONCAT_EQUAL',
        'T_MINUS_EQUAL',
        'T_MOD_EQUAL',
        'T_MUL_EQUAL',
        'T_AND_EQUAL',
        'T_OR_EQUAL',
        'T_PLUS_EQUAL',
        'T_POW_EQUAL',
        'T_SL_EQUAL',
        'T_SR_EQUAL',
        'T_XOR_EQUAL',
    );
    
    /**
     * @var string[] non PHP tokens
     */
    private $non_code__token_group = array(
        'T_INLINE_HTML',
        'T_COMMENT',
        'T_DOC_COMMENT',
    );
    
    /**
     * @var string[] non PHP tokens
     */
    private $html__token_group = array(
        'T_INLINE_HTML',
    );
    
    /**
     * @var string[] non PHP tokens
     */
    private $comments__token_group = array(
        'T_COMMENT',
        'T_DOC_COMMENT',
    );
    
    /**
     * @var string[] trimming whitespaces around this tokens
     */
    private $strip_whitespace_around__token_group  = array(
        
        '__SERV', // Tokens without type
        
        'T_WHITESPACE', // /\s*/
        'T_CLOSE_TAG',
        'T_CONSTANT_ENCAPSED_STRING', // String in quotes
        
        // Equals
        'T_DIV_EQUAL',
        'T_BOOLEAN_OR',
        'T_BOOLEAN_AND',
        'T_IS_EQUAL',
        'T_IS_GREATER_OR_EQUAL',
        'T_IS_IDENTICAL',
        'T_IS_NOT_EQUAL',
        'T_IS_SMALLER_OR_EQUAL',
        'T_SPACESHIP',
        
        // Assignments
        'T_CONCAT_EQUAL',
        'T_MINUS_EQUAL',
        'T_MOD_EQUAL',
        'T_MUL_EQUAL',
        'T_AND_EQUAL',
        'T_OR_EQUAL',
        'T_PLUS_EQUAL',
        'T_POW_EQUAL',
        'T_SL_EQUAL',
        'T_SR_EQUAL',
        'T_XOR_EQUAL',
        
        // Bit
        'T_SL', // <<
        'T_SR', // >>
        
        // Uno
        'T_INC', // ++
        'T_DEC', // --
        'T_POW', // **
        
        // Cast type
        'T_ARRAY_CAST',
        'T_BOOL_CAST',
        'T_DOUBLE_CAST',
        'T_OBJECT_CAST',
        'T_STRING_CAST',
        
        // Different
        'T_START_HEREDOC', // <<<
        'T_NS_SEPARATOR', // \
        'T_ELLIPSIS', // ...
        'T_OBJECT_OPERATOR', // ->
        'T_DOUBLE_ARROW', // =>
        'T_DOUBLE_COLON', // ::
        'T_PAAMAYIM_NEKUDOTAYIM', // ::
    );
    
    private $dont_trim_whitespace_around__token_group = array(
        'T_ENCAPSED_AND_WHITESPACE',
        'T_OPEN_TAG',
    );
    
    private $include__token_group = array(
        'T_INCLUDE',
        'T_REQUIRE',
        'T_INCLUDE_ONCE',
        'T_REQUIRE_ONCE',
    );
    
    private $one_line__token_group = array(
        'T_NAMESPACE',
        'T_CLASS',
        'T_TRAIT',
        'T_PUBLIC',
        'T_PROTECTED',
        'T_PRIVATE',
        'T_FUNCTION',
        'T_FOREACH',
        'T_FOR',
        'T_DO',
        'T_WHILE',
        'T_SWITCH',
    );
    
    /**
     * Parse code and transform it to array of arrays with token like
     * [
     *    0 => (string) TOKEN_TYPE,
     *    1 => (mixed)  TOKEN_VALUE
     *    2 => (int)    DOCUMENT_STRING_NUMBER
     * ]
     *
     * Convert all tokens to the above mentioned format
     *
     * Single tokens like '.' or ';' receive TOKEN_TYPE like '__SERV'
     * Single tokens like '.' or ';' receive DOCUMENT_STRING_NUMBER from the previous token
     *
     * @param $text
     *
     * @return mixed
     */
    public function getTokensFromText( $text )
    {
        $this->tokens = @token_get_all( $text );
        $this->convertTokensToStandard();
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
    private function convertTokensToStandard(){
    
        $prev_token[2] = 1;
        foreach($this->tokens as $key => &$token){
            
            // Convert if
            $token = is_array($token)
                ? array(token_name($token[0]), $token[1], $token[2])
                : array('__SERV',              $token,    $prev_token[2]);
            
            $prev_token = $token;
        }
    }
    
    public function setMaxKey(){
        $this->max_index = max(array_keys($this->tokens));
    }
    
    /**
     * @param int $key
     */
    public function newIteration($key)
    {
        $this->current_key = $key;
        $this->setIterationTokens();
    }
    
    /**
     * set tokens from next{$depth} to prev{$depth}
     *
     * @param int $depth
     */
    public function setIterationTokens($depth = 4)
    {
        $this->current = $this->tokens[$this->current_key];
        for( ; $depth !== 0; $depth-- ){
            $this->{'next'.$depth};
            $this->{'prev'.$depth};
        }
    }
    
    
    /**
     * Gather tokens back in string
     * Using all tokens if non passed
     *
     * @param array $input Array of lexems
     *
     * @return string
     */
    public function glueTokens($input = array())
    {
        return implode('', array_column($input ?: $this->tokens, 0));
    }
    
    public function isInGroup($group, $token_or_direction, $steps = 1)
    {
        $group = is_array($group)
            ? $group
            : $this->{$group . '__token_group'};
        
        $token = is_array($token_or_direction)
            ? $token_or_direction
            : $this->getToken($token_or_direction, $steps);
        
        return isset($token[0], $group) && in_array($token[0], $group, true);
    }
    
    public function isCurrentTokenInGroup( $group ){
        $group .= '__token_group';
        return isset($this->current[0], $this->$group) && in_array($this->current[0], $this->$group, true );
    }
    
    public function isNextTokenTypeOfGroup( $group, $steps = 1){
        $group .= '__token_group';
        $token = $this->{'next'.$steps}; // Initiating __get() method
        return isset($token[0], $this->$group) && in_array($token[0], $this->$group, true );
    }
    
    public function isPrevTokenTypeOfGroup( $group, $steps = 1){
        $group .= '__token_group';
        $token = $this->{'prev'.$steps}; // Initiating __get() method
        return isset($token[0], $this->$group) && in_array($token[0], $this->$group, true );
    }
    
    /**
     * Check if the current token is type of given string
     *
     * @param $token_type
     * @param $token
     *
     * @return bool
     */
    public function isTypeOf($token_type, $token)
    {
        return $token[0] === $token_type;
    }
    
    /**
     * Check if the current token is type of given string
     *
     * @param $token_type
     *
     * @return bool
     */
    public function isCurrentTypeOf($token_type)
    {
        return $this->current[0] === $token_type;
    }
    
    /**
     * Check if the current token is type of given string
     *
     * @param string $token_type
     * @param int    $step
     *
     * @return bool
     */
    public function isNextTypeOf($token_type, $step = 1)
    {
        return $this->isTypeOf($this->{'next' . $step}, $token_type);
    }
    
    
    /**
     * Check if the current token is type of given string
     *
     * @param string $token_type
     * @param int    $step
     *
     * @return bool
     */
    public function isPrevTypeOf($token_type, $step = 1)
    {
        return $this->isTypeOf($this->{'prev' . $step}, $token_type);
    }
    
    /**
     * Compares token value to given value
     *
     * @param array|null   $token
     * @param string|array $stings_to_compare_to
     *
     * @return bool
     */
    public function isTokenEqualTo($token, $stings_to_compare_to)
    {
        return isset($token[1]) && in_array($token[1], (array)$stings_to_compare_to, true);
    }
    
    /**
     * Compares next token value to given value
     *
     * @param string|array $string_or_array
     *
     * @return bool
     */
    public function isCurrentEqualTo($string_or_array)
    {
        return $this->isTokenEqualTo($this->current, $string_or_array);
    }
    
    /**
     * Compares next token value to given value
     *
     * @param string|array $string_or_array
     * @param int          $steps
     *
     * @return bool
     */
    public function isNextEqualTo($string_or_array, $steps = 1)
    {
        return $this->isTokenEqualTo($this->{'next'.$steps}, $string_or_array);
    }
    
    /**
     * Compares previous token value to given value
     *
     * @param string|array $string_or_array
     * @param int          $steps
     *
     * @return bool
     */
    public function isPrevEqualTo($string_or_array, $steps = 1)
    {
        return $this->isTokenEqualTo($this->{'prev'.$steps}, $string_or_array);
    }
    
    /**
     * Returns position of the searched token
     * Search for needle === if needle is set
     *
     * @param              $start
     * @param string|array $needle
     * @param int          $depth of search. How far we should look for the token
     *
     * @return bool|int
     */
    public function searchForward($start, $needle, $depth = 250)
    {
        // Needle is an array with strings
        if( is_array($needle) ){
            for( $i = 0, $key = $start + 1; $i < $depth; $i++, $key++ ){
                if( isset($this->tokens[$key]) && in_array($this->tokens[$key][1], $needle, true) ){
                    return $key;
                }
            }
    
        // Needle is a string
        }else{
            for( $i = 0, $key = $start + 1; $i < $depth; $i++, $key++ ){
                if( isset($this->tokens[$key]) && $this->tokens[$key][1] === $needle ){
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
        if( is_array($needle) ){
            for( $i = 0, $key = $start - 1; $i < $depth && $key > 0; $i--, $key-- ){
                if( isset($this->tokens[$key]) && in_array($this->tokens[$key][1], $needle, true) ){
                    return $key;
                }
            }
            
        // Needle is a string
        }else{
            for( $i = 0, $key = $start - 1; $i < $depth && $key > 0; $i--, $key-- ){
                if( isset($this->tokens[$key]) && $this->tokens[$key][1] === $needle ){
                    return $key;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Get next or previous token from $this->tokens
     * Searches on a certain depth
     *
     * @param string $direction
     * @param int    $steps
     *
     * @return array|null
     */
    public function getToken($direction = 'next', $steps = 1)
    {
        $out = null;
        
        switch($direction){
            case 'next':
                for( $key = $this->current_key, $curr_step = 0; ! $out && $key <= $this->max_index; $key++ ){
                    $curr_step = isset($this->tokens[$key]) ? ++$curr_step        : $curr_step;
                    $out       = $curr_step === $steps      ? $this->tokens[$key] : null;
                }
                break;
            case 'prev':
                for( $key = $this->current_key, $curr_step = 0; ! $out && $key >= 0; $key-- ){
                    $curr_step = isset($this->tokens[$key]) ? ++$curr_step        : $curr_step;
                    $out       = $curr_step === $steps      ? $this->tokens[$key] : null;
                }
                break;
        }
        
        return $out;
    }
    
    /**
     * Getting prev set lexem, Search for needle === if needle is set
     *
     * @param int $start
     * @param int $end
     *
     * @return array|false
     */
    public function getRange($start, $end)
    {
        if( $end !== false ){
            return array_slice($this->tokens, $start, $end - $start + 1);
        }
        
        return false;
    }
    
    /**
     * Unset token with given names
     *
     * @param mixed ...$tokens_positions
     */
    public function unsetTokens(...$tokens_positions)
    {
        foreach( $tokens_positions as $tokens_position ){
            
            if( $tokens_position === 'current' ){
                $key = $this->current_key;
                
            }else{
                $direction = substr($tokens_position, 0, 4);
                $depth     = substr($tokens_position, 0, -1);
                $key       = $direction === 'next'
                    ? $this->current_key + $depth
                    : $this->current_key - $depth;
            }
            unset($this->tokens[$key]);
            
        }
        
        // Resetting token from prev4 to next4
        if( ! in_array('current', $tokens_positions, true) ){
            $this->setIterationTokens();
        }
    }
    
    /**
     * @todo make it capable to compare variants of sequences. '(' to '(' or  '[',
     *
     * @param int   $position
     * @param array $sequence Array of lexemes
     *
     * @return bool
     */
    public function checkSequenceFromPosition( $position, $sequence ){
        
        foreach( $sequence as $offset => $token ){
            
            $position_to_check = $position + $offset;
            
            if( ! isset( $this->tokens[ $position_to_check ] ) ){
                return false;
            }
            
            // Both is arrays
            if( is_array( $token ) && is_array( $this->tokens[ $position_to_check ] ) ){
                
                // Compare first element
                if( $token[0] !== $this->tokens[ $position_to_check ][0] ){
                    return false;
                    
                    // Compare second if provided
                }elseif( isset( $token[1] ) && $token[1] !== $this->tokens[ $position_to_check ][1] ){
                    return false;
                }
                
                // At least one is not an array. Straight check
            }elseif( $token !== $this->tokens[ $position_to_check ] ){
                
                return false;
            }
        }
        
        return true;
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
        if( strpos($name, 'next') !== false || strpos($name, 'prev') !== false ){
            $this->$name = $this->getToken(substr($name, 0, 4), substr($name, 0, -1));
            
            return $this->$name;
            
        // Process name 'current'
        }elseif( $name === 'current' ){
            $this->$name = $this->tokens[$this->current_key];
            
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
            $this->$name = $this->getToken(substr($name, 0, 4), substr($name, 0, -1));
            
            return isset( $this->$name );
            
        // Process name 'current'
        }elseif( $name === 'current' ){
            $this->$name = $this->tokens[$this->current_key];
    
            return isset( $this->$name );
        }
        
        return false;
    }
}