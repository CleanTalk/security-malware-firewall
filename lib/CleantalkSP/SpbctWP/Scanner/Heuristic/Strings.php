<?php


namespace CleantalkSP\SpbctWP\Scanner\Heuristic;


class Strings
{
    
    public $tokens;
    
    public function __construct( Tokens $tokens_handler )
    {
        $this->tokens = $tokens_handler;
    }
    
    /**
     * Deletes T_ENCAPSED_AND_WHITESPACE
     * Coverts T_ENCAPSED_AND_WHITESPACE to T_CONSTANT_ENCAPSED_STRING if could
     *
     * @param int $key
     *
     * @return false Always returns false, because it doesn't unset current element
     */
    public function convertToSimple($key)
    {
        if( $this->tokens->isCurrentTypeOf('T_ENCAPSED_AND_WHITESPACE') &&
            $this->tokens->isNextEqualTo('"') &&
            $this->tokens->isPrevEqualTo('"')
        ){
            $this->tokens->unsetTokens('next1', 'prev1');
    
            $this->tokens->tokens[$key] = array(
                'T_CONSTANT_ENCAPSED_STRING',
                '\'' . $this->tokens->current[1] . '\'',
                $this->tokens->current[2],
            );
        }
        
        return false;
    }
    
    /**
     * Convert chr('\xNN') to 'a'
     *
     * @param int $key
     *
     * @return false Always returns false, because it doesn't unset current element
     */
    public function convertChrFunctionToString($key)
    {
        if(
            $this->tokens->isCurrentEqualTo(')') &&
            $this->tokens->isInGroup(array('T_LNUMBER', 'T_CONSTANT_ENCAPSED_STRING'), 'prev') &&
            $this->tokens->isPrevEqualTo('(', 2) &&
            $this->tokens->isPrevTokenTypeOfGroup('T_STRING', 3) &&
            $this->tokens->isPrevEqualTo('chr', 3)
        ){
            $char_num     = (int)trim($this->tokens->prev1[1], '\'"');
            $this->tokens->tokens[$key] = array(
                'T_CONSTANT_ENCAPSED_STRING',
                '\'' . (chr($char_num) ?: '') . '\'',
                $this->tokens->prev3[2],
            );
            $this->tokens->unsetTokens('prev1', 'prev2', 'prev3');
        }
        
        return false;
    }
    
    /**
     * Convert chars present like "\xNN" to their symbols
     *
     * @param int $key
     *
     * @return false Always return false, do not change token structure ever
     */
    public function convertHexSymbolsToString($key)
    {
        // Convert "\xNN" to 'a'
        if(
            $this->tokens->isCurrentTypeOf('T_CONSTANT_ENCAPSED_STRING') &&
            (isset($this->tokens->current[1][0]) && $this->tokens->current[1][0] === '"') &&
            preg_match('@\\\\[A-Z\d]{3}@', $this->tokens->current[1])
        ){
            preg_match_all('@(\\\\[a-zA-Z\d]{3})@', $this->tokens->current[1], $matches);
            $matches         = $matches[0];
            $replacements    = array_map(
                static function ($elem){
                    return eval("return \"$elem\";");
                },
                $matches
            );
            $this->tokens->tokens[$key][1] = str_replace($matches, $replacements, $this->tokens->tokens[$key][1]);
        }
        
        return false;
    }
    
    /**
     * Concatenates simple strings
     *
     * @param int $key
     *
     * @return bool have the function unset the current element
     */
    public function concatenateSimpleStrings($key){
    
        if(
            $this->tokens->isCurrentTypeOf('T_ENCAPSED_AND_WHITESPACE') &&
            $this->tokens->isNextTypeOf('T_ENCAPSED_AND_WHITESPACE')
        ){
            $this->tokens->tokens[$key+1] = array(
                'T_ENCAPSED_AND_WHITESPACE',
                $this->tokens->next1[1].$this->tokens->next1[1],
                $this->tokens->current[2],
            );
            $this->tokens->unsetTokens('current');
            
            return true;
        }
        
        return false;
    }
    
    /**
     * Concatenates 'a'.'b' and "a"."b" to 'ab'
     *
     * @param int $key
     *
     * @return false Always returns false, because it doesn't unset current element
     */
    public function concatenateComplexStrings($key)
    {
        if(
            $this->tokens->isCurrentEqualTo('.') &&
            $this->tokens->isInGroup(array('T_LNUMBER', 'T_CONSTANT_ENCAPSED_STRING'), 'prev') &&
            $this->tokens->isInGroup(array('T_LNUMBER', 'T_CONSTANT_ENCAPSED_STRING'), 'next')
        ){
                $this->tokens->prev1[1] = $this->tokens->prev1[1][0] === '"'
                    ? '\'' . preg_replace("/'/", '\'', substr($this->tokens->prev1[1], 1, -1))
                    : substr($this->tokens->prev1[1], 0, -1);
                $this->tokens->next1[1] = $this->tokens->next1[1][0] === '"'
                    ? preg_replace("/'/", '\'', substr($this->tokens->next1[1], 1, -1)) . '\''
                    : substr($this->tokens->next1[1], 1);
                
                $this->tokens->tokens[$key] = array(
                    'T_CONSTANT_ENCAPSED_STRING',
                    $this->tokens->prev1[1] . $this->tokens->next1[1],
                    $this->tokens->prev1[2],
                );
                $this->tokens->unsetTokens('prev1', 'next1');
            }
        
        return false;
    }
}