<?php


namespace CleantalkSP\SpbctWP\Scanner\Heuristic;


class Simplifier
{
    /**
     * @var Tokens
     */
    private $tokens;
    
    public function __construct( Tokens $tokens_handler )
    {
        $this->tokens = $tokens_handler;
    }
    
    /**
     * Extracts non-code lexems in the separate property
     *
     * @param int     $key
     *
     * @return bool returns true if changes were made in original $tokens array or false if wasn't
     */
    public function deleteNonCodeTokens( $key )
    {
        if( $this->tokens->isCurrentTokenInGroup('non_code') ){
            $this->tokens->unsetTokens('current');
            
            return true;
        }
    
        return false;
    }
    
    /**
     * Strip long and useless whitespaces
     *
     * @param int $key
     *
     * @return bool returns true if changes were made in original $tokens array or false if isn't
     */
    public function stripWhitespaces($key)
    {
        if( $this->tokens->isCurrentTypeOf('T_WHITESPACE') ){
            
            // Completely delete the whitespace if nearby tokens allow it
            if(
                $this->tokens->isNextTokenTypeOfGroup('strip_whitespace_around') ||
                $this->tokens->isPrevTokenTypeOfGroup('strip_whitespace_around')
            ){
                $this->tokens->unsetTokens('current');
                
                return true;
            
            // Otherwise replace it with minimal whitespace
            }else{
                $this->tokens->tokens[$key][1] = ' ';
            }
        }
        
        return false;
    }
    
    
}