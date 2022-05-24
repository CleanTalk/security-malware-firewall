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
        if( $this->tokens->next1->isTypeOf('non_code') ){
            $this->tokens->unsetTokens('next1');
            
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
        if( $this->tokens->current->type === 'T_WHITESPACE' ){
            
            // Completely delete the whitespace if nearby tokens allow it
            if(
                ! $this->tokens->prev1->isTypeOf('dont_trim_whitespace_around') &&
                ! $this->tokens->next1->isTypeOf('dont_trim_whitespace_around') &&
                (
                    $this->tokens->prev1->isTypeOf('strip_whitespace_around') ||
                    $this->tokens->next1->isTypeOf('strip_whitespace_around')
                )
            ){
                    $key                        = $this->tokens->prev1->key;
                    $this->tokens['current']    = $this->tokens->prev1;
                    $this->tokens['current'][3] = $key;
                    $this->tokens->unsetTokens( 'prev1' );
                
                return true;
            }
            
            // Otherwise, replace it with minimal whitespace
            $this->tokens['current'][1] = ' ';
        }
        
        return false;
    }
    
    
}