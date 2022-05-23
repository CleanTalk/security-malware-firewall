<?php


namespace CleantalkSP\SpbctWP\Scanner\Heuristic;


use CleantalkSP\SpbctWP\Scanner\Heuristic\DataStructures\Token;

class Transformations
{
    /**
     * @var Tokens
     */
    private $tokens;
    
    public function __construct( Tokens $tokens )
    {
        $this->tokens = $tokens;
    }
    
    /**
     * @todo Check for second parameter for gzinflate and base64_decode functions
     * Decode data with functions:
     *  - base64_decode
     *  - urldecode
     *  - rawurldecode
     *  - gzinflate
     *  - str_rot13
     *  - gzuncompress
     *
     * @param $key
     *
     * @return bool Returns true if $this->tokens were modified | false otherwise
     */
    public function decodeData($key)
    {
        if(
            $this->tokens->current->type === 'T_STRING' &&
            $this->tokens->next2->type === 'T_CONSTANT_ENCAPSED_STRING'
        ){
            switch( $this->tokens->current->value ){
                case 'base64_decode':
                    $data = base64_decode( $this->tokens->next2->value );
                    break;
                case 'urldecode':
                    $data = urldecode( $this->tokens->next2->value );
                    break;
                case 'rawurldecode':
                    $data = rawurldecode( $this->tokens->next2->value );
                    break;
                case 'gzinflate':
                    $data = gzinflate( $this->tokens->next2->value );
                    break;
                case 'str_rot13':
                    $data = str_rot13( $this->tokens->next2->value );
                    break;
                case 'gzuncompress':
                    $data = gzuncompress( $this->tokens->next2->value );
                    break;
                default:
                    $data = false;
            }
            
            // Replacing function and data with its result
            // decode_func('ENCODED_DATA') -> 'DECODED_DATA'
            if( $data ){
                $this->tokens->unsetTokens('next1', 'next2', 'next3');
                $this->tokens['current'] = new Token(
                    'T_CONSTANT_ENCAPSED_STRING',
                    '\'' . $data . '\'',
                    $this->tokens->current->line,
                    $this->tokens->current->key
                );
                
                return true;
            }
            
            /* @todo make new data merge wth tokens
            if( $data ){
                // Decompress from GZ gzuncompress
                $prev = $this->tokens->getRange( $key - 2, $key - 1 );
                if( isset( $prev[0] ) && $prev[0][0] === 'T_STRING' && $prev[0][1] === 'gzuncompress' ){
                    $data = gzuncompress( $data );
                    if( $data ){
                        $this->tokens->unsetTokens('prev1', 'prev2', 'next4');
                        $this->tokens['current'] = new Token(
                            'T_CONSTANT_ENCAPSED_STRING',
                            '\'' . $data . '\'',
                            $this->tokens->current->line,
                            $this->tokens->current->key
                        );
                        $data = token_get_all( '<?php ' . $data );
                        
                        if( $data ){
                            unset( $data[0] );
                            $tokens = array_merge($tokens, $data );
                        }
                        
                    }
                }
            }
            */
        }
        
        return false;
    }
}