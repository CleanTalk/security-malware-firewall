<?php


namespace CleantalkSP\SpbctWP\Scanner\Heuristic;


class Transformations
{
    /**
     * @var Tokens
     */
    private $token_handler;
    
    public function __construct( Tokens $tokens_handler )
    {
        $this->token_handler = $tokens_handler;
    }
    
    // Decode for base64
    public function decodeData(&$tokens, $key)
    {
        if( $tokens[ $key ][0] === 'T_STRING' ){
            
            $next = $this->token_handler->getRange($key + 1, $key + 2 );
            
            if( isset( $next[1] ) && $next[1][0] === 'T_CONSTANT_ENCAPSED_STRING' ){
                
                switch( $tokens[ $key ][1] ){
                    case 'base64_decode':
                        $data = base64_decode( $next[1][1] );
                        break;
                    case 'urldecode':
                        $data = urldecode( $next[1][1] );
                        break;
                    case 'rawurldecode':
                        $data = rawurldecode( $next[1][1] );
                        break;
                    case 'gzinflate':
                        $data = gzinflate( $next[1][1] );
                        break;
                    case 'str_rot13':
                        $data = str_rot13( $next[1][1] );
                        break;
                    default:
                        $data = false;
                }
                
                // Replacing function and data with it's result
                // decode_func('ENCODED_DATA') -> 'DECODED_DATA'
                if( $data ){
                    $tokens[ $key ] = array( 'T_CONSTANT_ENCAPSED_STRING', '\'' . $data . '\'', $tokens[ $key ][2] );
                    // @todo Check for second parameter for gzinflate and base64_decode functions
                    unset( $tokens[$key + 1 ], $tokens[$key + 2 ], $tokens[$key + 3 ] );
                }
                
                if( $data ){
                    
                    // Decompress from GZ gzuncompress
                    $prev = $this->token_handler->getRange($key - 2, $key - 1 );
                    if( isset( $prev[0] ) && $prev[0][0] === 'T_STRING' && $prev[0][1] === 'gzuncompress' ){
                        $data = gzuncompress( $data );
                        if( $data ){
                            
                            unset( $tokens[$key - 1  ], $tokens[$key - 2 ], $tokens[$key + 4 ] );
                            $tokens[ $key ] = array( 'T_CONSTANT_ENCAPSED_STRING', '\'' . $data . '\'', $tokens[ $key ][2] );
                            $data                 = token_get_all( '<?php ' . $data );
                            
                            if( $data ){
                                unset( $data[0] );
                                $tokens = array_merge($tokens, $data );
                            }
                            
                        }
                    }
                }
            }
        }
    }
}