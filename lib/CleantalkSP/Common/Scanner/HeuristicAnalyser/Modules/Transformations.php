<?php

namespace CleantalkSP\Common\Scanner\HeuristicAnalyser\Modules;

use CleantalkSP\Common\Scanner\HeuristicAnalyser\DataStructures\Token;

class Transformations
{
    /**
     * @var Tokens
     */
    private $tokens;

    public function __construct(Tokens $tokens)
    {
        $this->tokens = $tokens;
    }

    /**
     * @param $_key
     *
     * @return bool Returns true if $this->tokens were modified | false otherwise
     * @todo Check for second parameter for gzinflate and base64_decode functions
     * Decode data with functions:
     *  - base64_decode
     *  - urldecode
     *  - rawurldecode
     *  - gzinflate
     *  - str_rot13
     *  - gzuncompress
     *
     * @psalm-suppress PossiblyUnusedMethod
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public function decodeData($_key)
    {
        if (
            $this->tokens->current->type === 'T_STRING' &&
            $this->tokens->next2->type === 'T_CONSTANT_ENCAPSED_STRING'
        ) {
            //@psalm-suppress UnusedVariable
            switch ( $this->tokens->current->value ) {
                case 'base64_decode':
                    $data = base64_decode((string)$this->tokens->next2->value);
                    break;
                case 'urldecode':
                    return $this->transformUrlDecodeIntoTokens((string)$this->tokens->next2->value);
                case 'rawurldecode':
                    $data = rawurldecode((string)$this->tokens->next2->value);
                    break;
                case 'gzinflate':
                    $data = gzinflate((string)$this->tokens->next2->value);
                    break;
                case 'str_rot13':
                    $data = str_rot13((string)$this->tokens->next2->value);
                    break;
                case 'gzuncompress':
                    $data = gzuncompress((string)$this->tokens->next2->value);
                    break;
                case 'hex2bin':
                    //run hex2bin transformation
                    return $this->transformHexStringIntoTokens((string)$this->tokens->next2->value);
                default:
                    $data = false;
            }

            /**
             * This code is disabled because of incomplete of other parts except hex2bin
             */
            //==
            // Replacing function and data with its result
            // EXAMPLE: decode_func('ENCODED_DATA') -> 'DECODED_DATA'
            //if ( $data ) {
            //    $this->tokens->unsetTokens('next1', 'next2', 'next3');
            //    $this->tokens['current'] = new Token(
            //        'T_CONSTANT_ENCAPSED_STRING',
            //        '\'' . $data . '\'',
            //        $this->tokens->current->line,
            //        $this->tokens->current->key
            //    );
            //
            //    return true;
            //}
            if ( ! $data ) {
                return false;
            }
            //==
            //possible reasons
            /* @todo make new data merge wth tokens
             * if( $data ){
             * // Decompress from GZ gzuncompress
             * $prev = $this->tokens->getRange( $key - 2, $key - 1 );
             * if( isset( $prev[0] ) && $prev[0][0] === 'T_STRING' && $prev[0][1] === 'gzuncompress' ){
             * $data = gzuncompress( $data );
             * if( $data ){
             * $this->tokens->unsetTokens('prev1', 'prev2', 'next4');
             * $this->tokens['current'] = new Token(
             * 'T_CONSTANT_ENCAPSED_STRING',
             * '\'' . $data . '\'',
             * $this->tokens->current->line,
             * $this->tokens->current->key
             * );
             * $data = token_get_all( '<?php ' . $data );
             *
             * if( $data ){
             * unset( $data[0] );
             * $tokens = array_merge($tokens, $data );
             * }
             *
             * }
             * }
             * }
             */
        }

        return false;
    }

    /**
     * Get new tokens to global tokens from hex string.
     * @param string $hex_string
     * @return bool
     */
    private function transformHexStringIntoTokens($hex_string)
    {
        if ( is_string($hex_string) ) {
            $data = @hex2bin($hex_string);
            if ( ! $data ) {
                //data is false, check if hex string is quoted
                $data = str_replace(array('\'', '"'), '', $hex_string);
                $data = @hex2bin($data);
            }
            if ( $data ) {
                //unset unnecessary tokens
                if ( $this->tokens->prev1->value === '@' ) {
                    $this->tokens->unsetTokens($this->tokens->prev1[3]);
                }

                $this->tokens->unsetTokens('next1', 'next2');

                //add new tokens to the line
                $this->tokens['current'] = new Token(
                    'T_CONSTANT_ENCAPSED_STRING',
                    '"' . $data . '"',
                    $this->tokens->current->line,
                    $this->tokens->current->key
                );
                return true;
            }
        }
        //hex2bin failed
        return false;
    }

    /**
     * Transform URL-encoded string into tokens.
     * @param string $url_encoded_string
     * @return bool
     */
    private function transformUrlDecodeIntoTokens($url_encoded_string)
    {
        if (is_string($url_encoded_string)) {
            $decoded_data = @urldecode($url_encoded_string);

            // Unset unnecessary tokens
            $this->tokens->unsetTokens('next1', 'next2', 'next3');

            // Add new token with the decoded data
            $this->tokens['current'] = new Token(
                'T_CONSTANT_ENCAPSED_STRING',
                $decoded_data,
                $this->tokens->current->line,
                $this->tokens->current->key
            );

            return true;
        }
        return false;
    }
}
