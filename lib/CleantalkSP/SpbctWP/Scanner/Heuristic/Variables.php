<?php


namespace CleantalkSP\SpbctWP\Scanner\Heuristic;


class Variables
{
    public $variables     = array();
    public $variables_bad = array();
    public $arrays        = array();
    public $constants     = array();
    
    /**
     * @var Tokens
     */
    public $tokens;
    
    private $variables_types_to_concat = array(
        'T_CONSTANT_ENCAPSED_STRING',
        // 'T_ENCAPSED_AND_WHITESPACE',
        'T_LNUMBER',
        'T_DNUMBER',
    );
    
    private $sequences = array(
        
        'define_constant' => array(
            array( 'T_STRING', 'define' ),
            array( '__SERV', '(', ),
            array( 'T_CONSTANT_ENCAPSED_STRING' ),
            array( '__SERV', ',', ),
            array( 'T_CONSTANT_ENCAPSED_STRING' )
        ),
        
        'array_equation_array' => array(
            array( '__SERV', '=', ),
            array( 'T_ARRAY' ),
            array( '__SERV', '(', ),
        ),
        
        'array_equation_square_brackets' => array(
            array( '__SERV', '=', ),
            array( '__SERV', '[', ),
        )
    );
    
    public $variables_bad_default = array(
        '$_POST',
        '$_GET',
    );
    
    public function __construct( Tokens $tokens_handler )
    {
        $this->tokens = $tokens_handler;
    }
    
    /**
     * Replaces ${'string'} to $variable
     *
     * @param int $key
     *
     * @return false Always returns false, because it doesn't unset current element
     */
    public function convertVariableStrings($key)
    {
        if(
            $this->tokens->isCurrentEqualTo('$') &&
            $this->tokens->isNextEqualTo('{') &&
            $this->tokens->isNextTypeOf('T_CONSTANT_ENCAPSED_STRING', 2)
        ){
            $this->tokens->tokens[$key] = array(
                'T_VARIABLE',
                '$' . trim($this->tokens->next2[1], '\'"'),
                $this->tokens->next2[2],
            );
            $this->tokens->unsetTokens('next1','next2','next3');
        }
        
        return false;
    }
    
    /**
     * Array equation via 'Array' word
     * $arr = array();
     *
     * @param int     $key
     *
     * @return false Always returns false, because it doesn't unset current element
     */
    public function updateArray_equation($key)
    {
        if( $this->tokens->checkSequenceFromPosition($key + 1, $this->sequences['array_equation_array']) ){
            $variable_end = $this->tokens->searchForward($key, ';') - 1;
            if( $variable_end ){
                $arr_tokens = $this->tokens->getRange($key + 4, $variable_end - 1);
                foreach( $arr_tokens as $array_token ){
                    if( $this->tokens->isInGroup(array('T_CONSTANT_ENCAPSED_STRING', 'T_LNUMBER'), $array_token) ){
                        $this->arrays[ $this->tokens->current[1] ][] = array(
                            $array_token[0],
                            $array_token[1],
                            $array_token[2],
                        );
                    }
                }
            }
        }
        
        return false;
    }
    
    /**
     * Array equation via '[]' operator
     * $arr = [];
     *
     * @param int     $key
     *
     * @return false returns false if current token( $tokens[ $key ] ) was unset or true if isn't
     */
    public function updateArray_equationShort($key)
    {
        if( $this->tokens->checkSequenceFromPosition($key + 1, $this->sequences['array_equation_square_brackets']) ){
            $variable_end = $this->tokens->searchForward($key, ';') - 1;
            if( $variable_end ){
                $array_tokens = $this->tokens->getRange($key + 3, $variable_end - 1);
                foreach( $array_tokens as $array_token ){
                    if( $this->tokens->isInGroup(array('T_CONSTANT_ENCAPSED_STRING', 'T_LNUMBER'), $array_token) ){
                        $this->arrays[ $this->tokens->current[1] ][] = array(
                            'T_CONSTANT_ENCAPSED_STRING',
                            $array_token[1],
                            $array_token[2]
                        );
                    }
                }
            }
        }
        
        return false;
    }
    
    /**
     * Array. New element equation via
     * $arr[] = 'value';
     *
     * @param int $key
     *
     * @return false returns false if current token( $tokens[ $key ] ) was unset or true if isn't
     */
    public function updateArray_newElement($key)
    {
        if(
            $this->tokens->isNextEqualTo('[') &&
            $this->tokens->isNextEqualTo(']', 2) &&
            $this->tokens->isNextEqualTo('=', 3)
        ){
            $var_temp = $this->tokens->getRange(
                $key + 4,
                $this->tokens->searchForward($key, ';') - 1
            );
            
            if( $var_temp ){
                $var_temp = $var_temp[0];
                if( $this->tokens->isInGroup(array('T_CONSTANT_ENCAPSED_STRING', 'T_LNUMBER'), $var_temp) ){
                    $this->arrays[ $this->tokens->current[1] ][] = array(
                        $var_temp[0],
                        $var_temp[1],
                        $var_temp[2],
                    );
                }
            }
        }
        
        return false;
    }
    
    /**
     * Simple equation
     * $a = 'value';
     *
     * @param int $key
     *
     * @return false returns false if current token( $tokens[ $key ] ) was unset or true if isn't
     */
    public function updateVariables_equation($key)
    {
        // Simple equation
        // $a = 'value';
        if(
            $this->tokens->isCurrentTypeOf('T_VARIABLE') &&
            $this->tokens->isNextEqualTo('=')
        ){
            $variable_end = $this->tokens->searchForward($key, ';') - 1;
            if($variable_end){
                $var_temp = $this->tokens->getRange($key + 2, $variable_end);
                $var_temp = count($var_temp) === 3 && $var_temp[0] === '"' &&  $var_temp[1][0] === 'T_ENCAPSED_AND_WHITESPACE' && $var_temp[2] === '"'
                    ? array( array( 'T_CONSTANT_ENCAPSED_STRING', '\'' . $var_temp[1][1] . '\'', $var_temp[1][2] ) )// Variable in a double quotes like $a = "$b";
                    : $var_temp; // // Variable in a single quotes like $a = 'value';
            
                $this->variables[ $this->tokens->current[1] ] = $var_temp;
            }
        }
        
        return false;
    }
    
    /**
     * Equation with concatenation.
     * $a .= 'value';
     *
     * @param int $key
     *
     * @return true returns false if current token( $tokens[ $key ] ) was unset or true if isn't
     */
    public function updateVariables_equationWithConcatenation($key)
    {
        if(
            $this->tokens->isCurrentTypeOf('T_VARIABLE') &&
            $this->tokens->isNextTypeOf('T_CONCAT_EQUAL')
        ){
            
            $var_temp = $this->tokens->getRange(
                $key + 2,
                $this->tokens->searchForward($key, ';') - 1
            );
            
            if( $var_temp ){
                
                // Variable in a double quotes like $a .= "$b";
                // We don't touch variables in a single quotes like $a .= 'value';
                if(
                    count( $var_temp ) === 3 &&
                    $this->tokens->isTokenEqualTo($var_temp[0], '"') &&
                    $this->tokens->isTokenEqualTo($var_temp[2], '"') &&
                    $this->tokens->isTypeOf('T_ENCAPSED_AND_WHITESPACE', $var_temp[1])
                ){
                    $var_temp = array(
                        array(
                            'T_CONSTANT_ENCAPSED_STRING',
                            '\'' . $var_temp[1][1] . '\'',
                            $var_temp[1][2],
                        ),
                    );
                }

                $this->variables[ $this->tokens->current[1] ] = isset( $this->variables[ $this->tokens->current[1] ] )
                    ? array_merge($this->variables[ $this->tokens->current[1] ], $var_temp)
                    : $var_temp;
            }
        }
        
        return false;
    }
    
    /**
     * Search and remember constants definition
     * define('CONSTANT_NAME','CONSTANT_VALUE'
     *
     * @param int $key
     *
     * @return false returns false if current token( $tokens[ $key ] ) was unset or true if isn't
     */
    public function updateConstants($key)
    {
        // Constants
        if(
            $this->tokens->isNextTypeOf('T_CONSTANT_ENCAPSED_STRING', 4) &&
            $this->tokens->checkSequenceFromPosition($key, $this->sequences['define_constant'] )
        ){
            $constant_name = trim( $this->tokens->next2[1], '\'"' );
            $this->constants[ $constant_name ] = trim( $this->tokens->next4[1], '\'"' );
        }
        
        return false;
    }
    
    /**
     * Concatenate variable in $this->variables
     *
     * @return void
     */
    public function concatenate(){
        
        foreach($this->variables as $var_name => $var){
            for($i = count($var)-1; $i > 0; $i--){
                $curr = isset($var[$i])   ? $var[$i]   : null;
                $next = isset($var[$i-1]) ? $var[$i-1] : null;
                if(
                    in_array( $curr[0], $this->variables_types_to_concat, true ) &&
                    in_array( $next[0], $this->variables_types_to_concat, true )
                ){
                    Controller::_concatenate($this->variables[$var_name], $i, true);
                }
            }
        }
    }
    
    /**
     * Replace variables with it's content
     *
     * @param int $key
     *
     * @return void
     */
    public function replace($key)
    {
            // Replace variable
            if( $this->tokens->isCurrentTypeOf('T_VARIABLE') ){
                
                // Arrays
                if( $this->isTokenInArrays($this->tokens->current) ){
                    
                    // Array element
                    if(
                        $this->tokens->isNextEqualTo('[') &&
                        $this->tokens->isNextTypeOf('T_LNUMBER') &&
                        $this->tokens->isNextEqualTo(array('.', '(', ';'), 3)
                    ){
                        if( isset($this->arrays[ $this->tokens->current[1] ][ $this->tokens->next1[1][1] ][1]) ){
                            if( $this->tokens->isNextEqualTo('(', 3) ){
                                $this->tokens->tokens[$key] = array(
                                    'T_STRING',
                                    substr($this->arrays[ $this->tokens->current[1] ][ $this->tokens->next1[1][1] ][1], 1, -1),
                                    $this->tokens->current[2],
                                );
                            }elseif( $this->tokens->isNextEqualTo('.', 3) ){
                                $this->tokens->tokens[$key] = array(
                                    'T_CONSTANT_ENCAPSED_STRING',
                                    '\'' . $this->arrays[ $this->tokens->current[1] ][ $this->tokens->next1[1][1] ][1] . '\'',
                                    $this->tokens->current[2],
                                );
                            }else{
                                $this->tokens->tokens[$key] = array(
                                    $this->arrays[ $this->tokens->current[1] ][ $this->tokens->next1[1][1] ][0],
                                    '\'' . $this->arrays[ $this->tokens->current[1] ][ $this->tokens->next1[1][1] ][1] . '\'',
                                    $this->tokens->current[2],
                                );
                            }
                            
                            $this->tokens->unsetTokens('next1', 'next2', 'next3');
                        }
                    }
                    
                // Variables
                }elseif(
                    $this->isTokenInVariables($this->tokens->current) &&
                    count($this->variables[ $this->tokens->current[1] ]) === 1 &&
                    in_array($this->variables[ $this->tokens->current[1] ][0][0], $this->variables_types_to_concat, true)
                ){
                    // Array or symbol from string replacement
                    if(
                        $this->tokens->isNextEqualTo(array('[', '{') ) &&
                        $this->tokens->isNextTypeOf('T_LNUMBER', 2)
                    ){
                        if( isset(
                            $this->variables[ $this->tokens->current[1] ][0][1][ $this->tokens->next2[1] ],
                            $this->variables[ $this->tokens->current[1] ][0][1][ $this->tokens->next2[1] + 1]
                        ) ){
                            $this->tokens->tokens[$key] = array(
                                'T_CONSTANT_ENCAPSED_STRING',
                                '\'' . $this->variables[$this->tokens->current[1]][0][1][ $this->tokens->next2[1] + 1] . '\'',
                                $this->tokens->current[2],
                            );
                            $this->tokens->unsetTokens('next1', 'next2', 'next3');
                        }
                        
                    // @todo Learn to replace $$var to $var_value
                    // }elseif( is_array( $next ) && $next === 'T_VARIABLE' ){
                    
                    // Single variable replacement
                    }else{
                        
                        // Variables function
                        if( $this->tokens->isNextEqualTo('(') ){
                            $this->tokens->tokens[ $key ] = array(
                                'T_STRING',
                                substr($this->variables[$this->tokens->current[1]][0][1], 1, -1),
                                $this->tokens->current[2],
                            );
                            // Variables in double/single quotes
                        }elseif( ! $this->tokens->isNextTokenTypeOfGroup('equation') ){
                            $this->tokens->tokens[ $key ] = array(
                                ! $this->tokens->isPrevEqualTo('"') ? 'T_CONSTANT_ENCAPSED_STRING' : 'T_ENCAPSED_AND_WHITESPACE',
                                ! $this->tokens->isPrevEqualTo('"') ? $this->variables[$this->tokens->current[1]][0][1] : substr($this->variables[$this->tokens->current[1]][0][1],1,-1),
                                $this->tokens->current[2],
                            );
                        }
                    }
                }
                
            // Constant replacement
            // @todo except cases when name of constant equal to something. Check type and siblings tokens
            }elseif( $this->isTokenInConstants($this->tokens->current) ){
                $this->tokens->tokens[$key] = array(
                    'T_CONSTANT_ENCAPSED_STRING',
                    '\'' . $this->constants[$this->tokens->current[1]] . '\'',
                    $this->tokens->current[2],
                );
            }
    }
    
    /**
     * Add variables with user input to BAD list
     */
    public function detectBad()
    {
        do{
            $bad_vars_count = count($this->variables_bad);
            
            foreach( $this->variables as $var_name => &$variable ){
                foreach( $variable as &$var_part ){
                    if(
                        $var_part[0] === 'T_VARIABLE' &&
                        (in_array($var_part[1], $this->variables_bad_default, true) || isset($this->variables_bad[$var_part[1]]))
                    ){
                        $this->variables_bad[$var_name] = $variable;
                        continue(2);
                    }
                }
                unset($var_part);
            }
            unset($variable);
        }while( $bad_vars_count !== count($this->variables_bad) );
    }
    
    /**
     * Check the set of tokens for bad variables
     *
     * @param $tokens
     *
     * @return bool
     */
    public function isSetOfTokensHasBadVariables($tokens)
    {
        return in_array('T_VARIABLE', array_column($tokens, 0), true) &&
               (
                   array_intersect(array_column($tokens, 1), $this->variables_bad_default)
                   // @todo fix the bad variables_bad gathering
                   // array_intersect(array_column($tokens, 1), array_keys($this->variables_bad))
               );
    }
    
    /**
     * Check if the given token in arrays
     *
     * @param $token
     *
     * @return bool
     */
    public function isTokenInArrays($token)
    {
        return $this->tokens->isTypeOf('T_VARIABLE', $token) && isset($this->arrays[$token[1]]);
    }
    
    /**
     * Check if the given token in arrays
     *
     * @param $token
     *
     * @return bool
     */
    public function isTokenInVariables($token)
    {
        return $this->tokens->isTypeOf('T_VARIABLE', $token) && isset($this->variables[$token[1]]);
    }
    
    /**
     * Check if the given token in arrays
     *
     * @param $token
     *
     * @return bool
     */
    public function isTokenInConstants($token)
    {
        return $this->tokens->isTypeOf('T_STRING', $token) && isset($this->constants[$token[1]]);
    }
}