<?php


namespace CleantalkSP\SpbctWP\Scanner\Heuristic;


use CleantalkSP\SpbctWP\Scanner\Heuristic\DataStructures\Token;
use CleantalkSP\DataStructures\ExtendedSplFixedArray;

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
            array( array('T_CONSTANT_ENCAPSED_STRING', 'T_LNUMBER') )
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
        '$_REQUEST',
        '$_COOKIE',
    );
    
    public function __construct( Tokens $tokens )
    {
        $this->tokens = $tokens;
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
            $this->tokens->current->value === '$' &&
            $this->tokens->next1->value === '{' &&
            $this->tokens->next2->type === 'T_CONSTANT_ENCAPSED_STRING'
        ){
            $this->tokens['current'] = new Token(
                'T_VARIABLE',
                '$' . trim($this->tokens->next2->value, '\'"'),
                $this->tokens->current->line,
                $this->tokens->current->key
            );
            $this->tokens->unsetTokens('next1','next2','next3');
            
            return true;
        }
        
        return false;
    }
    
    /**
     * Array equation via 'Array' word
     * $arr = array();
     *
     * @param int     $key
     *
     * @return false Always returns false, because it doesn't unset any elements
     */
    public function updateArray_equation($key)
    {
        // Check the sequence for array equation
        if(
            $this->tokens->current->value !== '=' || // To speed up
            ! $this->tokens->checkSequence($this->sequences['array_equation_array'])
        ){
            return false;
        }
            
        // Get end of array equation
        $variable_end = $this->tokens->searchForward($key, ';') - 1;
        if( ! $variable_end ){
            return false;
        }
        
        // Get all tokens of the array
        $array_tokens = $this->tokens->getRange($key + 4, $variable_end - 1);
        if( ! $array_tokens ){
            return false;
        }
        
        for(
            $i = 0;
            $arr_key = null, $arr_value = null, isset( $array_tokens[ $i ]);
            $arr_key = null, $arr_value = null, $i++
        ){
            
            // Case: [ 'a' => 'b' ] or [ 1 => 'b' ]
            if(
                isset($array_tokens[ $i + 1 ]) && $array_tokens[ $i + 1 ]->type === 'T_DOUBLE_ARROW' &&
                $array_tokens[ $i ]->isTypeOf( 'array_allowed_keys')
            ){
                $arr_key   = trim($array_tokens[ $i ]->value, '\'"');
                $arr_value = $array_tokens[ $i + 2 ];
                $i += 2; // Skip
                
            // Case: [ 'a', 'b', 'c' ]
            }elseif( $array_tokens[ $i ]->isTypeOf( 'array_allowed_values' ) ){
                $arr_key   = isset($this->arrays[ $this->tokens->current->value ])
                    ? count( $this->arrays[ $this->tokens->current->value ])
                    : 0;
                $arr_value = $array_tokens[ $i ];
            }
            
            if( $arr_key && $arr_value ){
                $array[ $arr_key ] = $arr_value;
            }
        }
        
        if( isset($array) ){
            $this->arrays[ $this->tokens->current->value ] = $array;
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
        if(
            $this->tokens->current->value !== '=' || // To speed up
            ! $this->tokens->checkSequence($this->sequences['array_equation_square_brackets'])
        ){
            return false;
        }
        
        $variable_end = $this->tokens->searchForward($key, ';') - 1;
        if( ! $variable_end ){
            return false;
        }
        
        // Get all tokens of the array
        $array_tokens = $this->tokens->getRange($key + 3, $variable_end - 1);
        if( ! $array_tokens ){
            return false;
        }
        
        for(
            $i = 0;
            $arr_key = null, $arr_value = null, isset( $array_tokens[ $i ]);
            $arr_key = null, $arr_value = null, $i++
        ){
            // Case: [ 'a' => 'b' ] or [ 1 => 'b' ]
            if(
                isset($array_tokens[ $i + 1 ]) && $array_tokens[ $i + 1 ]->type === 'T_DOUBLE_ARROW' &&
                $array_tokens[ $i ]->isTypeOf( 'array_allowed_keys')
            ){
                $arr_key   = trim($array_tokens[ $i ]->value, '\'"');
                $arr_value = $array_tokens[ $i + 2 ];
                $i += 2; // Skip
                
            // Case: [ 'a', 'b', 'c' ]
            }elseif( $array_tokens[ $i ]->isTypeOf( 'array_allowed_values' ) ){
                $arr_key   = isset($this->arrays[ $this->tokens->current->value ])
                    ? count( $this->arrays[ $this->tokens->current->value ])
                    : 0;
                $arr_value = $array_tokens[ $i ];
            }
            
            if( $arr_key && $arr_value ){
                $array[ $arr_key ] = $arr_value;
            }
        }
        
         if( isset($array) ){
            $this->arrays[ $this->tokens->current->value ] = $array;
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
            $this->tokens->next1->value === '[' &&
            $this->tokens->next2->value === ']' &&
            $this->tokens->next3->value === '='
        ){
            $var_temp = $this->tokens->getRange(
                $key + 4,
                $this->tokens->searchForward($key, ';') - 1
            );
            
            if( $var_temp !== false && count( $var_temp ) ){
                $var_temp = $var_temp[0];
                if( $var_temp->isTypeOf('array_allowed_values') ){
                    $this->arrays[ $this->tokens->current->value ][] = array(
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
            $this->tokens->current->type  === 'T_VARIABLE' &&
            $this->tokens->next1  ->value === '='
        ){
            $variable_end = $this->tokens->searchForward($key, ';') - 1;
            if($variable_end){
                
                $variable_tokens = $this->tokens->getRange($key + 2, $variable_end);
                
                if(
                    count($variable_tokens) === 3 &&
                    $variable_tokens[0]->value === '"' &&
                    $variable_tokens[1]->type === 'T_ENCAPSED_AND_WHITESPACE' &&
                    $variable_tokens[2]->value === '"'
                ){
                    $variable_tokens = array( new Token(
                        'T_CONSTANT_ENCAPSED_STRING',
                        '\'' . $variable_tokens[1]->value . '\'',
                        $variable_tokens[1]->line,
                        $variable_tokens[1]->key
                    ) );
                }
                
                // Variable in a single quotes like $a = 'value';
                $this->variables[ $this->tokens->current->value ] = $variable_tokens;
            }
        }
        
        return false;
    }
    
    /**
     * Equation with concatenation. $a .= 'value';
     * Adding right expression to the appropriate variable
     *
     * @param int $key
     *
     * @return false always return false
     */
    public function updateVariables_equationWithConcatenation($key)
    {
        if(
            $this->tokens->current->type === 'T_VARIABLE' &&
            $this->tokens->next1  ->type === 'T_CONCAT_EQUAL'
        ){
            
            $tokens_of_variable = $this->tokens->getRange(
                $key + 2,
                $this->tokens->searchForward($key, ';') - 1
            );
            
            if( $tokens_of_variable ){
                
                // Variable in a double quotes like $a .= "$b";
                // We don't touch variables in a single quotes like $a .= 'value';
                if(
                    count( $tokens_of_variable ) === 3 &&
                    $tokens_of_variable[0]->value === '"' &&
                    $tokens_of_variable[1]->type  === 'T_ENCAPSED_AND_WHITESPACE' &&
                    $tokens_of_variable[2]->value === '"'
                ){
                    $tokens_of_variable = array(
                        new Token(
                            'T_CONSTANT_ENCAPSED_STRING',
                            '\'' . $tokens_of_variable[1]->value . '\'',
                            $tokens_of_variable[1]->line,
                            $tokens_of_variable[1]->key
                        ),
                    );
                }
                
                // If the variable exists
                if( isset( $this->variables[ $this->tokens->current->value ] ) ){
                    $this->variables[ $this->tokens->current->value ]->append($tokens_of_variable);
                }else{
                    $this->variables[ $this->tokens->current->value ] = $tokens_of_variable;
                }
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
        if(
            $this->tokens->current->value === 'define' &&
            $this->tokens->checkSequence($this->sequences['define_constant'])
        ){
            $constant_name = trim( $this->tokens->next2->value, '\'"' );
            $this->constants[ $constant_name ] = trim( $this->tokens->next4->value, '\'"' );
        }
        
        return false;
    }
    
    /**
     * Concatenate variable in $this->variables
     *
     * @return void
     */
    public function concatenate(){
        
        foreach($this->variables as &$var){
            
            for(
                $key = 0, $key_max = count( $var );
                
                $current = isset($var[ $key ])     ? $var[ $key ]     : null,
                $next    = isset($var[ $key + 1 ]) ? $var[ $key + 1 ] : null,
                $key < $key_max;
                
                $key++
            ){
                if(
                    ( $current && in_array( $current->type, $this->variables_types_to_concat, true ) ) &&
                    ( $next    && in_array( $next->type,    $this->variables_types_to_concat, true ) )
                ){
                    $var[ $key ] = new Token(
                        $current->type,
                        "'" . trim($current->value, '\'"') . trim($next->value, '\'"') . "'",
                        $current->line,
                        $current->key
                    );
                    unset( $var[ $key + 1 ]);
                    $var->reindex($key); // Reindex start form given key
                }
            }
        }
    }
    
    /**
     * Replace variables with it's content
     *
     * @param int $key
     *
     * @return bool
     */
    public function replace($key)
    {
        // Replace variable
        if( $this->tokens->current->type === 'T_VARIABLE' ){
            
            $variable_name = $this->tokens->current->value;
            
            // Arrays
            if( $this->isTokenInArrays($this->tokens->current) ){
                
                // Array element
                if(
                    $this->tokens->next1->value === '[' &&
                    $this->tokens->next1->type === 'T_LNUMBER' &&
                    $this->tokens->next3->isValueIn( [ '.', '(', ';' ] )
                ){
                    if( isset($this->arrays[ $variable_name ][ $this->tokens->next1->value[1] ][1]) ){
                        if( $this->tokens->next3->value === '(' ){
                            $this->tokens['current'] = new Token(
                                'T_STRING',
                                substr($this->arrays[ $variable_name ][ $this->tokens->next1->value[1] ][1], 1, -1),
                                $this->tokens->current->line,
                                $this->tokens->current->key
                            );
                        }elseif( $this->tokens->next3->value === '.' ){
                            $this->tokens['current'] = new Token(
                                'T_CONSTANT_ENCAPSED_STRING',
                                '\'' . $this->arrays[ $variable_name ][ $this->tokens->next1->value[1] ][1] . '\'',
                                $this->tokens->current->line,
                                $this->tokens->current->key
                            );
                        }else{
                            $this->tokens['current'] = new Token(
                                $this->arrays[ $variable_name ][ $this->tokens->next1->value[1] ][0],
                                '\'' . $this->arrays[ $variable_name ][ $this->tokens->next1->value[1] ][1] . '\'',
                                $this->tokens->current->line,
                                $this->tokens->current->key
                            );
                        }
                        
                        $this->tokens->unsetTokens('next1', 'next2', 'next3');
                        
                        return true;
                    }
                }
                
            // Variables
            }elseif(
                $this->isTokenInVariables($this->tokens->current) &&
                count($this->variables[ $variable_name ]) === 1 &&
                in_array($this->variables[ $variable_name ][0][0], $this->variables_types_to_concat, true)
            ){
                // Array or symbol from string replacement
                if(
                    $this->tokens->next2->type === 'T_LNUMBER' &&
                    $this->tokens->next1->isValueIn( [ '[', '{' ] )
                ){
                    if( isset(
                        $this->variables[ $variable_name ][0][1][ $this->tokens->next2->value ],
                        $this->variables[ $variable_name ][0][1][ $this->tokens->next2->value + 1]
                    ) ){
                        $this->tokens['current'] = new Token(
                            'T_CONSTANT_ENCAPSED_STRING',
                            '\'' . $this->variables[ $variable_name ][0][1][ $this->tokens->next2->value + 1] . '\'',
                            $this->tokens->current->line,
                            $this->tokens->current->key
                        );
                        $this->tokens->unsetTokens('next1', 'next2', 'next3');
                        
                        return true;
                    }
                    
                // @todo Learn to replace $$var to $var_value
                // }elseif( is_array( $next ) && $next === 'T_VARIABLE' ){
                
                // Single variable replacement
                }else{
                    
                    // Variables function
                    if( $this->tokens->next1->value === '(' ){
                        $this->tokens['current'] = new Token(
                            'T_STRING',
                            substr($this->variables[ $variable_name ][0][1], 1, -1),
                            $this->tokens->current->line,
                            $this->tokens->current->key
                        );
                        // Variables in double/single quotes
                    }elseif( ! $this->tokens->next1->isTypeOf('equation') ){
                        $this->tokens['current'] = new Token(
                            ! $this->tokens->prev1->value === '"' ? 'T_CONSTANT_ENCAPSED_STRING' : 'T_ENCAPSED_AND_WHITESPACE',
                            ! $this->tokens->prev1->value === '"' ? $this->variables[ $variable_name ][0][1] : substr($this->variables[ $variable_name ][0][1],1,-1),
                            $this->tokens->current->line,
                            $this->tokens->current->key
                        );
                    }
                }
            }
            
        // Constant replacement
        // @todo except cases when name of constant equal to something. Check type and siblings tokens
        }elseif( $this->isTokenInConstants($this->tokens->current) ){
            $this->tokens['current'] = new Token(
                'T_CONSTANT_ENCAPSED_STRING',
                '\'' . $this->constants[ $this->tokens->current->value ] . '\'',
                $this->tokens->current->line,
                $this->tokens->current->key
            );
        }
        
        return false;
    }
    
    /**
     * Add variables to bad list depends on:
     *  - containing user input ($_POST,$_GET,...)
     *  - containing variables contain user input
     *
     * See $this->variables_bad to view the list of user input variables
     *
     * @return void
     */
    public function detectBad()
    {
        // Perform until count of bad variables becomes stable
        do{
            // Count bad variables on start of each iteration
            $bad_vars_count = count($this->variables_bad);
            
            foreach( $this->variables as $name => $variable_tokens ){
                
                if( $this->isSetOfTokensHasBadVariables( $variable_tokens ) ){
                    $this->variables_bad[ $name ] = $variable_tokens;
                }
                
            }
        }while( $bad_vars_count !== count($this->variables_bad) );
    }
    
    /**
     * Check the set of tokens for bad variables
     *
     * @param Token[]|ExtendedSplFixedArray $tokens Set of tokens
     *
     * @return bool
     */
    public function isSetOfTokensHasBadVariables( $tokens )
    {
    	foreach( $tokens as $token ){
      
    		if(
    			$token->type === 'T_VARIABLE' &&
                (
                    in_array($token->value, $this->variables_bad_default, true ) ||
			        in_array($token->value, $this->variables_bad, true )
                )
		    ){
    			return true;
		    }
	    }
    	
    	return false;
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
        return $token->type === 'T_VARIABLE' && isset($this->arrays[ $token->value ]);
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
        return $token->type === 'T_VARIABLE' && isset($this->variables[ $token->value ]);
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
        return $token->type === 'T_STRING' && isset($this->constants[ $token->value ]);
    }
}