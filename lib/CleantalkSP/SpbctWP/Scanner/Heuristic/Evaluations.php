<?php


namespace CleantalkSP\SpbctWP\Scanner\Heuristic;


class Evaluations
{
    /**
     * @var Tokens
     */
    private $tokens;
    
    /**
     * Contains all evaluations code
     *
     * @var array
     */
    public $evaluations = array();
    
    /**
     * Code functions or directives which executes code
     *
     * @var string[]
     */
    private $evaluation_constructs = array(
        'create_function',
        'eval',
        'assert',
    );
    
    public function __construct(Tokens $tokens_handler)
    {
        $this->tokens = $tokens_handler;
    }
    
    /**
     * Gets all evaluation constructions in $this->evaluations to scan them later
     *
     * @return void
     */
    public function getAll($key)
    {
        if( in_array($this->tokens->current[1], $this->evaluation_constructs, true) ){
            
            // Put found code (not tokens) in the $this->evaluations[ string ]
            $tokens = $this->tokens->getRange(
                $key + 2,
                $this->tokens->searchForward($key, ';') - 2
            );
            
            if( $tokens ){
                $this->evaluations[ $this->tokens->current[2] ] = '<?php ' . trim($this->tokens->glueTokens($tokens), '\'"');
            }
        }
    }
}