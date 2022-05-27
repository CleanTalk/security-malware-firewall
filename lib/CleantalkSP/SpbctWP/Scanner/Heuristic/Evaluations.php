<?php


namespace CleantalkSP\SpbctWP\Scanner\Heuristic;


class Evaluations
{
    /**
     * @var Tokens
     */
    private $tokens;
    
    /**
     * @var Variables
     */
    private $variables;
    
    /**
     * @var Includes
     */
    private $includes;
    /**
     * @var SQLs
     */
    private $sqls;
    
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
    
    private $output_constructs = array(
		'T_ECHO',
		'T_PRINT',
	);
    
    public function __construct(Tokens $tokens, Variables $variables, Includes $includes, SQLs $sqls )
    {
        $this->tokens    = $tokens;
        $this->variables = $variables;
        $this->includes  = $includes;
        $this->sqls      = $sqls;
    }
    
    /**
     * Gets all evaluation constructions in $this->evaluations to scan them later
     *
     * @param int $key
     *
     * @return void
     */
    public function getAll($key)
    {
        if(
            ! (
                $this->tokens->prev1->type === 'T_OBJECT_OPERATOR' ||
                $this->tokens->prev2->type === 'T_FUNCTION'
            ) &&
            in_array($this->tokens->current->value, $this->evaluation_constructs, true)
        ){
            // Put found code (not tokens) in the $this->evaluations[ string ]
            $tokens = $this->tokens->getRange(
                $key + 2,
                $this->tokens->searchForward($key, ';') - 2
            );
            
            if( $tokens ){
                $this->evaluations[ $this->tokens->current->line ] = '<?php ' . trim($this->tokens->glueTokens($tokens), '\'"');
            }
        }
    }
    
    public function isSafe()
    {
        // Evaluation is empty
        if( count( $this->tokens ) > 3 ){
            return false;
        }
        
        // Evaluation doesn't have a bad variables
        if(
            ! $this->sqls->requests &&
            ! $this->includes->includes &&
            ! $this->variables->isSetOfTokensHasBadVariables( $this->tokens->tokens )
        ){
            return true;
        }
        
        return false;
    }
}