<?php

namespace CleantalkSP\SpbctWP\Scanner\Heuristic;

/**
 * Class Heuristic
 *
 * @package Security Plugin by CleanTalk
 * @subpackage Scanner
 * @Version 2.3
 * @author Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see https://github.com/CleanTalk/security-malware-firewall
 */
class Controller
{
	// Constants
	const FILE_MAX_SIZE = 524288; // 512 KB
    
	// Current file attributes
	/**
	 * @var bool Defines if the passed code is plain text
	 */
	public $is_text       = false;
	public $is_evaluation = false;
	
	public $extension;     // File extension
	public $path;          // File path
	public $curr_dir;      // File path
	public $file_size = 0; // File size
 
	public $tokens    = array(); // Array with file lexems
	
	public $file_content   = '';   // Original
	public $file_work      = '';   // Work copy
    
    public $error               = array();
	private $properties_to_pass = array(
		'is_evaluation',
		'variables',
		'arrays',
		'constants',
		'variables_bad'
	);
	
	public $verdict = array(); // Scan results
	public $looks_safe = false;
	
	private $output_constructs = array(
		'T_ECHO',
		'T_PRINT',
	);
	
	private $bad_constructs = array(
		'CRITICAL' => array(
			'eval',
			'assert',
			'create_function',
            // 'unserialize',
		),
		'DANGER' => array(
			'system',
			'passthru',
			'proc_open',
			'exec',
            'pcntl_exec',
            'popen',
            'shell_exec',
            '`',
		),
		'SUSPICIOUS' => array(
			//'base64_encode',
			//'base64_decode',
			'str_rot13',
			'syslog',
		),
	);
	
	private $whitespace_lexem = array(
		'T_WHITESPACE',
		' ',
		null,
	);
	
	/** Modules */
    
    /**
     * @var Tokens
     */
    private $token_handler;
    /**
     * @var Simplifier
     */
    private $simplifier;
    /**
     * @var Strings
     */
    private $strings;
    /**
     * @var Variables
     */
    private $variables;
    /**
     * @var Transformations
     */
    private $transformations;
    /**
     * @var Includes
     */
    private $includes;
    /**
     * @var SQLs
     */
    private $sqls;
    /**
     * @var Evaluations
     */
    private $evaluations;
    
    /**
     * @var CodeStyle
     */
    private $code_style;
    
    /**
	 * Heuristic constructor.
	 * Getting common info about file|text and it's content
	 *
	 * @param array $input
	 * @param self  $self
	 */
	public function __construct( $input, $self = null ){
		
		// Accept
		if( $self && $self instanceof self ){
			
			foreach( $input as $property_name => $property_value ){
				if( in_array($property_name, $this->properties_to_pass, true) ){
                    $this->$property_name = $property_value;
                }
			}
			
		}
		
		// Accept file as a string
		if( isset( $input['content'] ) ){
			
			$this->is_text   = true;
			
			if( $this->checkFileSize(strlen($input['content'] ) ) ){
				$this->file_size    = strlen( $input['content'] );
				$this->file_work    = $input['content'];
				$this->file_content = $this->file_work;
			}
			
			// Accept file as a path
		}elseif( isset( $input['path'] ) ){
			
			$this->path      = $input['path'];
			$this->curr_dir  = dirname( $this->path );
			$this->extension = pathinfo( $this->path, PATHINFO_EXTENSION );
			
			if( $this->checkFileAccessibility() && $this->checkFileSize(filesize($this->path ) ) )
			{
				$this->file_size    = (int) filesize( $this->path );
				$this->file_work    = file_get_contents( $this->path );
				$this->file_content = $this->file_work;
			}
			
			// Bad params provided
		}else{
            $this->error = array('error' => 'BAD_PARAMS');
            
            return;
        }
		
		$this->token_handler   = new Tokens();
        $this->simplifier      = new Simplifier($this->token_handler);
        $this->strings         = new Strings($this->token_handler);
        $this->variables       = new Variables($this->token_handler);
        $this->sqls            = new SQLs($this->token_handler, $this->variables);
        $this->transformations = new Transformations($this->token_handler);
        $this->includes        = new Includes($this->token_handler, $this->variables, $this->curr_dir, $this->is_text);
        $this->evaluations     = new Evaluations($this->token_handler);
        $this->code_style      = new CodeStyle($this->token_handler);
        
		$this->token_handler->getTokensFromText($this->file_content );
		$this->tokens = &$this->token_handler->tokens;
  
	}
	
	private function checkFileAccessibility(){
		
		if( ! file_exists( $this->path ) ){
			$this->error = array( 'error' => 'FILE_NOT_EXISTS' );
			return false;
		}
		
		if( ! is_readable( $this->path ) ){
			$this->error = array( 'error' => 'FILE_NOT_READABLE' );
			return false;
		}
  
		if( ! is_file( $this->path ) || is_dir( $this->path ) || is_link( $this->path ) ){
			$this->error = array( 'error' => 'IS_NOT_A_FILE' );
			return false;
		}
		
		return true;
	}
	
	private function checkFileSize( $file_size ){
		
		if( ! (int) $file_size ){
			$this->error = array( 'error' => 'FILE_SIZE_ZERO' );
			return false;
		}
		
		if( (int) $file_size > self::FILE_MAX_SIZE ){
			$this->error = array( 'error' => 'FILE_SIZE_TO_LARGE' );
			return false;
		}
		
		return true;
	}
	
	/**
	 * Process file.
	 * Do all the work
	 *
	 * All the results in the $this->verdict
	 *
	 * @return void
	 */
	public function processContent(){
        
        if( ! $this->evaluations ){
            
            $this->code_style->analiseLineLengths($this->file_content);
    
            foreach( $this->tokens as $key => &$current_token ){
                
                // Counting tokens which are incompatible in one line
                $this->code_style->searchIncompatibleOnelinedTokens();
                $this->code_style->gatherLinesNumAndLength();
                
                if( $this->simplifier->deleteNonCodeTokens($key) ) continue;
                
            } unset($current_token);
    
            \CleantalkSP\Common\Helper::array_reindex( $this->tokens );
        }
        
	    /**
         * Deobfuscating
         * Repeat until all array with tokens became stable
         */
        do{
            
            $stamp = $this->createStamp();
            
            $this->token_handler->setMaxKey();
            
            /** Continue the cycle if the function unset current element */
            foreach( $this->tokens as $key => &$current_token ){
                
                // Set current token to use it in modules
                $this->token_handler->newIteration($key);
                
                if( $this->simplifier->stripWhitespaces($key) ) continue;
                
                // Strings alterations
                if( $this->strings->convertToSimple($key) ) continue;
                if( $this->strings->convertChrFunctionToString($key) ) continue;
                if( $this->strings->convertHexSymbolsToString($key) ) continue;
                if( $this->strings->concatenateSimpleStrings($key) ) continue;
                if( $this->strings->concatenateComplexStrings($key) ) continue;
                
                // Strings actions and alterations
                if( $this->variables->convertVariableStrings($key) ) continue;
                if( $this->variables->updateVariables_equation($key) ) continue;
                if( $this->variables->updateVariables_equationWithConcatenation($key) ) continue;
                if( $this->variables->updateArray_equation($key) ) continue;
                if( $this->variables->updateArray_equationShort($key) ) continue;
                if( $this->variables->updateArray_newElement($key) ) continue;
                
                // Updating constants
                if( $this->variables->updateConstants($key) ) continue;
                
                // Executing decoding functions
                //$this->transformations->decodeData($this->tokens, $key);
                
            } unset( $current_token );
            
            \CleantalkSP\Common\Helper::array_reindex( $this->tokens );
            
            $this->variables->concatenate(); // Concatenates variable content if it's possible
            $this->variables->replace( $this->tokens ); // Replaces variables with its content
            
        }while( $stamp !== $this->createStamp() );
        
        \CleantalkSP\Common\Helper::array_reindex( $this->tokens );
        
		// Mark evaluation as safe if it matches conditions
		if( $this->is_evaluation &&
		    (
			    // Only output
                (isset( $this->tokens[1][0] ) && in_array($this->tokens[1][0], $this->output_constructs, true ) ) ||
                // Empty
                (count( $this->tokens ) === 1 )
		    )
		){
			$this->looks_safe = true;
			
			return;
		}
        
        // Detecting bad variables
        $this->variables->detectBad();
		
        /** Gather the results of scanning */
        foreach( $this->tokens as $key => &$current_token ){
            
            // Getting all include constructions and detecting bad
            $this->includes->standardize($this->tokens, $key);
            $this->includes->get($this->tokens, $key);
    
            // Getting all MySQL requests and detecting bad
            $this->sqls->getViaFunctions($key);
            $this->sqls->getViaKeyWords($key);
    
            // Get all evaluation to test them again
            $this->evaluations->getAll($key);
            
        } unset($current_token);
        
		// Making verdict
		$this->make_verdict();
		
        /** Create new instance of Heuristic\Controller for each evaluation found */
        foreach( $this->evaluations->evaluations as $evaluation_string => $evaluation ){
            
            $sub = new self(array('content' => $evaluation, 'is_evaluation' => true, ), $this );
            $sub->processContent();
            
            // Set eval string like in a parent
            foreach( $sub->verdict as &$vulnerabilities ){
                $vulnerabilities = array( $evaluation_string => current( $vulnerabilities ) );
            }unset( $vulnerabilities );
            
            /** Merge verdicts */
            $this->verdict = array_merge_recursive( $this->verdict, $sub->verdict );
            
            if( $sub->looks_safe ){
                unset( $this->verdict['CRITICAL'][ $evaluation_string ] );
            }
        }
	}
    
    private function createStamp(){
	    return md5($this->token_handler->glueTokens());
    }
    
	public function make_verdict()
	{
		// Detecting bad functions
		foreach($this->tokens as $key => $lexem){
			if(is_array($lexem)){
				foreach( $this->bad_constructs as $severity => $set_of_functions){
					foreach($set_of_functions as $bad_function){
						if(
							$lexem[1] === $bad_function &&
							! (
								isset($this->tokens[$key - 1][0]) &&
                                $this->tokens[$key - 1][0] === 'T_OBJECT_OPERATOR'
							)
						){
							$this->verdict[$severity][$lexem[2]][] = $bad_function;
						}
					}
				}
			}
		}
		
		// Adding bad includes to $verdict['SEVERITY']['string_num'] = 'whole string with include'
		foreach($this->includes->includes as $include){
			if($include['status'] === false){
				if($include['not_url'] === false && $include['ext_good'] === false){
                    $this->verdict['CRITICAL'][$include['string']][] = substr($this->token_handler->glueTokens($include['include']), 0, 255);
                }elseif($include['good'] === false){
                    $this->verdict['SUSPICIOUS'][$include['string']][] = substr($this->token_handler->glueTokens($include['include']), 0, 255);
                }
			}
		}
		
		// Adding bad sql to $verdict['SEVERITY']['string_num'] = 'whole string with sql'
		foreach($this->sqls->requests as $sql){
			if($sql['status'] === false){
				$this->verdict['SUSPICIOUS'][$sql['string']][] = substr($this->token_handler->glueTokens($sql['sql']), 0, 255);
			}
		}
        
        $this->mergeVerdicts( $this->code_style->detectBadLines() );
	}
    
    /**`
     * Merge verdicts from different modules
     *
     * @param $verdict_to_merge
     */
	private function mergeVerdicts( $verdict_to_merge ){
	    foreach( $this->verdict as $severity => &$line_nums_verdict ){
	        foreach( $line_nums_verdict as $line_num => &$verdict ){
	            if( isset( $verdict_to_merge[ $severity ][ $line_num ] ) ){
	                $this->verdict[ $severity ][ $line_num ][] = $verdict_to_merge[ $severity ][ $line_num ];
                }
            }
        }
    }
	
	/**
	 * Concatenates anything
	 *
	 * @param $lexems
	 * @param $curr_index
	 * @param bool $backwards
	 */
	public static function _concatenate(&$lexems, $curr_index, $backwards = false){
		$next_index = $curr_index + ($backwards ? (-1) : 1);
		$curr_val = $lexems[$curr_index][0] === 'T_CONSTANT_ENCAPSED_STRING' ? substr($lexems[$curr_index][1], 1, -1) : $lexems[$curr_index][1];
		$next_val = $lexems[$next_index][0] === 'T_CONSTANT_ENCAPSED_STRING' ? substr($lexems[$next_index][1], 1, -1) : $lexems[$next_index][1];
		$lexems[$next_index] = array(
			$lexems[$curr_index][0],
			'"' . ($backwards ? $next_val . $curr_val : $curr_val . $next_val) . '"',
			$lexems[$curr_index][2],
		);
		unset($lexems[$curr_index]);
	}
    
    /**
     * Return all found includes
     *
     * @return array
     */
    public function getIncludes()
    {
        return $this->includes->includes;
    }
}
