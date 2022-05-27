<?php


namespace CleantalkSP\SpbctWP\Scanner\Heuristic;


use PHPMailer\PHPMailer\Exception;
use CleantalkSP\DataStructures\ExtendedSplFixedArray;
use CleantalkSP\SpbctWP\Scanner\Heuristic\DataStructures\Token;

class Includes
{
    /**
     * @var array[] Contains arrays with array with each include tokens
     */
    public $includes = array();
    
    /**
     * @var Tokens
     */
    private $tokens;
    
    /**
     * @var Variables
     */
    private $variables_handler;
    
    /**
     * @var string Contains current directory with file we are working with
     */
    private $current_directory;
    
    /**
     * @var bool Show if we are analysing plain text, false if we are working with file
     */
    private $is_text;
    
    public function __construct(Tokens $tokens_handler, Variables $variables_handler, $current_directory, $is_text)
    {
        $this->tokens            = $tokens_handler;
        $this->variables_handler = $variables_handler;
        $this->current_directory = $current_directory;
        $this->is_text           = $is_text;
    }
    
    /**
     * Brings all such constructs to "include'path';" format
     *
     * @param ExtendedSplFixedArray $tokens
     * @param int                   $key
     *
     * @return bool
     */
    public function standardize($key)
    {
        if(
            $this->tokens->next1->value === '(' &&
            $this->tokens->current->isTypeOf('include')
        ){
            $next_bracket_position = $this->tokens->searchForward( $key, ')');
            
            if( $next_bracket_position !== false ){
                
                $this->tokens['next1'] = new Token(
                    'T_WHITESPACE',
                    ' ',
                    $this->tokens->next1->line,
                    $this->tokens->next1->key
                );
                $this->tokens->unsetTokens($next_bracket_position);
                
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Gets all of the include and require constructs. Checks for file extension and checks the path.
     *
     * @param int $key
     *
     * @return void
     */
    public function get($key)
    {
        if( $this->tokens->current->isTypeOf('include') ){
            
            // Get previous "file_exists" function
            $prev_file_exists__start = $this->tokens->searchBackward( $key, 'file_exists');
            $prev_file_exists__end   = $prev_file_exists__start
                ? $this->tokens->searchForward( $prev_file_exists__start, ')')
                : null;
            $file_exists        = $prev_file_exists__start && $prev_file_exists__end
                ? $this->tokens->getRange( $prev_file_exists__start, $prev_file_exists__end)
                : null;
            
            // Get the include
            $include = $this->tokens->getRange(
                $key + 1,
                $this->tokens->searchForward( $key, ';') - 1
            );
            
            if( $include && count($include) ){
                $this->process($include, $file_exists, $key);
            }
        }
    }
    
    /**
     * Processing given tokens with "includes".
     * Convert it to standard.
     *
     * @todo Create SpbctWP\Scanner\Heuristic\IncludeDTO
     *
     * @param $include
     * @param $file_exists
     * @param $key
     * @param $tokens
     */
    public function process($include, $file_exists, $key)
    {
        $include = $include->toArray();
        
        // Trim heading whitespace
        if($include[0]->type === 'T_WHITESPACE'){
            unset($include[0]);
            $include = array_values($include);
        }
        
        $properties = array(
            'include'      => $include,
            'dir'          => $this->current_directory, // Current directory
            'string'       => $this->tokens->current->line,         // String number in file
            'path'         => '',   // Absolute path to the file
            'is_absolute'  => null, // Is path to file is absolute
            'name'         => '',   // Filename
            'error_free'   => true, // Checking for error ignoring "@" before include
            'not_url'      => true, // Is the path a URL
            'good'         => true, // Contains bad variables with user input
            'status'       => true, // Overall result. Good (true) by default
            'exists'       => true, // Is the file exists
            'ext'          => '',   // Extension of the file
            'ext_good'     => true, // Is extension is good (php|inc)
        );
    
        $properties['error_free'] = $this->tokens->prev1->value !== '@';
        $properties['good']       = ! $this->variables_handler->isSetOfTokensHasBadVariables($include);
        
        // Include is a single string, so we can continue to analise
        if( count($include) === 1 && $include[0]->type === 'T_CONSTANT_ENCAPSED_STRING' ){
            
            // Extracting path from the string token. Cutting quotes.
            $properties['path']    = substr($include[0]->value, 1, -1);
            $properties['not_url'] = ! filter_var($properties['path'], FILTER_VALIDATE_URL);
    
            // If the filepath is absolute.
            $properties['is_absolute'] = preg_match('@^([A-Z]:[\\\\]|[\/])@', $properties['path']);
    
            // Make path absolute
            $properties['path'] = ! $properties['is_absolute'] && $properties['not_url']
                ? $this->current_directory . DIRECTORY_SEPARATOR . preg_replace('@^([\\\\]|[\/])@', '', $properties['path'])
                : $properties['path'];
            
            // Extract filename from the path
            $properties['name'] = basename( $properties['path'] );
    
            // Checks file for existence. null if checking text (not file).
            $properties['exists'] =
                $this->is_text &&
                ! (
                    $file_exists &&
                    $file_exists[2]->type === 'T_CONSTANT_ENCAPSED_STRING' &&
                    $file_exists[2]->value === $properties['path']
                )
                    ? null
                    : (bool) realpath($properties['path']);
            
            // Getting extension.
            $properties['ext']      = preg_match('/.*\.(\S{1,10})$/', $properties['path'], $matches) ? $matches[1] : '';
    
            // Is extension appropriate?
            $properties['ext_good'] = in_array($properties['ext'], array('php', 'inc')) || is_dir($properties['path']);
        }
        
        // Gather result in one flag
        $properties['status'] = $properties['good'] && ! $properties['not_url'] && $properties['ext_good'];
        
        // Adding include directive itself to the "include"
        $properties['include'] = array_unshift($properties['include'], $this->tokens->current);
        
        $this->includes[] = $properties;
    }
}