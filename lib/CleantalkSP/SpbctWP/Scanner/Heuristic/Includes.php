<?php


namespace CleantalkSP\SpbctWP\Scanner\Heuristic;


use PHPMailer\PHPMailer\Exception;

class Includes
{
    /**
     * @var array[] Contains arrays with array with each include tokens
     */
    public $includes = array();
    
    /**
     * @var Tokens
     */
    private $token_handler;
    
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
        $this->token_handler     = $tokens_handler;
        $this->variables_handler = $variables_handler;
        $this->current_directory = $current_directory;
        $this->is_text           = $is_text;
    }
    
    // Brings all such constructs to "include'path';" format
    public function standardize(&$tokens, $key)
    {
        if(
            isset( $tokens[$key + 1] ) &&
            $tokens[$key + 1][1] === '(' &&
            $this->token_handler->isInGroup('include', $tokens[$key])
        ){
            $next_bracket = $this->token_handler->searchForward($key, ')');
            if( $next_bracket !== false ){
                unset($tokens[$key + 1], $tokens[$next_bracket]);
            }
        }
    }
    
    /**
     * Gets all of the include and require constructs. Checks for file extension and checks the path.
     *
     * @param array $tokens
     * @param int   $key
     *
     * @return void
     */
    public function get(&$tokens, $key)
    {
        if( $this->token_handler->isInGroup('include', $tokens[$key]) ){
            
            // Get previous "file_exists" function
            $prev_file_exists__start = $this->token_handler->searchBackward($key, 'file_exists');
            $prev_file_exists__end   = $prev_file_exists__start
                ? $this->token_handler->searchForward($prev_file_exists__start, ')')
                : null;
            $file_exists        = $prev_file_exists__start && $prev_file_exists__end
                ? $this->token_handler->getRange($prev_file_exists__start, $prev_file_exists__end)
                : null;
            
            // Get the include
            $include = $this->token_handler->getRange(
                $key + 1,
                $this->token_handler->searchForward($key, ';') - 1
            );
            if( $include ){
                $this->process($include, $file_exists, $key, $tokens);
            }
        }
    }
    
    public function process($include, $file_exists, $key, &$tokens)
    {
        $properties = array(
            'include'     => $include,                 // Tokens
            'dir'         => $this->current_directory, // Current directory
            'string'      => $tokens[$key][2],         // String number in file
            'first_string' => reset($include)[2], // First string of token set
            'last_string'  => end($include)[2],   // Last string of token set
            'path'        => '',   // Absolute path to the file
            'is_absolute' => null, // Is path to file is absolute
            'name'        => '',   // Filename
            'error_free'  => true, // Checking for error ignoring "@" before include
            'not_url'     => true, // Is the path a URL
            'good'        => true, // Contains bad variables with user input
            'status'      => true, // Overall result. Good (true) by default
            'exists'      => true, // Is the file exists
            'ext'         => '',   // Extension of the file
            'ext_good'    => true, // Is extension is good (php|inc)
        );
    
        $properties['error_free'] = $tokens[$key - 1][1] !== '@';
        $properties['good']       = ! $this->variables_handler->isSetOfTokensHasBadVariables($include);
        
        // Include is a single string, so we can continue to analise
        if( count($include) === 1 && $include[0][0] === 'T_CONSTANT_ENCAPSED_STRING' ){
            
            // Extracting path from the string token. Cutting quotes.
            $properties['path']    = substr($include[0][1], 1, -1);
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
                    $file_exists[2][0] === 'T_CONSTANT_ENCAPSED_STRING' &&
                    $file_exists[2][0] === $properties['path']
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
        
        array_unshift($properties['include'], $tokens[$key]); // Adding include directive itself to the "include"
        
        $this->includes[] = $properties;
    }
}