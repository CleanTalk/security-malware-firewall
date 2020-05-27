<?php

/**
 * Class SpbcScannerH
 *
 * @package Security Plugin by CleanTalk
 * @subpackage Scanner
 * @Version 2.1
 * @author Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see https://github.com/CleanTalk/security-malware-firewall
 */
class SpbcScannerH
{
	// Constants
	const FILE_MAX_SIZE = 524288; // 512 KB
	
	// Current file atributes
	public $is_text        = false;
	
	public $ext            = null; // File extension
	public $path           = null; // File path
	public $curr_dir       = null; // File path
	public $file_size      = 0;    // File size
	
	public $variables      = array();
	public $variables_bad  = array();
	public $file_lexems    = array(); // Array with file lexems
	
	public $file_content   = '';   // Original
	public $file_work      = '';   // Work copy
	public $file_stamp     = '';
	
	public $includes       = array();
	public $sql_requests   = array();
	
	public $error = array();
	
	public $verdict = array(); // Scan results
	
	private $debug = array();
	
	private $variables_bad_default = array(
		'$_POST',
		'$_GET',
	);
	
	static $bad_constructs = array(
		'CRITICAL' => array(
			'eval',
			'assert',
		),
		'DANGER' => array(
			'system',
			'passthru',
			'proc_open',
			'exec',
		),
		'SUSPICIOUS' => array(
			// 'base64_encode',
			// 'base64_decode',
			'str_rot13',
			'syslog',
		),
	);
	
	public $usless_lexems  = array(
		'T_INLINE_HTML',
		'T_COMMENT',
		'T_DOC_COMMENT',
		// 'T_WHITESPACE',
	);
	
	public $strip_whitespace_lexems  = array(
		'T_WHITESPACE', // /\s*/
		'T_CLOSE_TAG',
		'T_CONSTANT_ENCAPSED_STRING', // String in quotes
		// Equals
		'T_DIV_EQUAL',
		'T_BOOLEAN_OR',
		'T_BOOLEAN_AND',
		'T_IS_EQUAL',
		'T_IS_GREATER_OR_EQUAL',
		'T_IS_IDENTICAL',
		'T_IS_NOT_EQUAL',
		'T_IS_SMALLER_OR_EQUAL',
		'T_SPACESHIP',
		// Assignments
		'T_CONCAT_EQUAL',
		'T_MINUS_EQUAL',
		'T_MOD_EQUAL',
		'T_MUL_EQUAL',
		'T_AND_EQUAL',
		'T_OR_EQUAL',
		'T_PLUS_EQUAL',
		'T_POW_EQUAL',
		'T_SL_EQUAL',
		'T_SR_EQUAL',
		'T_XOR_EQUAL',
		// Bit
		'T_SL', // <<
		'T_SR', // >>
		// Uno
		'T_INC', // ++
		'T_DEC', // --
		'T_POW', // **
		// Cast type
		'T_ARRAY_CAST',
		'T_BOOL_CAST',
		'T_DOUBLE_CAST',
		'T_OBJECT_CAST',
		'T_STRING_CAST',
		// Different
		'T_START_HEREDOC', // <<<
		'T_NS_SEPARATOR', // \
		'T_ELLIPSIS', // ...
		'T_OBJECT_OPERATOR', // ->
		'T_DOUBLE_ARROW', // =>
		'T_DOUBLE_COLON', // ::
		'T_PAAMAYIM_NEKUDOTAYIM', // ::
	);
	
	public $equals_lexems = array(
		'=',
		'T_CONCAT_EQUAL',
		'T_MINUS_EQUAL',
		'T_MOD_EQUAL',
		'T_MUL_EQUAL',
		'T_AND_EQUAL',
		'T_OR_EQUAL',
		'T_PLUS_EQUAL',
		'T_POW_EQUAL',
		'T_SL_EQUAL',
		'T_SR_EQUAL',
		'T_XOR_EQUAL',
	);
	
	public $dont_trim_lexems = array(
		'T_ENCAPSED_AND_WHITESPACE',
		'T_OPEN_TAG',
	);
	
	public $varibles_types_to_concat = array(
		'T_CONSTANT_ENCAPSED_STRING',
		// 'T_ENCAPSED_AND_WHITESPACE',
		'T_LNUMBER',
		'T_DNUMBER',
	);
	
	public $whitespace_lexem = array(
		'T_WHITESPACE',
		' ',
		null,
	);
	
	// Getting common info about file|text and it's content
	function __construct($path, $params = array())
	{
		// Exept file as a plain text|array
		if(isset($params['content'])){
			$this->is_text = true;
			$this->file_size    = strlen($params['content']);
			if($this->file_size != 0){
				if($this->file_size < self::FILE_MAX_SIZE){
					$this->file_work = $params['content'];
					$this->file_content = $this->file_work;
					$this->text_check = true;
					unset($params['content']);
				}else
					return $this->error = array('error' =>'FILE_SIZE_TO_LARGE');
			}else
				return $this->error = array('error' =>'FILE_SIZE_ZERO');
			
		// Exept file as a path
		}elseif(!empty($path)){
			// Path
			$this->path     = $path;
			$this->curr_dir = dirname($this->path);
			// Exstension
			$tmp = explode('/', $path);
			$tmp = explode('.', $tmp[count($tmp)-1]);
			$this->ext = $tmp[count($tmp)-1];
			
			if(file_exists($this->path)){
				if(is_readable($this->path)){
					$this->file_size = filesize($this->path);
					if($this->file_size > 0){
						if($this->file_size < self::FILE_MAX_SIZE){
							$this->file_work    = file_get_contents($this->path);
							$this->file_content = $this->file_work;
						}else
							return $this->error = array('error' =>'FILE_SIZE_TO_LARGE');
					}else
						return $this->error = array('error' =>'FILE_SIZE_ZERO');
				}else
					return $this->error = array('error' =>'FILE_NOT_READABLE');
			}else
				return $this->error = array('error' =>'FILE_NOT_EXISTS');
		}
	}
		
	public function process_file()
	{
		
		$this->file_lexems = @token_get_all($this->file_work);
		
		// Preparing file
		$this->lexems_getAll();
		
		$this->lexems_stripUseless();
		
		// Simplifying
		do{
			$this->file_stamp = $this->_stamp();
			
			$this->lexems_stripWhitespaces(); // Strips usless withspaces
			
			$this->strings_convert();       // Convert to simple lexems strings
			$this->strings_concatenate();   // Concatenates nearby string lexems
			
			$this->variables_getAll();
			$this->variables_concatenate(); // Concatenates variable content if it's possible
			$this->variables_replace();     // Repaces variables with its content
			
		}while( $this->file_stamp !== $this->_stamp() );
		
		//* Getting construction
		
		// Detecting bad variables
		$this->variables_detectBad();
		
		// Getting all include constructions and detecting bad
		// $this->includes_standartize();
		$this->includes_getAll();
		
		// Getting all MySQL requests and detecting bad
		$this->sql_requests_getAll();
		
		// Making verdict
		$this->make_verdict();
		
		// $this->file_work = $this->gather_lexems();
		
	}
	
	// Strips Usless lexems. T_INLINE_HTML, T_COMMENT, T_DOC_COMMENT
	public function lexems_getAll()
	{
		foreach($this->file_lexems as $key => &$lexem){
			if(isset($lexem[1])) $lexem[0] = token_name($lexem[0]);
		}
	}
	
	// Strips Usless lexems. T_INLINE_HTML, T_COMMENT, T_DOC_COMMENT
	public function lexems_StripUseless()
	{
		for($key = 0, $arr_size = count($this->file_lexems); $key < $arr_size; $key++){
			if(in_array($this->file_lexems[$key][0], $this->usless_lexems)){
				
				// Unset useless lexems
				unset($this->file_lexems[$key]);
				// $this->file_lexems[$key] = $this->whitespace_lexem;
				// $this->file_lexems[$key][2] = $lexem[2];
			}
		}
		$this->file_lexems = array_values($this->file_lexems);
	}
	
	// Strips T_WHITESPACE around (array)strip_whitespace_lexems and single lexems
	public function lexems_stripWhitespaces()
	{
		for($key = 0, $current = null, $arr_size = count($this->file_lexems); $key < $arr_size; $key++, $current = isset($this->file_lexems[$key]) ? $this->file_lexems[$key] : null){
			if($current && $current[0] == 'T_WHITESPACE'){
				
				$next = isset($this->file_lexems[$key+1]) ? $this->file_lexems[$key+1] : null;
				$prev = isset($this->file_lexems[$key-1]) ? $this->file_lexems[$key-1] : null;
				
				if(($next && !is_array($next)) || ($prev && !is_array($prev))){
					unset($this->file_lexems[$key]);
				}elseif(($next && in_array($next[0], $this->strip_whitespace_lexems)) || ($prev && in_array($prev[0], $this->strip_whitespace_lexems))){
					unset($this->file_lexems[$key]);
				}else{
					$this->file_lexems[$key][1] = ' ';
				}
			}else{
				if(!in_array($this->file_lexems[$key][0], $this->dont_trim_lexems) && is_array($this->file_lexems[$key]))
					$this->file_lexems[$key][1] = trim($this->file_lexems[$key][1]);
			}
		}
		$this->file_lexems = array_values($this->file_lexems);		
	}
	
	// Coverts T_ENCAPSED_AND_WHITESPACE to T_CONSTANT_ENCAPSED_STRING if could
	public function strings_convert()
	{
		for(
			$key = 0,
			$current = null,
			$arr_size = count($this->file_lexems);
			
			$key < $arr_size;
			
			$key++,
			$current = isset($this->file_lexems[$key]) ? $this->file_lexems[$key] : null
		){
			if($current && $current[0] === 'T_ENCAPSED_AND_WHITESPACE'){
				$next = isset($this->file_lexems[$key+1]) ? $this->file_lexems[$key+1] : null;
				$prev = isset($this->file_lexems[$key-1]) ? $this->file_lexems[$key-1] : null;
				if($prev == '"' && $next == '"'){
					unset($this->file_lexems[$key-1]);
					unset($this->file_lexems[$key+1]);
					$this->file_lexems[$key] = array(
						'T_CONSTANT_ENCAPSED_STRING',
						'\''.$current[1].'\'',
						$current[2],
					);
				}
			}
			
			// Convert chr('\xNN') to 'a'
			elseif( $current && $current === ')' ){
				$prev  = isset( $this->file_lexems[ $key - 1 ] ) ? $this->file_lexems[ $key - 1 ] : null;
				$prev2 = isset( $this->file_lexems[ $key - 2 ] ) ? $this->file_lexems[ $key - 2 ] : null;
				$prev3 = isset( $this->file_lexems[ $key - 3 ] ) ? $this->file_lexems[ $key - 3 ] : null;
				if (
					$prev && is_array( $prev ) && $prev[0] === 'T_LNUMBER' &&
					$prev2 && $prev2 === '(' &&
					$prev3 && is_array( $prev3 ) && $prev3[0] === 'T_STRING' && $prev3[1] === 'chr'
				) {
					unset(
						$this->file_lexems[ $key - 1 ],
						$this->file_lexems[ $key - 2 ],
						$this->file_lexems[ $key - 3 ]
					);
					$this->file_lexems[ $key ] = array(
						'T_CONSTANT_ENCAPSED_STRING',
						'\'' . ( chr( $prev[1] ) ? chr( $prev[1] ) : '') . '\'',
						$prev3[2],
					);
				}
			}
			
			// Convert "\xNN" to 'a'
			elseif( isset($current, $current[0]) && $current[0] === 'T_CONSTANT_ENCAPSED_STRING' && strpos( $current[1], '"') === 0 && strpos( $current[1], '\x') !== false ){
				preg_match( '/(\\\\x[\d]{2})/', $current[1], $matches );
				unset($matches[0]);
				$matches = array_values( $matches );
				$replacements = array_map(function($elem){
					return eval( "return \"$elem\";");
				}, $matches);
				$this->file_lexems[ $key ][1] = str_replace( $matches, $replacements, $current[1] );
			}
		}
	}
	
	// Concatenates T_CONSTANT_ENCAPSED_STRING if could
	public function strings_concatenate()
	{
		for(
			$key = 0,
			$current = null,
			$arr_size = count( $this->file_lexems );
			
			$key < $arr_size;
			
			$key ++,
			$current = isset( $this->file_lexems[ $key ] ) ? $this->file_lexems[ $key ] : null
		){
			
			// Concatenates simple strings
			if($current && $current[0] === 'T_ENCAPSED_AND_WHITESPACE'){
				$next = isset($this->file_lexems[$key+1]) ? $this->file_lexems[$key+1] : null;
				if($next && $next[0] === 'T_ENCAPSED_AND_WHITESPACE'){
					$this->file_lexems[$key+1] = array(
						'T_ENCAPSED_AND_WHITESPACE',
						$current[1].$next[1],
						$current[2],
					);
					unset($this->file_lexems[$key]);
				}
			}
			
			// Concatenates 'a'.'b' and "a"."b" to 'ab'
			elseif($current && $current === '.'){	
				$next = isset($this->file_lexems[$key+1]) ? $this->file_lexems[$key+1] : null;
				$prev = isset($this->file_lexems[$key-1]) ? $this->file_lexems[$key-1] : null;
				if(is_array($prev) && is_array($next) && $prev[0] == 'T_CONSTANT_ENCAPSED_STRING' && $next[0] == 'T_CONSTANT_ENCAPSED_STRING'){
					unset($this->file_lexems[$key-1]);
					unset($this->file_lexems[$key]);
					$prev[1] = $prev[1][0] === '"' ?  '\''.preg_replace("/'/", '\'', substr($prev[1], 1, -1))      : substr($prev[1], 0, -1);
					$next[1] = $next[1][0] === '"' ?       preg_replace("/'/", '\'', substr($next[1], 1, -1)).'\'' : substr($next[1], 1);
					$this->file_lexems[$key+1] = array(
						'T_CONSTANT_ENCAPSED_STRING',
						$prev[1].$next[1],
						$prev[2],
					);
				}
			}
		}
		$this->file_lexems = array_values($this->file_lexems);
	}
	
	//* Variable control
	public function variables_getAll()
	{
		for($key = 0, $current = null, $arr_size = count($this->file_lexems); $key < $arr_size; $key++){
			$current = isset($this->file_lexems[$key]) ? $this->file_lexems[$key] : null;
			if($current && is_array($current) && $current[0] === 'T_VARIABLE'){
				$next = isset($this->file_lexems[$key+1]) ? $this->file_lexems[$key+1] : null;
				if($next === '='){
					$variable_end = $this->lexem_getNext($key, ';')-1;
					if($variable_end){
						$var_temp = $this->lexem_getRange($key+2, $variable_end);
						if(count($var_temp) == 3 && $var_temp[0] === '"' &&  $var_temp[1][0] === 'T_ENCAPSED_AND_WHITESPACE' && $var_temp[2] === '"'){
							$var_temp = array(array(
								'T_CONSTANT_ENCAPSED_STRING',
								'\''.$var_temp[1][1].'\'',
								$var_temp[1][2]
							));
						}
						$this->variables[$current[1]] = $var_temp;
					}					
				}
				if($next[0] === 'T_CONCAT_EQUAL' && isset($this->variables[$current[1]])){
					$variable_end = $this->lexem_getNext($key, ';')-1;
					if($variable_end){
						$var_temp = $this->lexem_getRange($key+2, $variable_end);
						if(count($var_temp) == 3 && $var_temp[0] === '"' &&  $var_temp[1][0] === 'T_ENCAPSED_AND_WHITESPACE' && $var_temp[2] === '"'){
							$var_temp = array(array(
								'T_CONSTANT_ENCAPSED_STRING',
								'\''.$var_temp[1][1].'\'',
								$var_temp[1][2]
							));
						}
						$this->variables[$current[1]] = array_merge($this->variables[$current[1]], $var_temp);
					}					
				}
			}
		}
	}
	
	//* Variable concatenate
	public function variables_concatenate(){
		foreach($this->variables as $var_name => $var){
			for($i = count($var)-1; $i > 0; $i--){
				$curr = isset($var[$i])   ? $var[$i]   : null;
				$next = isset($var[$i-1]) ? $var[$i-1] : null;
				if(in_array($curr[0], $this->varibles_types_to_concat) && in_array($next[0], $this->varibles_types_to_concat)){
					$this->_concatenate($this->variables[$var_name], $i, true);
				}
			}
		}
	}
	
	//* Replace variables with it's content
	public function variables_replace()
	{
		$in_quotes = false;
		for($key = 0, $current = null, $arr_size = count($this->file_lexems); $key < $arr_size; $key++, $current = isset($this->file_lexems[$key]) ? $this->file_lexems[$key] : null){
			if($current == '"')
				$in_quotes = !$in_quotes ? true : false;		
			if(is_array($current) && $current[0] === 'T_VARIABLE'){
				if(isset($this->variables[$current[1]]) && count($this->variables[$current[1]]) == 1 && in_array($this->variables[$current[1]][0][0], $this->varibles_types_to_concat)){
					$next  = isset($this->file_lexems[$key+1]) ? $this->file_lexems[$key+1] : null;
					$next2 = isset($this->file_lexems[$key+2]) ? $this->file_lexems[$key+2] : null;
					if($next === '('){ // Variables function
						$this->file_lexems[$key][0] = 'T_STRING';
						$this->file_lexems[$key][1] = substr($this->variables[$current[1]][0][1], 1, -1);
						$this->file_lexems[$key][2] = $current[2];
					}elseif(!in_array($next[0], $this->equals_lexems)){ // Variables in double/single quotes
						$this->file_lexems[$key][0] = !$in_quotes ? 'T_CONSTANT_ENCAPSED_STRING'  : 'T_ENCAPSED_AND_WHITESPACE';
						$this->file_lexems[$key][1] = !$in_quotes ? $this->variables[$current[1]][0][1] : substr($this->variables[$current[1]][0][1], 1, -1);
						$this->file_lexems[$key][2] = $current[2];
					}
				}
			}
		}
	}
	
	public function variables_detectBad()
	{
		do{
			$bad_vars_ccount = count($this->variables_bad);
			
			foreach($this->variables as $var_name => $variable){
				
				foreach($variable as $var_part){
					
					if($var_part[0] === 'T_VARIABLE' && (in_array($var_part[1], $this->variables_bad_default) || isset($this->variables_bad[$var_part[1]]))){
						$this->variables_bad[$var_name] = $variable;
						continue(2);
					}
					
				} unset($var_part);
				
			} unset($var_name, $variable);
			
		}while($bad_vars_ccount != count($this->variables_bad));
	}
	
	// Brings all such constructs to include'path';
	public function includes_standartize()
	{
		for($key = 0, $current = null, $arr_size = count($this->file_lexems); $key < $arr_size; $key++, $current = isset($this->file_lexems[$key]) ? $this->file_lexems[$key] : null){
			if($current && strpos($current[0], 'INCLUDE') !== false || strpos($current[0], 'REQUIRE') !== false){
				if($this->file_lexems[$key+1] === '('){
					$next_bracket = $this->lexem_getNext($key, ')');
					if($next_bracket !== false)
						unset($this->file_lexems[$key+1]);
						unset($this->file_lexems[$next_bracket]);
				}
				$this->file_lexems = array_values($this->file_lexems);
			}
		}
	}
	
	// Gets all of the include and require constructs. Checks for file extension and checks the path.
	public function includes_getAll()
	{
		for(
			$key = 0,
			$current = null,
			$arr_size = count($this->file_lexems);
			
			$key < $arr_size;
			
			$key++,
			$current = isset($this->file_lexems[$key]) ? $this->file_lexems[$key] : null,
			$prev_file_exists__key = null,
			$prev_file_exists      = null
		){
			if ( ! is_null( $current ) && in_array( $current[0], array( 'T_INCLUDE', 'T_INCLUDE_ONCE', 'T_REQUIRE', 'T_REQUIRE_ONCE' ) ) ){
				
				// Get previous "file_exists" function
				$prev_file_exists__start = $this->lexem_getPrev( $key, 'file_exists' );
				$prev_file_exists__end = $prev_file_exists__start ? $this->lexem_getNext( $prev_file_exists__start, ')' ) : null;
				$prev_file_exists = $prev_file_exists__start && $prev_file_exists__end ? $this->lexem_getRange( $prev_file_exists__start, $prev_file_exists__end) : null;
				
				$include_end = $this->lexem_getNext($key, ';')-1;
				if($include_end){
					$include = $this->lexem_getRange($key+1, $include_end);
					if( $prev_file_exists ){
						$include['file_exists'] = $prev_file_exists;
					}
					$this->includes_processsAndSave($include, $key);
				}
				
			}
		}
	}
	
	public function includes_processsAndSave($include, $key)
	{
		// Check flags
		 $unknown  = true;
		 $good     = true;
		 $status   = true;
		 $not_url  = null;
		 $path     = null;
		 $exists   = null;
		 $ext      = null;
		 $ext_good = null;
		 
		// Checking for bad variables in include
		foreach($include as $value){
			if($value[0] === 'T_VARIABLE' && (in_array($value[1], $this->variables_bad_default) || isset($this->variables_bad[$value[1]]))){
				$good = false;
				break;
			}
		} unset($value);
		
		// Checking for @ before include
		$error_free = $this->file_lexems[$key-1] === '@' ? false : true;
		
		// Include is a single string
		if(
			(count($include) == 1 && $include[0][0] === 'T_CONSTANT_ENCAPSED_STRING') or 
			(count($include) == 3 && $include[0] == '(' && $include[1][0] === 'T_CONSTANT_ENCAPSED_STRING')
		){
			
			$path = count($include) == 3 ? substr($include[1][1], 1, -1) : substr($include[0][1], 1, -1); // Cutting quotes
			$not_url  = !filter_var($path, FILTER_VALIDATE_URL) ? true : false; // Checks if it is URL
			preg_match('/^(((\S:\\{1,2})|(\S:\/{1,2}))|\/)?.*/', $path, $matches);                         // Reconizing if path is absolute.
			$path     = empty($matches[1]) && $not_url ? $this->curr_dir.'/'.$path : $path;                // Make path absolute
			$exists   = $this->is_text && ! ( isset( $include['file_exists'] ) && $include['file_exists'][2][0] === 'T_CONSTANT_ENCAPSED_STRING' && $include['file_exists'][2][0] === $path )
				? null
				: (realpath($path) ? true : false);                          // Checks for existence. null if checking text (not file).
			preg_match('/.*\.(\S*)$/', $path, $matches2);          // Reconizing extension.
			$ext      = isset($matches2[1]) ? $matches2[1] : '';   
			$ext_good = in_array($ext, array('php', 'inc')) || is_dir($path) ? true : false;             // Good extension?
			
			$unknown  = false;
		}
		
		
		// Gather result in one flag
		$status = $good
			? (!$unknown
				? (!$not_url || !$ext_good
					? false
					: true)
				: null)
			: false;
		
		//$status = $good ? ($error_free ? ($unknown ? null : (!$not_url || !$exists || !$ext_good ? false : true)) : false) : false; // prev versison
		
		array_unshift($include, $this->file_lexems[$key]);
		
		$this->includes[] = array(
			'include'    => $include,
			'good'       => $good,
			'status'     => $status,
			'not_url'    => $not_url,
			'path'       => $path,
			'exists'     => $exists,
			'error_free' => $error_free,
			'ext'        => $ext,
			'ext_good'   => $ext_good,
			'string'     => $this->file_lexems[$key][2],
		);
	}
	
	public function sql_requests_getAll(){
		for(
			$key = 0, $current = null, $arr_size = count($this->file_lexems);
			$key < $arr_size;
			$key++
		){
			$current = isset($this->file_lexems[$key]) ? $this->file_lexems[$key] : null;
			$sql_start = null;
			$sql_end = null;
			if($current[0] == 'T_STRING'
					&& (   $current[1] == 'mysql_query'
						|| $current[1] == 'mysqli_query'
						|| $current[1] == 'mysqli_send_query'
						|| $current[1] == 'mysqli_multi_query'
					)
				){
					$sql_start = $key + 2;
					$sql_start = $key;
					$sql_end = $this->lexem_getNext($key, ';')-1;
				}
			if($current[0] == 'T_STRING' && ($current[1] == 'mysqli' || $current[1] == 'MYSQLI') && $this->file_lexems[$key+2][0] == 'T_STRING'
					&& (   
						   $this->file_lexems[$key+2][1] == 'query'
						|| $this->file_lexems[$key+2][1] == 'send_query'
						|| $this->file_lexems[$key+2][1] == 'multi_query'
					)
				){
					$sql_start = $key + 4;
					$sql_start = $key;
					$sql_end = $this->lexem_getNext($key, ';')-1;
				}
			if($current[0] == 'T_STRING' && ($current[1] == 'pdo' || $current[1] == 'PDO') && $this->file_lexems[$key+2][0] == 'T_STRING'
				&& (   
					   $this->file_lexems[$key+2][1] == 'query'
					|| $this->file_lexems[$key+2][1] == 'exec'
				)
			){
				$sql_start = $key + 4;
				$sql_start = $key;
				$sql_end = $this->lexem_getNext($key, ';')-1;
			}
			if($current[0] == 'T_VARIABLE' && $this->file_lexems[$key+1][0] == 'T_OBJECT_OPERATOR' && $this->file_lexems[$key+2][0] == 'T_STRING'
				&& (   
					   $this->file_lexems[$key+2][1] == 'query'
					|| $this->file_lexems[$key+2][1] == 'get_results'
				)
				&& $this->file_lexems[$key+3][0] == '('
			){
				$sql_start = $key + 4;
				$sql_start = $key;
				$sql_end = $this->lexem_getNext($key, ';')-1;
			}
			
			if($sql_start && $sql_end){
				$sql = $this->lexem_getRange($sql_start, $sql_end);
				$this->sql_requests_processsAndSave($sql, $key);
			}
		}
	}
	
	public function sql_requests_processsAndSave($sql, $key, $status = true, $good = true){
		
		// Checking for bad variables in sql
		foreach($sql as $value){
			if($value[0] === 'T_VARIABLE' && (in_array($value[1], $this->variables_bad_default) || isset($this->variables_bad[$value[1]]))){
				$good = false;
				break;
			}
		} unset($value);
		
		$status = $good ? true : false;
		
		$this->sql_requests[] = array(
			'sql'    => $sql,
			'status' => $status,
			'good'   => $good,
			'string' => $this->file_lexems[$key][2],
		);
		
	}
	
	public function make_verdict()
	{
		// Detecting bad functions
		foreach($this->file_lexems as $key => $lexem){
			if(is_array($lexem)){
				foreach(self::$bad_constructs as $severity => $set_of_functions){
					foreach($set_of_functions as $bad_function){
						if(
							$lexem[1] === $bad_function &&
							! ( isset( $this->file_lexems[ $key - 1 ], $this->file_lexems[ $key - 1][0] ) && $this->file_lexems[ $key - 1][0] === 'T_OBJECT_OPERATOR' )
						){
							$this->verdict[$severity][$lexem[2]][] = $bad_function;
						}
					} unset($bad_function);
				} unset($severity, $set_of_functions);
			}
		}
		// Adding bad includes to $verdict['SEVERITY']['string_num'] = 'whole string with include'
		foreach($this->includes as $include){
			if($include['status'] === false){
				if($include['not_url'] === false or $include['ext_good'] === false)
					$this->verdict['CRITICAL'][$include['string']][] = substr($this->gather_lexems($include['include']), 0, 255);
				elseif($include['good'] === false)
					$this->verdict['SUSPICIOUS'][$include['string']][] = substr($this->gather_lexems($include['include']), 0, 255);
			}
		}
		// Adding bad sql to $verdict['SEVERITY']['string_num'] = 'whole string with sql'
		foreach($this->sql_requests as $sql){
			if($sql['status'] === false){
				$this->verdict['SUSPICIOUS'][$sql['string']][] = substr($this->gather_lexems($sql['sql']), 0, 255);
			}
		}
	}
	
	// Getting next setted lexem, Search for needle === if needle is set
	public function lexem_getNext($start, $needle = null)
	{
		for($i = 0, $key = $start+1; $i < 100; $i++, $key++){
			if(isset($this->file_lexems[$key])){
				$current = $this->file_lexems[$key];
				if($needle === null)
					return $key;
				elseif(!is_array($current) && $current === $needle || is_array($current) && $current[1] === $needle)
					return $key;
			}
		}
		return false;
	}
	
	/**
	 * Getting prev setted lexem, Search for needle === if needle is set
	 *
	 * @param int $start
	 * @param null $needle
	 *
	 * @return bool|int
	 */
	public function lexem_getPrev($start, $needle = null)
	{
		for($i = 0, $key = $start-1; $i < 100 && $key > 0; $i--, $key--){
			if(isset($this->file_lexems[$key])){
				$current = $this->file_lexems[$key];
				if($needle === null)
					return $key;
				elseif(!is_array($current) && $current === $needle || is_array($current) && $current[1] === $needle)
					return $key;
			}
		}
		return false;
	}
	
	// Getting prev setted lexem, Search for needle === if needle is set
	public function lexem_getRange($start, $end)
	{
		return array_slice($this->file_lexems, $start, $end - $start + 1);
	}
	
	// Gathering file back
	public function gather_lexems($input = null)
	{
		$input = $input ? $input : $this->file_lexems;
		$out = '';
		foreach($input as $key => $lexem)
			$out .= is_array($lexem) ? $input[$key][1] : $input[$key];
		
		return $out;
	}
	
	// MD5 current lexems
	public function _stamp($input = null)
	{
		return md5($this->gather_lexems($input));
	}
	
	//* Concatenates anything
	public function _concatenate(&$lexems, $curr_index, $backwards = false, $type = 'T_ENCAPSED_AND_WHITESPACE'){
		$next_index = $curr_index + ($backwards ? (-1) : 1);
		$curr_val = $lexems[$curr_index][0] == 'T_CONSTANT_ENCAPSED_STRING' ? substr($lexems[$curr_index][1], 1, -1) : $lexems[$curr_index][1];
		$next_val = $lexems[$next_index][0] == 'T_CONSTANT_ENCAPSED_STRING' ? substr($lexems[$next_index][1], 1, -1) : $lexems[$next_index][1];
		$lexems[$next_index] = array(
			$lexems[$curr_index][0],
			'"' . ($backwards ? $next_val . $curr_val : $curr_val . $next_val) . '"',
			$lexems[$curr_index][2],
		);
		unset($lexems[$curr_index]);
	}
}
