<?php

namespace CleantalkSP\Common\Scanner\HeuristicAnalyser;

use CleantalkSP\Common\Scanner\HeuristicAnalyser\DataStructures\ExtendedSplFixedArray;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\DataStructures\Token;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\Exceptions\HeuristicScannerException;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\Modules\CodeStyle;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\Modules\Entropy;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\Modules\Evaluations;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\Modules\FunctionsDecryptorService;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\Modules\Includes;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\Modules\Mathematics;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\Modules\Simplifier;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\Modules\SQLs;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\Modules\Strings;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\Modules\Tokens;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\Modules\Transformations;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\Modules\Variables;

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
class HeuristicAnalyser
{
    // Constants
    const HEURISTIC_SCAN_MAX_FILE_SIZE = 524288; // 512 KB

    // Current file attributes
    /**
     * @var bool Defines if the passed code is plain text
     */
    public $is_text = false;
    public $is_evaluation = false;

    /**
     * @var array|string|string[]
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $extension;     // File extension
    public $path;          // File path
    public $curr_dir;      // File path

    /**
     * @var int
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $file_size = 0; // File size

    /**
     * @var Tokens
     */
    public $tokens; // Array with file lexemes

    public $file_content = '';   // Original
    public $file_work = '';   // Work copy

    /**
     * @var string[]
     * @psalm-suppress UnusedProperty
     */
    private $properties_to_pass = array(
        'is_evaluation',
        'variables',
        'arrays',
        'constants',
        'variables_bad'
    );

    public $verdict = array(); // Scan results

    /**
     * @var bool
     * @psalm-suppress UnusedProperty
     */
    public $looks_safe = false;

    private $bad_constructs = array(
        'SUSPICIOUS' => array(
            'str_rot13',
            'syslog',
            'eval',
            'assert',
            'create_function',
            'shell_exec',
            'system',
            'passthru',
            'proc_open',
            'exec',
            'pcntl_exec',
            'popen',
            '`',
            // 'unserialize',
        ),
    );

    private $super_globals = array(
        '$_GET',
        '$_POST',
        '$_COOKIE',
        '$_FILES',
        '$_SERVER',
        '$GLOBALS',
        '$_SESSION',
        '$_REQUEST',
    );

    /**
     * Contains a set of dangerous values that have been decoded
     * @var string[]
     */
    private $dangerous_decoded_values = array(
        'base64_decode',
        'base64_encode'
    );

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
     * @psalm-suppress UnusedProperty
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
     * @var string
     */
    public $deobfuscated_code;

    /**
     * @var Entropy
     */
    private $entropyAnalyser;

    /**
     * @var Mathematics
     */
    private $mathematics;

    /**
     * Heuristic constructor.
     * Getting common info about file|text and it's content
     *
     * @param array $input
     * @param self $self
     * @throws HeuristicScannerException
     */
    public function __construct($input, $self = null)
    {
        // Accept
        if ( $self instanceof self ) {
            foreach ( $input as $property_name => $property_value ) {
                if ( in_array($property_name, $this->properties_to_pass, true) ) {
                    $this->$property_name = $property_value;
                }
            }
        }

        // Accept file as a string
        if ( isset($input['content']) ) {
            $this->is_text = true;
            $this->checkFileSize(strlen($input['content']));
            $this->file_size    = strlen($input['content']);
            $this->file_work    = $input['content'];
            $this->file_content = $this->file_work;
            // Accept file as a path
        } elseif ( isset($input['path']) ) {
            $this->path      = $input['path'];
            $this->curr_dir  = dirname($this->path);
            $this->extension = pathinfo($this->path, PATHINFO_EXTENSION);
            $this->checkFileSize((int)filesize($this->path));
            $this->checkFileAccessibility();
            $this->file_size    = (int)filesize($this->path);
            $this->file_work    = file_get_contents($this->path);
            $this->file_content = $this->file_work;
            // Bad params provided
        } else {
            throw new HeuristicScannerException('BAD_PARAMS');
        }

        $this->tokens          = new Tokens($this->file_content);
        $this->simplifier      = new Simplifier($this->tokens);
        $this->mathematics     = new Mathematics($this->tokens);
        $this->strings         = new Strings($this->tokens);
        $this->variables       = new Variables($this->tokens);
        $this->sqls            = new SQLs($this->tokens, $this->variables);
        $this->transformations = new Transformations($this->tokens);
        $this->includes        = new Includes($this->tokens, $this->variables, $this->curr_dir, $this->is_text);
        $this->evaluations     = new Evaluations($this->tokens, $this->variables, $this->includes, $this->sqls);
        $this->code_style      = new CodeStyle($this->tokens);

        if ( isset($input['path']) && version_compare(PHP_VERSION, '8.1', '>=') && extension_loaded('mbstring') ) {
            // Do not run entropy analysis on included constructs
            $this->entropyAnalyser = new Entropy($input['path']);
        }
    }

    private function checkFileAccessibility()
    {
        if ( ! file_exists($this->path) ) {
            throw new HeuristicScannerException('FILE_NOT_EXISTS');
        }

        if ( ! is_readable($this->path) ) {
            throw new HeuristicScannerException('FILE_NOT_READABLE');
        }

        if ( ! is_file($this->path) || is_dir($this->path) || is_link($this->path) ) {
            throw new HeuristicScannerException('IS_NOT_A_FILE');
        }

        return true;
    }

    /**
     * @param $file_size
     * @throws HeuristicScannerException
     */
    private function checkFileSize($file_size)
    {
        if ( ! (int)$file_size ) {
            throw new HeuristicScannerException('FILE_SIZE_ZERO');
        }

        if ( (int)$file_size > self::HEURISTIC_SCAN_MAX_FILE_SIZE ) {
            throw new HeuristicScannerException('FILE_SIZE_TOO_LARGE');
        }
    }

    /**
     * Process file.
     * Do all the work
     *
     * All the results in the $this->verdict
     *
     * @return void
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function processContent()
    {
        // Skip files does not contain PHP code
        if ( $this->extension !== 'php' && ! $this->code_style->hasPHPOpenTags() ) {
            return;
        }

        // Analysing code style
        // Do this, only for initial code
        if ( ! $this->evaluations->evaluations ) {
            if (
                $this->extension !== 'html' &&
                $this->extension !== 'htm' &&
                $this->extension !== 'shtml' &&
                $this->extension !== 'js'
            ) {
                $this->code_style->analyseLineLengths($this->file_content);
                $this->code_style->analyseHumanUnreadableCode($this->file_content);
                $this->code_style->analyseWeightOfNoise($this->file_content);
            }

            foreach ( $this->tokens as $key => $_current_token ) {
                // Counting tokens which are incompatible in one line
                $this->code_style->searchIncompatibleOnelinedTokens();
                $this->code_style->sortTokensWithDifferentTypes();

                $this->simplifier->deleteNonCodeTokens($key);
            }

            $this->tokens->reindex();
        }

        /**
         * Deobfuscation
         * Repeat until all array with tokens became stable
         */
        do {
            // Consider that tokens were not changed in start of the cycle
            $this->tokens->were_modified = false;

            // Skip empty files without PHP code
            if ( empty($this->tokens) ) {
                return;
            }

            /**
             * Continue the cycle if the function unset any elements
             * Every new iteration temporary tokens are redefined
             */
            foreach ( $this->tokens as $key => $_current_token ) {
                // Actions which could possibly delete tokens from the set
                $this->simplifier->stripWhitespaces($key);
                $this->mathematics->evaluateMathExpressions();
                $this->strings->convertToSimple($key);
                $this->strings->convertChrFunctionToString($key);
                $this->strings->convertFileGetContentsToString($this->path);
            }

            foreach ( $this->tokens as $key => $_current_token ) {
                $this->strings->concatenateSimpleStrings($key);
                $this->strings->concatenateComplexStrings($key);
            }

            foreach ( $this->tokens as $key => $_current_token ) {
                $this->includes->standardize($key);
                $this->variables->convertVariableStrings($key);
                $this->variables->replace($key);

                // Actions which are alter tokens with no deletion
                $this->strings->convertHexSymbolsToString($key);
                $this->variables->updateVariablesEquation($key);
                $this->variables->updateVariablesEquationWithConcatenation($key);
                $this->variables->updateArrayEquation($key);
                $this->variables->updateArrayEquationShort($key);
                $this->variables->updateArrayNewElement($key);
                $this->variables->updateConstants($key);

                // Executing decoding functions
                $this->transformations->decodeData($key);
            }

            $this->variables->concatenate(); // Concatenates variable content if it's possible
            foreach ( $this->tokens as $key => $_current_token ) {
                $this->strings->concatenateSimpleStrings($key);
                $this->strings->concatenateComplexStrings($key);
                $this->variables->concatenateVars($key);
            }

            foreach ( $this->tokens as $key => $_current_token ) {
                $this->variables->replaceArrayVars($key);
            }

            foreach ( $this->tokens as $key => $_current_token ) {
                $this->strings->concatenateComplexStrings($key);
            }

            foreach ( $this->tokens as $key => $_current_token ) {
                $this->variables->replaceVars($key);
            }
        } while ( $this->tokens->were_modified === true );

        // Decryption of data inside functions base64_decode , str_rot13
        $functions_descriptor = new FunctionsDecryptorService($this->tokens);
        $functions_descriptor->handle();

        // Mark evaluation as safe if it matches conditions
        if ( $this->is_evaluation && $this->evaluations->isSafe() ) {
            $this->looks_safe = true;

            return;
        }

        // Detecting bad variables
        $this->variables->detectBad();
        if ( $this->entropyAnalyser ) {
            $this->entropyAnalyser->analyse($this->variables);
        }

        /** Gather the results of scanning */
        foreach ( $this->tokens as $key => $_current_token ) {
            // Getting all include constructions and detecting bad
            $this->includes->get($key);

            // Getting all MySQL requests and detecting bad
            $this->sqls->getViaFunctions($key);
            $this->sqls->getViaKeyWords($key);

            // Get all evaluation to test them again
            $this->evaluations->getAll($key);
        }

        // Making verdict
        $this->makeVerdict();
        $this->deobfuscated_code = $this->getResultCode();
        /** Create new instance of Heuristic\Controller for each evaluation found */
        foreach ( $this->evaluations->evaluations as $evaluation_string => $evaluation ) {
            $sub = new self(array('content' => $evaluation, 'is_evaluation' => true,), $this);
            $sub->processContent();

            // Set eval string like in a parent
            foreach ( $sub->verdict as &$vulnerabilities ) {
                $vulnerabilities = array($evaluation_string => current($vulnerabilities));
            }
            unset($vulnerabilities);

            /** Merge verdicts */
            $this->verdict = array_merge_recursive($this->verdict, $sub->verdict);
        }

        $this->cleanUpVerdict();
    }

    public function makeVerdict()
    {
        // Detecting bad functions
        foreach ( $this->tokens as $_token ) {
            foreach ( $this->bad_constructs as $severity => $set_of_functions ) {
                if (
                    ! (
                        $this->tokens->prev1->type === 'T_OBJECT_OPERATOR' ||
                        $this->tokens->prev2->type === 'T_FUNCTION'
                    )
                ) {
                    // From common bad_constructs
                    $current_token_value = trim((string)$this->tokens->current->value, '\'');
                    if (in_array($current_token_value, $set_of_functions, true)) {
                        $found_malware_key = array_search($current_token_value, $set_of_functions, true);

                        // If common bad structures found, then check containment for superglobals
                        if ($found_malware_key !== false && $this->checkingSuperGlobalsInTheSystemCommands($this->tokens->current)) {
                            $this->verdict['SUSPICIOUS'][$this->tokens->current->line][] = 'global variables in a sys command';
                            break;
                        }

                        // If the current token is backtick, so we have to check shell command existing inside the backticks.
                        if ( $current_token_value === '`' ) {
                            if ( $this->checkingShellCommand($this->tokens->current) ) {
                                $this->verdict['SUSPICIOUS'][$this->tokens->current->line][] = 'shell command inside the backticks';
                            }
                            break;
                        }

                        $this->verdict[$severity][$this->tokens->current->line][] = $set_of_functions[$found_malware_key];
                    }
                }
            }

            // From special decrypted constructs
            if ($this->checkingSpecialDecryptedToken($this->tokens->current)) {
                $found_malware_key                                        = array_search(
                    $this->tokens->current->value,
                    $this->dangerous_decoded_values,
                    true
                );
                $this->verdict['SUSPICIOUS'][$this->tokens->current->line][] = $this->dangerous_decoded_values[$found_malware_key];
            } elseif ($this->checkingDecryptedToken($this->tokens->current)) {
                $this->verdict['SUSPICIOUS'][$this->tokens->current->line][] = 'the function contains suspicious arguments';
            }
        }

        // Adding bad includes to $verdict['SEVERITY']['string_num'] = 'whole string with include'
        foreach ( $this->includes->includes as $include ) {
            if ( $include['status'] === false ) {
                if ( $include['not_url'] === false && $include['ext_good'] === false ) {
                    $this->verdict['SUSPICIOUS'][$include['string']][] = substr(
                        $this->tokens->glueTokens(ExtendedSplFixedArray::createFromArray($include['include'])),
                        0,
                        255
                    );
                } elseif ( $include['good'] === false ) {
                    $this->verdict['SUSPICIOUS'][$include['string']][] = substr(
                        $this->tokens->glueTokens(ExtendedSplFixedArray::createFromArray($include['include'])),
                        0,
                        255
                    );
                }
            }
        }

        // Adding bad sql to $verdict['SEVERITY']['string_num'] = 'whole string with sql'
        foreach ( $this->sqls->requests as $sql ) {
            if ( $sql['status'] === false ) {
                $this->verdict['SUSPICIOUS'][$sql['string']][] = substr(
                    $this->tokens->glueTokens(ExtendedSplFixedArray::createFromArray($sql['sql'])),
                    0,
                    255
                );
            }
        }

        if ( $this->entropyAnalyser && $this->entropyAnalyser->getVerdict() ) {
            $this->verdict['SUSPICIOUS'] = $this->entropyAnalyser->getVerdict();
        }

        // Detecting JavaScript injection in HTML
        // @todo Make this work ditch!
        //$html_analyser = new HTML($this->tokens);
        //$html_analyser->analise();
        //if( $html_analyser->result ){
        //    $this->verdict['SUSPICIOUS'][ $html_analyser->result ][] = 'inappropriate_html';
        //}

        foreach ($this->code_style->detectBadLines() as $line => $bad_style) {
            $this->verdict['SUSPICIOUS'][$line][] = $bad_style;
        }
    }

    public function cleanUpVerdict()
    {
        // Delete whole category if it's empty
        foreach ( $this->verdict as $category_name => $verdict_category ) {
            if ( empty($verdict_category) ) {
                unset($this->verdict[$category_name]);
            }
        }
    }

    /**
     * Return all found includes
     *
     * @return array
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function getIncludes()
    {
        return $this->includes->includes;
    }

    /**
     * Return all found includes
     *
     * @return array
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function getSQLs()
    {
        return $this->sqls->requests;
    }

    /**
     * Return all found includes
     *
     * @return array
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function getVariables()
    {
        return [
            'variables' => $this->variables->variables,
            'arrays'    => $this->variables->arrays,
            'constants' => $this->variables->constants,
        ];
    }

    /**
     * Return all found includes
     *
     * @return array
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function getVariablesBad()
    {
        return $this->variables->variables_bad;
    }

    private function checkingSpecialDecryptedToken(DataStructures\Token $token)
    {
        if (!$token->existsTag('glued')) {
            return false;
        }

        return $token->type === 'T_CONSTANT_ENCAPSED_STRING' &&
            is_callable(trim((string)$token->value, '\'')) &&
            in_array(trim((string)$token->value, '\''), $this->dangerous_decoded_values, true);
    }

    private function checkingDecryptedToken(DataStructures\Token $token)
    {
        if ($token->existsTag('suspicious_args')) {
            return true;
        }

        return false;
    }

    /**
     * Check if super global variables found in the token applications.
     * @param Token $token
     * @return bool
     */
    private function checkingSuperGlobalsInTheSystemCommands(DataStructures\Token $token)
    {
        //search for next semicolon to find depth of seek
        $end_of_expression = $this->tokens->searchForward($token->key, array(';','`','?'));
        $depth = $end_of_expression ? $end_of_expression - $token->key : 0;
        foreach ($this->super_globals as $super_global) {
            //search for superglobs usage
            $forward_look_super_globals = $this->tokens->searchForward($token->key, $super_global, $depth);
            if (false !== $forward_look_super_globals) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checking if the backticks "`" contains a shell command.
     *
     * @param Token $token
     * @return bool
     */
    private function checkingShellCommand(DataStructures\Token $token)
    {
        $end_of_expression = $this->tokens->searchForward($token->key, '`');

        if ( $end_of_expression ) {
            $tokens = $this->tokens->getRange($token->key + 1, $end_of_expression - 1);
            if ( count($tokens) > 0 ) {
                $first_token_value = trim($tokens[0][1], "'\"");
                $exploded_command = explode(' ', trim($first_token_value, "'\""));
                $command = $exploded_command[0];
                if ( $command && preg_match('#^((0<&196;)|([A-Za-z]*=)|([a-z]{2,}\.*_*\d*[a-z\d]* )){1,1}[a-zA-Z =\/\\\'\d><_+-.|:; &$]*$#', $command) ) {
                    return true;
                }
            }
        }
        return false;
    }

    private function getResultCode()
    {
        $output = '';
        foreach ( $this->tokens as $token ) {
            if ( !is_null($token) ) {
                $output .= $token[1];
            }
        }
        return $output;
    }
}
