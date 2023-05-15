<?php

namespace CleantalkSP\SpbctWP\Scanner\Heuristic;

use CleantalkSP\DataStructures\ExtendedSplFixedArray;
use CleantalkSP\Common\Helpers\Arr;

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

    public $error = array();

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
        'CRITICAL'   => array(
            'eval',
            'assert',
            'create_function',
            // 'unserialize',
        ),
        'DANGER'     => array(
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
            'str_rot13',
            'syslog',
        ),
    );

    /**
     * Contains a set of dangerous values that have been decoded
     * @var string[]
     */
    private $dangerous_decoded_values = array(
        'base64_decode',
        'base64_encode'
    );

    /** Modules */

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
     * Heuristic constructor.
     * Getting common info about file|text and it's content
     *
     * @param array $input
     * @param self $self
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

            if ( $this->checkFileSize(strlen($input['content'])) ) {
                $this->file_size    = strlen($input['content']);
                $this->file_work    = $input['content'];
                $this->file_content = $this->file_work;
            }
            // Accept file as a path
        } elseif ( isset($input['path']) ) {
            $this->path      = $input['path'];
            $this->curr_dir  = dirname($this->path);
            $this->extension = pathinfo($this->path, PATHINFO_EXTENSION);
            if ( $this->checkFileAccessibility() && $this->checkFileSize(filesize($this->path)) ) {
                $this->file_size    = (int)filesize($this->path);
                $this->file_work    = file_get_contents($this->path);
                $this->file_content = $this->file_work;
            }
            // Bad params provided
        } else {
            $this->error = array('error' => 'BAD_PARAMS');
        }

        if ( $this->error ) {
            return;
        }

        $this->tokens          = new Tokens($this->file_content);
        $this->simplifier      = new Simplifier($this->tokens);
        $this->strings         = new Strings($this->tokens);
        $this->variables       = new Variables($this->tokens);
        $this->sqls            = new SQLs($this->tokens, $this->variables);
        $this->transformations = new Transformations($this->tokens);
        $this->includes        = new Includes($this->tokens, $this->variables, $this->curr_dir, $this->is_text);
        $this->evaluations     = new Evaluations($this->tokens, $this->variables, $this->includes, $this->sqls);
        $this->code_style      = new CodeStyle($this->tokens);
    }

    private function checkFileAccessibility()
    {
        if ( ! file_exists($this->path) ) {
            $this->error = array('error' => 'FILE_NOT_EXISTS');

            return false;
        }

        if ( ! is_readable($this->path) ) {
            $this->error = array('error' => 'FILE_NOT_READABLE');

            return false;
        }

        if ( ! is_file($this->path) || is_dir($this->path) || is_link($this->path) ) {
            $this->error = array('error' => 'IS_NOT_A_FILE');

            return false;
        }

        return true;
    }

    private function checkFileSize($file_size)
    {
        if ( ! (int)$file_size ) {
            $this->error = array('error' => 'FILE_SIZE_ZERO');

            return false;
        }

        if ( (int)$file_size > self::FILE_MAX_SIZE ) {
            $this->error = array('error' => 'FILE_SIZE_TO_LARGE');

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
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function processContent()
    {
        // Analysing code style
        // Do this, only for initial code
        if ( ! $this->evaluations->evaluations ) {
            $this->code_style->analiseLineLengths($this->file_content);

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
                $this->strings->convertToSimple($key);
                $this->strings->convertChrFunctionToString($key);
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
                // $this->transformations->decodeData($key);
            }

            $this->variables->concatenate(); // Concatenates variable content if it's possible
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
                    !(
                        $this->tokens->prev1->type === 'T_OBJECT_OPERATOR' ||
                        $this->tokens->prev2->type === 'T_FUNCTION'
                    )
                ) {
                    // From common bad_constructs
                    if (in_array(trim((string)$this->tokens->current->value, '\''), $set_of_functions, true)) {
                        $found_malware_key                                        = array_search(
                            $this->tokens->current->value,
                            $set_of_functions,
                            true
                        );
                        $this->verdict[$severity][$this->tokens->current->line][] = $set_of_functions[$found_malware_key];
                    // From special decrypted constructs
                    } elseif ($this->checkingSpecialDecryptedToken($this->tokens->current)) {
                        $found_malware_key                                        = array_search(
                            $this->tokens->current->value,
                            $this->dangerous_decoded_values,
                            true
                        );
                        $this->verdict['CRITICAL'][$this->tokens->current->line][] = $this->dangerous_decoded_values[$found_malware_key];
                    } elseif ($this->checkingGluedToken($this->tokens->current)) {
                        $this->verdict['SUSPICIOUS'][$this->tokens->current->line][] = 'obfuscation tag script';
                    } elseif ($this->checkingDecryptedToken($this->tokens->current)) {
                        $this->verdict['CRITICAL'][$this->tokens->current->line][] = 'the function contains suspicious arguments';
                    }
                }
            }
        }

        // Adding bad includes to $verdict['SEVERITY']['string_num'] = 'whole string with include'
        foreach ( $this->includes->includes as $include ) {
            if ( $include['status'] === false ) {
                if ( $include['not_url'] === false && $include['ext_good'] === false ) {
                    $this->verdict['CRITICAL'][$include['string']][] = substr(
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

        // Detecting JavaScript injection in HTML
        // @todo Make this work ditch!
        //$html_analyser = new HTML($this->tokens);
        //$html_analyser->analise();
        //if( $html_analyser->result ){
        //    $this->verdict['SUSPICIOUS'][ $html_analyser->result ][] = 'inappropriate_html';
        //}

        $this->mergeVerdicts($this->code_style->detectBadLines());
    }

    /**
     * Merge verdicts from different modules
     *
     * @param $verdict_to_merge
     */
    private function mergeVerdicts($verdict_to_merge)
    {
        foreach ( $this->verdict as $severity => &$line_nums_verdict ) {
            foreach ( $line_nums_verdict as $line_num => $_verdict ) {
                if ( isset($verdict_to_merge[$severity][$line_num]) ) {
                    $this->verdict[$severity][$line_num][] = $verdict_to_merge[$severity][$line_num];
                }
            }
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

    private function checkingGluedToken(DataStructures\Token $token)
    {
        if (!$token->existsTag('glued')) {
            return false;
        }

        return $token->type === 'T_CONSTANT_ENCAPSED_STRING' &&
               stripos((string)$token->value, '<script');
    }

    private function checkingDecryptedToken(DataStructures\Token $token)
    {
        if ($token->existsTag('suspicious_args')) {
            return true;
        }

        return false;
    }
}
