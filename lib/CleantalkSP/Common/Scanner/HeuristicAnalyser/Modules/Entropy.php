<?php

namespace CleantalkSP\Common\Scanner\HeuristicAnalyser\Modules;

use CleantalkSP\Common\Scanner\HeuristicAnalyser\Vendors\TiktokenPhp\src\Encoder;

class Entropy
{
    /**
     * @var array|null
     */
    private $verdict;

    /**
     * Flag - is need to check variables separately
     * @var bool
     */
    private $is_file_suspicious;

    /**
     * @param string $path
     */
    public function __construct($path)
    {
        $this->is_file_suspicious = $this->analyseFile($path);
    }

    /**
     * Analysing variables one by one and making verdict to each ones
     *
     * @param Variables $variables
     * @return void
     */
    public function analyse(Variables $variables)
    {
        if ( !$this->is_file_suspicious ) {
            return;
        }

        $variables_obj = $variables->variables;
        $variable_names = array_keys($variables->variables);

        if ( !count($variable_names) ) {
            return;
        }

        $encoder = new Encoder();
        $detected_unreadable_variables = [];
        foreach ( $variable_names as $variable ) {
            // do not change empty state! this change is from heur package!
            if ( empty($variables_obj[$variable]) ) {
                continue;
            }
            if ( strpos($variable, '_') === 0 || strlen($variable) < 5 ) {
                continue;
            }
            $num_tokens = count($encoder->encode($variable));
            if ( ! $num_tokens ) {
                continue;
            }
            $res = strlen($variable) / $num_tokens;
            if ( $res < 2 && isset($variables_obj[$variable][0][2]) ) {
                $detected_unreadable_variables[$variables_obj[$variable][0][2]] = [$variable];
            }
        }

        if ( count($detected_unreadable_variables) ) {
            $this->verdict = $detected_unreadable_variables;
        }
    }

    /**
     * Analysing average unreadable score for the full file
     *
     * @param $path
     * @return bool
     */
    private function analyseFile($path)
    {
        $variable_names = $this->extractVariableNames($path);

        $filtered_names = [];
        foreach ( $variable_names as $variable_name ) {
            if ( strpos($variable_name, '_') !== 0 && strlen($variable_name) >= 5 ) {
                $filtered_names[] = $variable_name;
            }
        }

        $filtered_names = array_unique($filtered_names);
        if ( count($filtered_names) > 3 ) {
            $encoder = new Encoder();
            $sum = 0;

            foreach ( $filtered_names as $filtered_name ) {
                $num_tokens = count($encoder->encode($filtered_name));
                if ( ! $num_tokens ) {
                    continue;
                }
                $res = strlen($filtered_name) / $num_tokens;
                $sum += $res;
            }

            $average_tokenization = $sum / count($filtered_names);

            if ( $average_tokenization < 2 ) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param $path
     * @return string[]
     */
    private function extractVariableNames($path)
    {
        $content = file_get_contents($path);
        preg_match_all('/\$([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)/', $content, $matches);
        return $matches[1];
    }

    /**
     * @return array|null
     */
    public function getVerdict()
    {
        return $this->verdict;
    }
}
