<?php

namespace CleantalkSP\Common\Scanner\HeuristicAnalyser\Modules;

use CleantalkSP\Common\Scanner\HeuristicAnalyser\DataStructures\Token;

class Strings
{
    public $tokens;

    public function __construct(Tokens $tokens_handler)
    {
        $this->tokens = $tokens_handler;
    }

    /**
     * Deletes T_ENCAPSED_AND_WHITESPACE
     * Converts T_ENCAPSED_AND_WHITESPACE to T_CONSTANT_ENCAPSED_STRING if could
     *
     * @param int $key
     *
     * @return true|false Always returns false, because it doesn't unset current element
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public function convertToSimple($_key)
    {
        if (
            $this->tokens->prev1->value === '"' &&
            $this->tokens->current->type === 'T_ENCAPSED_AND_WHITESPACE' &&
            $this->tokens->next1->value === '"'
        ) {
            $this->tokens->unsetTokens('next1', 'prev1');
            $this->tokens['current'] = new Token(
                'T_CONSTANT_ENCAPSED_STRING',
                '\'' . $this->tokens->current->value . '\'',
                $this->tokens->current->line,
                $this->tokens->current->key
            );

            return true;
        }

        return false;
    }

    /**
     * Convert chr('\xNN') to 'a'
     *
     * @param int $key
     *
     * @return bool For now, Always returns false, because it doesn't unset current element
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public function convertChrFunctionToString($_key)
    {
        // @todo rearrange condition sequence. Make $this->tokens->prev3->value === 'chr' first.
        if (
            $this->tokens->current->value === ')' &&
            $this->tokens->prev2->value === '(' &&
            $this->tokens->prev1->isTypeOf('chr_func_val') &&
            $this->tokens->prev3->type === 'T_STRING' &&
            $this->tokens->prev3->value === 'chr'
        ) {
            $char_num                = (int)trim((string)$this->tokens->prev1->value, '\'"');
            $this->tokens['current'] = new Token(
                'T_CONSTANT_ENCAPSED_STRING',
                '\'' . (chr($char_num) ?: '') . '\'',
                $this->tokens->prev3->line,
                $this->tokens->current->key
            );
            $this->tokens->unsetTokens('prev1', 'prev2', 'prev3');

            return true;
        }

        return false;
    }

    /**
     * Convert chars present like "\xNN" to their symbols representation
     *
     * @param int $key
     *
     * @return false Always return false, do not change token structure ever
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public function convertHexSymbolsToString($_key)
    {
        if (
            $this->tokens->current->type === 'T_CONSTANT_ENCAPSED_STRING' &&
            // Compare first letter of a string to differ '\xNN' string from "\xNN". Quotes difference
            $this->getFirstLetter($this->tokens->current->value) === '"' &&
            preg_match_all('@\\\\x([\da-fA-F]{1,2})@', (string)$this->tokens->current->value, $matches) &&
            isset($matches[1])
        ) {
            $replacements               = array_map(
                static function ($elem) {
                    return chr(hexdec($elem));
                },
                $matches[1]
            );
            $this->tokens['current'][1] = str_replace($matches[0], $replacements, (string)$this->tokens->current->value);
        }

        return false;
    }

    /**
     * Convert file_get_contents(__DIR__ . '/file.example') to gathered content string
     *
     * @param string $current_file_path
     * @return void
     */
    public function convertFileGetContentsToString($current_file_path)
    {
        if (
            $this->tokens->current->type === 'T_STRING' &&
            $this->tokens->current->value === 'file_get_contents' &&
            $this->tokens->next1->value === '('
        ) {
            $start_position = $this->tokens->next1[3];
            $closing_bracket_position = $this->tokens->searchForward($start_position, ')');
            $tokens_inside_brackets = $this->tokens->getRange($start_position + 1, $closing_bracket_position - 1);

            // Check against of nested bracers.
            // @ToDo implement nested bracers values calculating
            $is_nested_bracers = false;
            foreach ( $tokens_inside_brackets as $token ) {
                if ( $token->value === '(' ) {
                    $is_nested_bracers = true;
                }
            }

            if ( $is_nested_bracers ) {
                return;
            }

            // Calculate path string
            $path = '';
            foreach ($tokens_inside_brackets as $token) {
                if ( $token->isTypeOf('could_be_concatenated') ) {
                    $path .= trim((string)$token->value, '\'');
                }
                if ( $token->type === 'T_DIR' ) {
                    $path .= dirname($current_file_path);
                }
            }

            if ( $path && file_exists($path) ) {
                // Delete tokens which contained the file_get_contents expression
                for ( $i = $start_position; $i <= $closing_bracket_position; $i++ ) {
                    $this->tokens->unsetTokens($i);
                }

                // Insert newly calculated token with gathered content string
                $this->tokens['current'] = new Token(
                    'T_LNUMBER',
                    @file_get_contents($path),
                    $this->tokens->current->line,
                    $this->tokens->current->key
                );
            }
        }
    }

    /**
     * Concatenates simple strings with type T_CONSTANT_ENCAPSED_STRING
     *
     * @param int $key
     *
     * @return bool true if the function unset any elements
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public function concatenateSimpleStrings($_key)
    {
        if (
            $this->tokens->current->isTypeOf('simple_strings') &&
            $this->tokens->next1->isTypeOf('simple_strings')
        ) {
            $this->tokens['current'] = new Token(
                'T_CONSTANT_ENCAPSED_STRING',
                "'" . trim((string)$this->tokens->current->value, '\'"') . trim((string)$this->tokens->next1->value, '\'"') . "'",
                $this->tokens->current->line,
                $this->tokens->current->key
            );
            $this->tokens->unsetTokens('next1');

            return true;
        }

        return false;
    }

    /**
     * Concatenates 'a'.'b' and "a"."b" to 'ab'
     *
     * @param int $key
     *
     * @return bool Shows if any elements were unset
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public function concatenateComplexStrings($_key)
    {
        if (
            $this->tokens->current->value === '.' &&
            $this->tokens->prev1->isTypeOf('could_be_concatenated') &&
            $this->tokens->next1->isTypeOf('could_be_concatenated')
        ) {
            $left_val = $this->tokens->prev1->type === 'T_CONSTANT_ENCAPSED_STRING'
                ? $this->getFirstLetter($this->tokens->current->value) === '"'
                    ? preg_replace(['/\\\\"/', "/'/"], ['"', "\'"], substr((string)$this->tokens->prev1->value, 1, -1))
                    : substr((string)$this->tokens->prev1->value, 1, -1)
                : $this->tokens->prev1->value;

            $right_val = $this->tokens->next1->type === 'T_CONSTANT_ENCAPSED_STRING'
                ? $this->getFirstLetter($this->tokens->current->value) === '"'
                    ? preg_replace(['/\\\\"/', "/'/"], ['"', "\'"], substr((string)$this->tokens->next1->value, 1, -1))
                    : substr((string)$this->tokens->next1->value, 1, -1)
                : $this->tokens->next1->value;

            switch ($left_val . $right_val) {
                case 'eval':
                    $token_type = 'T_EVAL';
                    break;
                case 'assert':
                case 'create_function':
                    $token_type = 'T_STRING';
                    break;
                default:
                    $token_type = 'T_CONSTANT_ENCAPSED_STRING';
            }

            $value = $token_type === 'T_CONSTANT_ENCAPSED_STRING' ? "'" . $left_val . $right_val . "'" : $left_val . $right_val;

            $this->tokens['current'] = new Token(
                $token_type,
                $value,
                $this->tokens->current->line,
                $this->tokens->current->key
            );

            $this->tokens['current']->addTag('glued');

            $this->tokens->unsetTokens('prev1', 'next1');

            return true;
        }

        return false;
    }

    /**
     * Get first letter of the string.
     *
     * @param $string
     *
     * @return string One symbol - first letter
     */
    private function getFirstLetter($string)
    {
        return $string[0];
    }
}
