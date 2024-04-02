<?php

namespace CleantalkSP\Common\Scanner\HeuristicAnalyser\Modules;

class CodeStyle
{
    /**
     * @var Tokens
     */
    private $tokens;

    /**
     * @var int shows how many symbols could contain normal code line
     */
    const CRITICAL_CODE_STRING_LENGTH = 1000;

    /**
     * Holds numbers of critical long lines
     *
     * @var int[]
     */
    private $critical_long_line_nums = array();

    /**
     * Check if file contains unreadable code
     */
    private $is_unreadable = false;

    /**
     * Line numbers with tokens which should be on a different lines
     *
     * @var array
     */
    private $greedy_token_lines = array();

    /**
     * Number of symbols with code|html|comments
     *
     * @var int
     */
    private $length_of_tokens__code = 0;
    private $length_of_tokens__html = 0;
    private $length_of_tokens__comments = 0;

    /**
     * Line numbers with tokens contains code|html|comments
     *
     * @var array
     */
    private $number_of_lines__code = array();
    private $number_of_lines__html = array();
    private $number_of_lines__comments = array();

    public function __construct(Tokens $tokens)
    {
        $this->tokens = $tokens;
    }

    /**
     * @param $content
     * @return void
     * @psalm-suppress UnusedMethod
     */
    public function analyseLineLengths(&$content)
    {
        $lines = preg_split("/((\r?\n)|(\r\n?))/", $content);

        for ( $line_num = 1; isset($lines[$line_num - 1]); $line_num++ ) {
            try {
                $line = $lines[$line_num - 1];
                if ($this->analyseLineLengthsIsExceptions($line)) {
                    continue;
                }
                if ( strlen($line) > self::CRITICAL_CODE_STRING_LENGTH ) {
                    $this->critical_long_line_nums[] = $line_num;
                }
            } catch (\Exception $_e) {
                continue;
            }
        }
    }

    /**
     * Check exceptions for long line
     *
     * @param string $line
     * @return bool
     */
    public function analyseLineLengthsIsExceptions($line)
    {
        if (preg_match('#^\s*<path\s+d="[^$][.\w\s-]+"\s*\/>#', $line, $match)) {
            return true;
        }

        return false;
    }

    public function analyseUnreadableCode(&$content)
    {
        $proportion_spec_symbols = $this->proportionOfSpecialSymbols();
        $weight = $this->getWeightOfRandom($content);

        if ($proportion_spec_symbols <= 3 || $weight > 1 ) {
            $this->is_unreadable = true;
        }
    }

    public function searchIncompatibleOnelinedTokens()
    {
        if ( $this->tokens->current->isTypeOf('one_line') ) {
            $this->greedy_token_lines[] = $this->tokens->current->line;
        }
    }

    public function sortTokensWithDifferentTypes()
    {
        $current_token_length = $this->tokens->current->length;
        $current_token_line   = $this->tokens->current->line;

        if ( $this->tokens->current->isTypeOf('html') ) {
            $this->tokens->html[]          = $this->tokens->current;
            $this->length_of_tokens__html  += $current_token_length;
            $this->number_of_lines__html[] = $current_token_line;
        } elseif ( $this->tokens->current->isTypeOf('comments') ) {
            $this->tokens->comments[]          = $this->tokens->current;
            $this->length_of_tokens__comments  += $current_token_length;
            $this->number_of_lines__comments[] = $current_token_line;
        } else {
            $this->length_of_tokens__code  += $current_token_length;
            $this->number_of_lines__code[] = $current_token_line;
        }
    }

    public function detectBadLines()
    {
        $line_nums = array_unique($this->critical_long_line_nums);
        $values    = array_fill(0, count($line_nums), 'long line');
        $result    = array_combine($line_nums, $values);

        if ($this->is_unreadable) {
            $result = array_merge($result, [1 => 'unreadable']);
        }

        return $result;
    }

    /**
     * Check if file contains PHP open tags ("<\?php" or `<\?`).
     * @return bool
     */
    public function hasPHPOpenTags()
    {
        foreach ( $this->tokens as $_token => $content ) {
            if ( isset($content[0]) && isset($this->tokens->next1[0]) ) {
                if ( $content[0] === 'T_OPEN_TAG' ) {
                    //check if open tag is short
                    $is_short = isset($content[1]) && $content[1] === '<?';
                    if (
                        // should be whitespaces after tag
                        $is_short && $this->tokens->next1[0] === 'T_WHITESPACE' ||
                        // should be whitespaces or variable after tag
                        !$is_short && in_array($this->tokens->next1[0], array('T_WHITESPACE', 'T_VARIABLE'))
                    ) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private function proportionOfSpecialSymbols()
    {
        $content = '';

        foreach ($this->tokens->tokens as $token) {
            $token_value = '';
            if (is_array($token)) {
                if (in_array($token[0], [T_COMMENT, T_DOC_COMMENT])) {
                    continue;
                }
                $token_value = $token[1];
            }

            $content .= $token_value;
        }

        preg_match_all('#[^a-zA-Z\d\s:\.,]#', $content, $symbols);

        if (isset($symbols[0]) && count($symbols[0]) > 0) {
            return strlen($content) / count($symbols[0]);
        }

        return 100;
    }

    private function getWeightOfRandom($content)
    {
        $weight = 0;

        preg_match_all('#[a-zA-Z\d_\-\+]+#', $content, $words);
        $words = isset($words[0]) ? $words[0] : [];

        $words = array_filter($words, function ($word) {
            return strlen($word) > 5 && strlen($word) < 50;
        });
        $words = array_values($words);

        $words_weight = [];
        foreach ($words as $word) {
            $words_weight[$word] = 0;
            $skip_caps_checking = false;
            if (strpos($word, '+') !== false) {
                $words_weight[$word] += 1;
            }
            $lower_word = strtolower($word);
            if ( strtolower($word) === $word || strtoupper($word) === $word ) {
                $skip_caps_checking = true;
            }
            if ( ! $skip_caps_checking && strlen($lower_word) - similar_text($lower_word, $word) > 3 ) {
                $words_weight[$word] += 1;
            }
            if (preg_match('#[^\d]\d+[\w]#', $word)) {
                $words_weight[$word] += 1;
            }
        }

        if (count($words_weight) > 0) {
            $weight = array_sum(array_values($words_weight)) / count($words_weight);
        }

        return $weight;
    }
}
