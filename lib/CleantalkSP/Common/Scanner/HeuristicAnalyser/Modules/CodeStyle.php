<?php

namespace CleantalkSP\Common\Scanner\HeuristicAnalyser\Modules;

use CleantalkSP\Common\Scanner\HeuristicAnalyser\DataStructures\Token;

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
     * @const How many different upper/lowercase chars should be provided to being get in weight count.
     */
    const RANDOM_CHAR_CASE_VOLATILITY_LIMIT = 3;
    /**
     * @const Minimum word length to check for random structures
     */
    const RANDOM_MIN_WORD_LEN = 5;
    /**
     * @const Maximum word length to check for random structures
     */
    const RANDOM_MAX_WORD_LEN = 5;
    /**
     * @const Sensitivity for random total weight
     */
    const RANDOM_TOTAL_WEIGHT_THRESHOLD = 1.00;
    /**
     * @const Sensitivity for special chars proportion
     */
    const SPECIAL_CHARS_PROPORTION_THRESHOLD = 0.33;

    /**
     * Holds numbers of critical long lines
     *
     * @var int[]
     */
    private $critical_long_line_nums = array();

    /**
     * Holds numbers of comments noise lines
     *
     * @var int[]
     */
    private $comment_noise_line_nums = array();

    /**
     * Check if file contains unreadable code
     */
    private $is_unreadable = false;

    /**
     * Check if weight of noise > 5
     *
     * @var bool
     */
    public $comments_noise = false;

    /**
     * Weight of noise
     *
     * @var int
     */
    private $noise_lines = 0;

    /**
     * Noise threshold
     *
     * @var int
     */
    private $noise_lines_threshold = 5;

    /**
     * Noise threshold
     *
     * @var int
     */
    private $noise_matches_threshold = 3;

    /**
     * Array for multi-line comments in one line
     *
     * @var array
     */
    private $matches = array();

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
                if ($this->analyseLineLengthsIsExcludedForLine($line)) {
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
     * Check if the line should be skipped.
     * Uses regexps of known signs to exclude.
     *
     * @param string $line
     * @return bool
     */
    public function analyseLineLengthsIsExcludedForLine($line)
    {
        if (preg_match('#^\s*<path\s+d="[^$][.\w\s-]+"\s*\/>#', $line, $match)) {
            return true;
        }

        return false;
    }

    /**
     * Check if the code is human-unreadable.
     * @param string $content File content.
     * @return void
     */
    public function analyseHumanUnreadableCode($content)
    {
        $proportion_spec_symbols = $this->proportionOfSpecialSymbols();
        $weight = $this->getWeightOfRandomCharStructures($content);

        if (
            $proportion_spec_symbols >= self::SPECIAL_CHARS_PROPORTION_THRESHOLD
            ||
            $weight > self::RANDOM_TOTAL_WEIGHT_THRESHOLD
        ) {
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

        //todo Merging on int indexes will rewrite current line weak_spot
        if ($this->is_unreadable) {
            $result = array_merge($result, [1 => 'unreadable']);
        }

        //todo This will replace other weak_spots on the line
        if ($this->comments_noise) {
            $first_comments_noise_line = (int)array_shift($this->comment_noise_line_nums);
            $result[$first_comments_noise_line] = 'comments noise';
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

    /**
     * Count special service chars like <>!= etc. and return the proportion to the total chars count.
     * Uses $this->tokens as content source.
     * @return float 0.0 -> 1.0
     */
    private function proportionOfSpecialSymbols()
    {
        $glued_content = '';

        foreach ($this->tokens->tokens as $token) {
            $token_value = '';
            //convert token to array if object provided
            if ($token instanceof Token) {
                $token = $token->toArray();
            }
            if (is_array($token)) {
                //if the token is comment, skip it
                if (in_array($token[0], [T_COMMENT, T_DOC_COMMENT])) {
                    continue;
                }
                $token_value = $token[1];
            }
            // glue all
            $glued_content .= $token_value;
        }
        if ( !empty($glued_content) ) {
            /**
             * This regexp match all symbols except letters, digits and whitespaces in a core. However,
             * we would exclude some chars that usually not used in the code, but can be used in a human text.
             * To check the list of all symbols that will be matched by this regexp, you can use this code:
             *
             *  $arr = array_count_values($symbols[0]);
             *  asort($arr);
             *  var_dump($arr);
             *
             */
            preg_match_all('#[^\pL\s\d\'\"()*\-+;&_@?!.,:%`]#', $glued_content, $symbols);
            /**
             * Notice:
             * Extended regexp to exclude more service chars, use or upgrade the current if there will be false positives:
             * preg_match_all('#[^\pL\s\d\'\"()\[\]*{}\-_\\\/@<>?!=.,:%`]#', $glued_content, $symbols);
             */
            if (isset($symbols[0]) && count($symbols[0]) > 0) {
                return count($symbols[0]) / (strlen($glued_content));
            }
        }

        return 0.0;
    }

    /**
     * Break the content to a several `words` and run a couple of checks
     * to calculate weight of random-char structures in this.
     * Increments if:
     * <ul>
     * <li> "+" char provided</li>
     * <li> char case volatility more than limit</li>
     * <li> if the word contains a lexeme like `x8k`, `p9R` etc.</li>
     * </ul>
     * @param string $content File content.
     * @return float Normal value is <= 1.00
     */
    private function getWeightOfRandomCharStructures($content)
    {
        $weight = 0.0;
        /**
         * Find the words to check. Global regex.
         */
        preg_match_all('#[a-zA-Z\d_\-+\\\/]+#', $content, $words);
        $words = isset($words[0]) ? $words[0] : [];
        $words = array_filter($words, function ($word) {
            return strlen($word) > self::RANDOM_MIN_WORD_LEN && strlen($word) < self::RANDOM_MAX_WORD_LEN;
        });
        $words = array_values($words);

        /**
         * Start check for each word.
         */
        $words_weight_data = [];
        foreach ($words as $word) {
            //init word random weight, could be between 0 -> 3
            $words_weight_data[$word] = 0;

            /**
             * Check + char provided
             */
            //todo What is this for?
            if (strpos($word, '+') !== false) {
                $words_weight_data[$word] += 1;
            }

            /**
             * Check char case volatility
             */
            $lower_word = strtolower($word);
            //skip case checking if no case difference
            $skip_caps_checking = $lower_word === $word || strtoupper($word) === $word;
            if ( ! $skip_caps_checking ) {
                //get count of chars that has case difference
                $count_of_case_volatile_chars = strlen($lower_word) - similar_text($lower_word, $word);
                //inc weight if volatile chars count more than the limit
                if ($count_of_case_volatile_chars > self::RANDOM_CHAR_CASE_VOLATILITY_LIMIT) {
                    $words_weight_data[$word] += 1;
                }
            }

            /**
             * Check if the word contains a lexeme like `x8k`, `p9R` etc
             */
            if (preg_match('#[^\d]\d+[\w]#', $word)) {
                $words_weight_data[$word] += 1;
            }
        }

        /**
         * Calculate result.
         * Result is a total sum of words weights divided by total count of words found in the content.
         * Normal value is <= 1.
         */
        if ( !empty($words_weight_data) ) {
            $weight = array_sum(array_values($words_weight_data)) / count($words_weight_data);
        }

        return $weight;
    }

    public function analyseWeightOfNoise($content)
    {
        $lines = preg_split("/((\r?\n)|(\r\n?))/", $content);

        // few multiline comments in one string
        for ( $line_num = 1; isset($lines[$line_num - 1]); $line_num++ ) {
            try {
                $line = $lines[$line_num - 1];
                preg_match_all('#\/\*\s*\w{1,5}\s*\*\/#', $line, $this->matches);
                if (count($this->matches[0]) > $this->noise_matches_threshold) {
                    $this->noise_lines++;
                }
                if ($this->noise_lines > $this->noise_lines_threshold) {
                    $this->comment_noise_line_nums[] = $line_num;
                    $this->comments_noise = true;
                }
            } catch (\Exception $_e) {
                continue;
            }
        }
    }
}
