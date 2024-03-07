<?php

namespace CleantalkSP\Common\Scanner\HeuristicAnalyser\Modules;

use CleantalkSP\Common\Scanner\HeuristicAnalyser\DataStructures\ExtendedSplFixedArray;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\DataStructures\Token;

class Mathematics
{
    /**
     *
     * @var Tokens
     */
    private $tokens;

    public function __construct(Tokens $tokens)
    {
        $this->tokens = $tokens;
    }

    /**
     * Convert mathematics expression to the final value
     *
     * @return array
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public function evaluateMathExpressions()
    {
        $brackets = [
            ['[', ']'],
            ['(', ')']
        ];
        $math_expressions = [];
        foreach ( $brackets as $bracket ) {
            if ( $this->tokens->current->value === $bracket[0] && $this->tokens->next1->value !== $bracket[1] ) {
                $tokens_inside_brackets = $this->getTokensInsideBrackets($bracket[1]);

                if ( count($tokens_inside_brackets) > 1 ) {
                    $expression_string = '';
                    foreach ($tokens_inside_brackets as $token_inside_brackets) {
                        // Getting only value of the token $_index
                        $expression_string .= $token_inside_brackets[1];
                    }
                    // Check if the string is the math expression
                    if ( preg_match('@^([-+]? ?(\d+|\(\g<1>\))( ?[-+*\/] ?\g<1>)?)$@', $expression_string) ) {
                        $math_expressions[] = $expression_string;
                        $math_result = eval('return ' . $expression_string . ';');

                        if ( $bracket[0] === '[' ) {
                            $index_to_insert = 'next1';
                            $start_to_delete = $this->tokens->next1[3];
                            $end_to_delete = $start_to_delete + count($tokens_inside_brackets) - 2;
                        } else {
                            $index_to_insert = 'current';
                            $start_to_delete = $this->tokens->current[3];
                            $end_to_delete = $start_to_delete + count($tokens_inside_brackets) + 1;
                        }
                        // Delete tokens which contained the math expression
                        for ( $i = $start_to_delete; $i <= $end_to_delete; $i++ ) {
                            $this->tokens->unsetTokens($i);
                        }
                        // Insert newly calculated token
                        $this->tokens[$index_to_insert] = new Token(
                            'T_LNUMBER',
                            $math_result,
                            $this->tokens->$index_to_insert->line,
                            $this->tokens->$index_to_insert->key
                        );
                    }
                }
            }
        }
        return $math_expressions;
    }

    /**
     * Getting tokens inside brackets [...], (...), (...(...)...)
     *
     * @param $closing_bracket
     * @return ExtendedSplFixedArray|false
     */
    private function getTokensInsideBrackets($closing_bracket)
    {
        $start_position = $this->tokens->next1[3];
        if ( is_null($start_position) ) {
            // Returns empty array if no more tokens forward
            return new ExtendedSplFixedArray();
        }
        $closing_bracket_position = $this->tokens->searchForward($start_position, $closing_bracket);
        $tokens_inside_brackets = $this->tokens->getRange($start_position, $closing_bracket_position - 1);

        if ( $closing_bracket === ')' ) {
            // Loop: If there are inner brackets - continue searching end of the expression
            $inner_brackets = [];
            do {
                if ( count($inner_brackets) ) {
                    $inner_start_position = $closing_bracket_position;
                    $closing_bracket_position = $this->tokens->searchForward($inner_start_position, $closing_bracket);
                    $tokens_inside_brackets = $this->tokens->getRange($inner_start_position, $closing_bracket_position - 1);
                    array_pop($inner_brackets);
                }

                if ( $tokens_inside_brackets ) {
                    foreach ( $tokens_inside_brackets as $token ) {
                        if ( $token[1] === '(' ) {
                            $inner_brackets[] = $token[1];
                        }
                    }
                }
            } while ( count($inner_brackets) );

            // Get full set of the tokens contains inner brackets too
            $tokens_inside_brackets = $this->tokens->getRange($start_position, $closing_bracket_position - 1);
        }
        return $tokens_inside_brackets;
    }
}
