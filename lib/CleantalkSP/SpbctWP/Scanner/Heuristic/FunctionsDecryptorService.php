<?php

namespace CleantalkSP\SpbctWP\Scanner\Heuristic;

class FunctionsDecryptorService
{
    private $tokens;
    private $suspiciousFunctions = array(
        'base64_decode',
        'str_rot13'
    );
    private $suspiciousResults = array(
        'function_exists',
        'time',
        'fopen',
        'file_put_contents',
        'file_exists',
        'is_writable',
        'chmod',
        'touch'
    );
    private $results = array();

    public function __construct(Tokens $tokens)
    {
        $this->tokens = $tokens;
    }

    public function searchSuspiciousFunctions()
    {
        foreach ( $this->tokens as $index => $token ) {
            if (
                $token &&
                $token->type === 'T_STRING' &&
                in_array($token->value, $this->suspiciousFunctions)
            ) {
                $this->results[$index] = array(
                    'f_name' => $token->value
                );
            }
        }

        return $this;
    }

    /** @psalm-suppress PossiblyUnusedMethod */
    public function searchFunctionArgs()
    {
        $token_indexes = array_keys($this->results);

        foreach ($this->results as $index => $_item) {
            $first_required_token_index = $this->nextTokenValueIs('(', $index);

            if (!$first_required_token_index) {
                unset($this->results[$index]);
                continue;
            }

            $last_required_token_index = $this->searchTokenValueIs(')', $first_required_token_index, next($token_indexes));

            if (!$last_required_token_index) {
                unset($this->results[$index]);
                continue;
            }

            // Get all between $first_required_token_index and $last_required_token_index
            $this->fillFunctionArgs($first_required_token_index, $last_required_token_index, $index);
        }

        return $this;
    }

    public function nextTokenValueIs($string, $currentTokenIndex, $limit = 10)
    {
        for ($i = 1; $i <= $limit; $i++) {
            if ($this->tokens[$currentTokenIndex + $i] && $this->tokens[$currentTokenIndex + $i]->value !== $string) {
                return false;
            }
            if ($this->tokens[$currentTokenIndex + $i] && $this->tokens[$currentTokenIndex + $i]->value === $string) {
                return $currentTokenIndex + $i;
            }
        }

        return false;
    }

    public function searchTokenValueIs($string, $currentTokenIndex, $limit = 10)
    {
        if (!$limit) {
            $limit = 10;
        }
        for ($i = 1; $i <= $limit; $i++) {
            if ($this->tokens[$currentTokenIndex + $i] && $this->tokens[$currentTokenIndex + $i]->value === $string) {
                return $currentTokenIndex + $i;
            }
        }

        return false;
    }

    private function fillFunctionArgs($start_token_index, $end_token_index, $index)
    {
        $function_arg = '';
        for ($i = $start_token_index; $i <= $end_token_index; $i++) {
            if ($this->tokens[$i]) {
                $function_arg .= $this->tokens[$i]->value;
            }
        }
        $this->results[$index]['f_args'] = trim($function_arg, '()');
    }

    /** @psalm-suppress UnusedMethod */
    private function launchingFunctions()
    {
        foreach ($this->results as $index => $item) {
            $this->results[$index]['f_result'] = $item['f_name']($item['f_args']);
        }

        return $this;
    }

    /** @psalm-suppress UnusedMethod */
    private function verdict()
    {
        foreach ($this->results as $index => $item) {
            foreach ($this->suspiciousResults as $suspiciousResult) {
                if (stripos($item['f_result'], $suspiciousResult) !== false) {
                    $this->tokens[$index]->addTag('suspicious_args');
                }
            }
        }
    }

    public function handle()
    {
        $this
            ->searchSuspiciousFunctions()
            ->searchFunctionArgs()
            ->launchingFunctions()
            ->verdict();
    }
}
