<?php

namespace CleantalkSP\SpbctWP\Scanner\Heuristic;

class HTML
{
    /**
     * @var Tokens
     */
    private $tokens;
    private $max_token_size_to_analise = 300;

    public $result = false;


    public function __construct(Tokens $tokens)
    {
        $this->tokens = $tokens;
    }


    public function analise()
    {
        if ( count($this->tokens->html) ) {
            foreach ( $this->tokens->html as $html ) {
                if ( strlen($html[1]) > $this->max_token_size_to_analise ) {
                    continue;
                    //throw new HeuristicScannerException('Analise limit exceeded');
                }
                if ( preg_match('#<script>[\s\S]+</script>#', $html[1]) ) {
                    $this->result = $html[0];
                    // @ToDo have to process not only one first founded suspicious html
                    // @ToDo $this->result must be an array of founded suspicious html
                    // @ToDo need to remove this return statement here
                    return;
                }
            }
        }
    }

    private function simplifyHTMLToken($token)
    {
        $token[1] = preg_replace('#<!--[\s\S]*-->#', '', $token[1]); // Strip comments
        $token[1] = preg_replace('#[\n\t\r]#', '', $token[1]);       // Strip empty new lines and tabs

        return $token;
    }
}
