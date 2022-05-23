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
    
    
    public function __construct( Tokens $tokens )
    {
        $this->tokens = $tokens;
    }
    

    public function analise()
    {
        if(
            count($this->tokens->html) === 1 &&
            strlen($this->tokens->html[0][1]) < $this->max_token_size_to_analise
        ){
            $this->tokens->html[0] = $this->simplifyHTMLToken( $this->tokens->html[0] );
            preg_match('#<script>[\s\S]+</script>#', $this->tokens->html[0][1]);
            $this->result = $this->tokens->html[0];
            
            return true;
        }
        
        return false;
    }
    
    private function simplifyHTMLToken( $token )
    {
        $token[1] = preg_replace('#<!--[\s\S]*-->#', '', $token[1]); // Strip comments
        $token[1] = preg_replace('#[\n\t\r]#', '', $token[1]);       // Strip empty new lines and tabs
        
        return $token;
    }
}