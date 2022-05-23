<?php


namespace CleantalkSP\SpbctWP\Scanner\Heuristic;


class CodeStyle
{
    /**
     * @var Tokens
     */
    private $tokens;
    
    /**
     * @var int shows how many symbols could contains normal code line
     */
    const NORMAL_CODE_STRING_LENGTH = 300;
    
    /**
     * @var int shows how many symbols could contains normal code line
     */
    const CRITICAL_CODE_STRING_LENGTH = 500;
    
    /**
     * Holds all lines length
     * Indexed by line numbers
     *
     * @var int[]
     */
    private $line_lengths = array();
    
    /**
     *
     * @var int[]
     */
    private $long_line_nums;
    
    /**
     * Holds numbers of critical long lines
     *
     * @var int[]
     */
    private $critical_long_line_nums;
    
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
    private $length_of_tokens__code     = 0;
    private $length_of_tokens__html     = 0;
    private $length_of_tokens__comments = 0;
    
    /**
     * Line numbers with tokens contains code|html|comments
     *
     * @var int
     */
    private $number_of_lines__code     = array();
    private $number_of_lines__html     = array();
    private $number_of_lines__comments = array();
    
    public function __construct(Tokens $tokens)
    {
        $this->tokens = $tokens;
    }
    
    public function analiseLineLengths(&$content)
    {
        $lines = explode("\r", $content);
        
        for( $line_num = 1; isset($lines[$line_num - 1]); $line_num++ ){
            
            $this->line_lengths[$line_num] = strlen($lines[$line_num - 1]);
            
            if( $this->line_lengths[$line_num] > self::NORMAL_CODE_STRING_LENGTH ){
                $this->long_line_nums[] = $line_num;
            }
            
            if( $this->line_lengths[$line_num] > self::CRITICAL_CODE_STRING_LENGTH ){
                $this->critical_long_line_nums[] = $line_num;
            }
        }
    }
    
    public function searchIncompatibleOnelinedTokens()
    {
        if( $this->tokens->current->isTypeOf( 'one_line') ){
            $this->greedy_token_lines[] = $this->tokens->current->line;
        }
    }
    
    public function sortTokensWithDifferentTypes(){
        
        $current_token_length = $this->tokens->current->length;
        $current_token_line   = $this->tokens->current->line;
        
        if( $this->tokens->current->isTypeOf('html') ){
            $this->tokens->html[]          =  $this->tokens->current;
            $this->length_of_tokens__html  += $current_token_length;
            $this->number_of_lines__html[] =  $current_token_line;
            
        }elseif( $this->tokens->current->isTypeOf('comments') ){
            $this->tokens->comments[]          =  $this->tokens->current;
            $this->length_of_tokens__comments  += $current_token_length;
            $this->number_of_lines__comments[] =  $current_token_line;
            
        }else{
            $this->length_of_tokens__code  += $current_token_length;
            $this->number_of_lines__code[] =  $current_token_line;
        }
    }
    
    public function detectBadLines()
    {
        $line_nums = array_intersect($this->greedy_token_lines, array_unique($this->greedy_token_lines));
        $values    = array_fill(0, count($line_nums), 'BAD_LINE__INTERSECTED_TOKENS');
        
        return array_combine($line_nums, $values);
    }
}