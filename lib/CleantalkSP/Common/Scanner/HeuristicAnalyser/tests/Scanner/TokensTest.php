<?php

use CleantalkSP\Common\Scanner\HeuristicAnalyser\DataStructures\Token;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\Modules\Tokens;
use PHPUnit\Framework\TestCase;

class TokensTest extends TestCase
{
    private $tokens;

    public function setUp()
    {
        $file_content = "<?php
            echo('hello');        
        ";
        $this->tokens = new Tokens($file_content);
    }

    public function testGetTokenFromPosition()
    {
        $echo_token = $this->tokens->getTokenFromPosition(2);
        $this->assertInstanceOf(Token::class, $echo_token);
        $this->assertEquals($echo_token[0], 'T_ECHO');
        $this->assertEquals($echo_token[1], 'echo');
    }
}
