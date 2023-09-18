<?php

use CleantalkSP\Common\Scanner\HeuristicAnalyser\Modules\HTML;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\Modules\Tokens;
use PHPUnit\Framework\TestCase;

class HTMLTest extends TestCase
{
    private $html;

    public function setUp()
    {
        $file_content = "<?php
        echo(
            '<script>alert(1);</script>'
        );
        ?>
        <script>alert(2);</script>
        ";
        $tokens = new Tokens($file_content);
        $this->html = new HTML($tokens);
    }

    public function testAnalise()
    {
        $this->html->analise();
        $this->assertEquals('T_INLINE_HTML', $this->html->result);
    }
}
