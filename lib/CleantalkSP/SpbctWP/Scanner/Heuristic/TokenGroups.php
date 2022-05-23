<?php

namespace CleantalkSP\SpbctWP\Scanner\Heuristic;

class TokenGroups
{
    /**
     * @var string[] Equation operation tokens
     */
    public static $equation = array(
        '=',
        'T_CONCAT_EQUAL',
        'T_MINUS_EQUAL',
        'T_MOD_EQUAL',
        'T_MUL_EQUAL',
        'T_AND_EQUAL',
        'T_OR_EQUAL',
        'T_PLUS_EQUAL',
        'T_POW_EQUAL',
        'T_SL_EQUAL',
        'T_SR_EQUAL',
        'T_XOR_EQUAL',
    );
    
    /**
     * @var string[] non PHP tokens
     */
    public static $non_code = array(
        'T_INLINE_HTML',
        'T_COMMENT',
        'T_DOC_COMMENT',
    );
    
    /**
     * @var string[] non PHP tokens
     */
    public static $html = array(
        'T_INLINE_HTML',
    );
    
    /**
     * @var string[] non PHP tokens
     */
    public static $comments = array(
        'T_COMMENT',
        'T_DOC_COMMENT',
    );
    
    /**
     * @var string[] trimming whitespaces around this tokens
     */
    public static $strip_whitespace_around = array(
        
        '__SERV', // Tokens without type
        
        'T_WHITESPACE', // /\s*/
        'T_CLOSE_TAG',
        'T_CONSTANT_ENCAPSED_STRING', // String in quotes
        
        // Equals
        'T_DIV_EQUAL',
        'T_BOOLEAN_OR',
        'T_BOOLEAN_AND',
        'T_IS_EQUAL',
        'T_IS_GREATER_OR_EQUAL',
        'T_IS_IDENTICAL',
        'T_IS_NOT_EQUAL',
        'T_IS_SMALLER_OR_EQUAL',
        'T_SPACESHIP',
        
        // Assignments
        'T_CONCAT_EQUAL',
        'T_MINUS_EQUAL',
        'T_MOD_EQUAL',
        'T_MUL_EQUAL',
        'T_AND_EQUAL',
        'T_OR_EQUAL',
        'T_PLUS_EQUAL',
        'T_POW_EQUAL',
        'T_SL_EQUAL',
        'T_SR_EQUAL',
        'T_XOR_EQUAL',
        
        // Bit
        'T_SL', // <<
        'T_SR', // >>
        
        // Uno
        'T_INC', // ++
        'T_DEC', // --
        'T_POW', // **
        
        // Cast type
        'T_ARRAY_CAST',
        'T_BOOL_CAST',
        'T_DOUBLE_CAST',
        'T_OBJECT_CAST',
        'T_STRING_CAST',
        
        // Different
        'T_START_HEREDOC', // <<<
        'T_NS_SEPARATOR', // \
        'T_ELLIPSIS', // ...
        'T_OBJECT_OPERATOR', // ->
        'T_DOUBLE_ARROW', // =>
        'T_DOUBLE_COLON', // ::
        'T_PAAMAYIM_NEKUDOTAYIM', // ::
    );
    
    /**
     * @var string[] Token types which require whitespace around them
     */
    public static $dont_trim_whitespace_around = array(
        'T_ENCAPSED_AND_WHITESPACE',
        'T_OPEN_TAG',
        'T_INCLUDE',
        'T_REQUIRE',
        'T_INCLUDE_ONCE',
        'T_REQUIRE_ONCE',
    );
    
    /**
     * @var string[] File attachment token types
     */
    public static $include = array(
        'T_INCLUDE',
        'T_REQUIRE',
        'T_INCLUDE_ONCE',
        'T_REQUIRE_ONCE',
    );
    
    /**
     * @var string[] Token types which are normally stand on a separate line
     */
    public static $one_line = array(
        'T_NAMESPACE',
        'T_CLASS',
        'T_TRAIT',
        'T_PUBLIC',
        'T_PROTECTED',
        'T_PRIVATE',
        'T_FUNCTION',
        'T_FOREACH',
        'T_FOR',
        'T_DO',
        'T_WHILE',
        'T_SWITCH',
    );
    
    public static $chr_func_val = [
        'T_LNUMBER',
        'T_CONSTANT_ENCAPSED_STRING',
    ];
    
    public static $could_be_concatenated = [
        'T_LNUMBER',
        'T_CONSTANT_ENCAPSED_STRING',
    ];
    
    public static $simple_strings = [
        'T_ENCAPSED_AND_WHITESPACE',
        'T_CONSTANT_ENCAPSED_STRING',
    ];
    
    public static $array_allowed_keys = [
        'T_LNUMBER',
        'T_CONSTANT_ENCAPSED_STRING',
    ];
    
    public static $array_allowed_values = [
        'T_LNUMBER',
        'T_CONSTANT_ENCAPSED_STRING',
    ];
}