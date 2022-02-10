<?php


namespace CleantalkSP\SpbctWP;


class Transaction extends \CleantalkSP\Common\Transaction
{
    protected function setOption($option_name, $value)
    {
        return update_option($option_name, $value, false);
    }
    
    protected function getOption($option_name, $default)
    {
        return get_option($option_name, $default);
    }
}