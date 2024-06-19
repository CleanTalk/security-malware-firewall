<?php

namespace CleantalkSP\SpbctWP\Firewall;

class FirewallState
{
    public static $is_need_to_increment_entire = true;

    public static $is_admin = false;

    public static function setIsNeedToIncrementEntire($value)
    {
        self::$is_need_to_increment_entire = $value;
    }

    public static function setIsAdmin($value)
    {
        self::$is_admin = $value;
    }
}
