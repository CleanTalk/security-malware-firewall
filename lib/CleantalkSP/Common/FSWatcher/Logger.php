<?php

namespace CleantalkSP\Common\FSWatcher;

class Logger
{
    private static $logger_dir = __DIR__ . DIRECTORY_SEPARATOR . 'logs';

    /**
     * @var string
     */
    private static $salt = '';

    private static function getCurrentDayLogPath()
    {
        $path = self::getLoggerDir();
        return $path
            ? $path . DIRECTORY_SEPARATOR . date('Y-m-d') . static::generateLogHash() . '.log'
            : false;
    }

    private static function setLoggerDir()
    {
        $result = (
            mkdir(self::$logger_dir) &&
            file_put_contents(self::$logger_dir . DIRECTORY_SEPARATOR . 'index.php', '<?php //Silence is golden')
        );
        return $result;
    }

    private static function getLoggerDir()
    {
        if ( !is_dir(self::$logger_dir) ) {
            if ( !self::setLoggerDir() ) {
                return false;
            }
        }
        return self::$logger_dir;
    }

    public static function log($msg)
    {
        $current_day_log_path = self::getCurrentDayLogPath();

        if ( !$current_day_log_path ) {
            error_log('Cant write log.');
            return;
        }

        $message = '[' . date('H:i:s') . ']' . ' ';

        $message .= debug_backtrace()[1]['class']
            . debug_backtrace()[1]['type']
            . debug_backtrace()[1]['function']
            . PHP_EOL;

        if (is_string($msg)) {
            $message .= $msg . PHP_EOL;
        }

        if (is_array($msg)) {
            foreach ($msg as $key => $value) {
                $message .= $key . ': ' . $value . PHP_EOL;
            }
        }

        error_log($message, 3, $current_day_log_path);
    }

    protected static function generateLogHash()
    {
        return md5(filemtime(__FILE__) . static::$salt);
    }

    /**
     * Store the salt value to the class property
     * The $salt must be used obligatorily
     *
     * @param $salt
     */
    public static function setSaltValue($salt = '')
    {
        static::$salt = (string) $salt;
    }
}
