<?php

namespace CleantalkSP\SpbctWP\Scanner\ScanningLog;

class ScanningLogFacade
{
    public static function writeToLog($content)
    {
        return Repository::write($content);
    }

    public static function clearLog()
    {
        return Repository::clear();
    }

    public static function render()
    {
        $data = Repository::getAll();
        if (!empty($data)) {
            Template::render($data);
        }
    }
}
