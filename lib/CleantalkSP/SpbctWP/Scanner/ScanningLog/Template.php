<?php

namespace CleantalkSP\SpbctWP\Scanner\ScanningLog;

class Template
{
    public static function render($data)
    {
        global $spbc;
        $template = '<div id="spbcscan-results-log-module">';
        $template .= '<div class="panel-body">';

        foreach ( $data as $item ) {
            $template .= '<p class="spbc_log-line">'
                         . date("M d Y H:i:s", $item['timestamp'] + $spbc->data['site_utc_offset_in_seconds'])
                         . ' '
                         . $item['content']
                         . '</p>';
        }

        $template .= '</div>';
        $template .= '</div>';

        echo $template;
    }
}
