<?php

namespace CleantalkSP\SpbctWP\Scanner\ScanningLog;

class Template
{
    public static function render($data)
    {
        global $spbc;
        $template = '<div id="spbcscan-results-log-module">';
        $template .= '<div class="panel-body">';

        $prev_item_content = '';
        foreach ( $data as $item ) {
            if ($prev_item_content === $item['content']) {
                continue;
            }
            $template .= '<p class="spbc_log-line">'
                         . date("M d Y H:i:s", $item['timestamp'] + $spbc->data['site_utc_offset_in_seconds'])
                         . ' '
                         . $item['content']
                         . '</p>';
            $prev_item_content = $item['content'];
        }

        $template .= '</div>';
        $template .= '</div>';

        echo $template;
    }
}
