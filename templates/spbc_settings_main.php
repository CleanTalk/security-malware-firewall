<?php
    $t_last_attacks_tpl = <<<EOT
<div class="spbc_table_general">
<table border="0" class="spbc_table_general">
    <tr>
        <th>
           Date and time 
        </th>
        <th>
            User
        </th>
        <th>
            Action 
        </th>
		<th>
            Page 
        </th>
		<th>
            Time on page, sec
        </th>
        <th>
            IP, Country
        </th>
    </tr>
    %s
</table>
</div>
EOT;

    $row_last_attacks_tpl = <<<EOT
    <tr>
        <td>
            %s 
        </td>
        <td>
            %s 
        </td>
        <td>
            %s 
        </td>
		<td>
            %s 
        </td>
        <td>
            %s 
        </td>
        <td>
            %s 
        </td>
    </tr>

EOT;


$spbc_rate_plugin_tpl = <<<EOT
<div class="spbc_rate_plugin">
    <div class="spbc_rate_block">
        <p>Tell other users about your experience with %s.</p>
        <p>Write your review on WordPress.org</p>
        <div>
            <a class="spbc_button_rate" href="https://wordpress.org/support/plugin/security-malware-firewall/reviews/?filter=5" target="_blank">RATE IT NOW</a>
        </div>
        <div class="spbc_rate_block_stars">
<span class="star-icon full">☆</span>
<span class="star-icon full">☆</span>
<span class="star-icon full">☆</span>
<span class="star-icon full">☆</span>
<span class="star-icon full">☆</span>
        </div>
    </div>
</div>
EOT;


$spbc_tpl = array_merge($spbc_tpl, array(
    't_last_attacks_tpl' => $t_last_attacks_tpl,
    'row_last_attacks_tpl' => $row_last_attacks_tpl,
    'spbc_rate_plugin_tpl' => $spbc_rate_plugin_tpl,
));


?>
