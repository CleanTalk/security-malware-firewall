<?php

$spbc_rate_plugin_tpl = '
<div class="spbc_settings_banner" id="spbc_rate_plugin">
    <div class="spbc_rate_block">
        <p>'.__('Tell other users about your experience with %s.', 'security-malware-firewall').'</p>
        <p>'.__('Write your review on WordPress.org', 'security-malware-firewall').'</p>
        <div>
            <a class="spbc_button_rate" href="https://wordpress.org/support/plugin/security-malware-firewall/reviews/?filter=5" target="_blank">'.__('RATE IT NOW', 'security-malware-firewall').'</a>
        </div>
        <div class="spbc_rate_block_stars">
			<span class="star-icon full">☆</span>
			<span class="star-icon full">☆</span>
			<span class="star-icon full">☆</span>
			<span class="star-icon full">☆</span>
			<span class="star-icon full">☆</span>
        </div>
    </div>
</div>';

$spbc_translate_banner_tpl = '
<div class="spbc_settings_banner" id="spbc_translate_plugin">
    <div class="spbc_rate_block">
        <p>'.__('Help others use the plugin in your language.', 'security-malware-firewall').'</p>
        <p>'.__('We ask you to help with the translation of the plugin in your language. Please take a few minutes to make the plugin more comfortable.', 'security-malware-firewall').'</p>
        <div>
            <a class="spbc_button_rate" href="https://translate.wordpress.org/locale/%s/default/wp-plugins/security-malware-firewall" target="_blank">'.__('TRANSLATE', 'security-malware-firewall').'</a>
        </div>
    </div>
</div>';

$spbc_tpl = array(
    'spbc_rate_plugin_tpl' => $spbc_rate_plugin_tpl,
	'spbc_translate_banner_tpl' => $spbc_translate_banner_tpl,
);
