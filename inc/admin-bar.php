<?php

/**
 * Adding parent nodes for plugins depending on installed ones
 *
 * @param WP_Admin_Bar $wp_admin_bar
 */
function spbc_admin__admin_bar__add_structure( $wp_admin_bar ) {
    
    global $spbc, $apbct;
    
    do_action( 'cleantalk_admin_bar__prepare_counters' );
    
    // Adding parent node
    $wp_admin_bar->add_node( array(
        'id'    => 'cleantalk_admin_bar__parent_node',
        'title' =>
            apply_filters('cleantalk_admin_bar__add_icon_to_parent_node', '' ) . // @deprecated
            apply_filters('cleantalk_admin_bar__parent_node__before', '' ) .
            '<span class="cleantalk_admin_bar__title">' . __('CleanTalk', 'cleantalk-spam-protect') . '</span>' .
            apply_filters('cleantalk_admin_bar__parent_node__after', '' ),
        'meta' => array( 'class' => 'cleantalk-admin_bar--list_wrapper'),
    ) );
    
    // Security
    $title = $spbc->notice_trial
        ? "<span><a href='https://cleantalk.org/my/bill/security?utm_source=wp-backend&utm_medium=cpc&utm_campaign=WP%20backend%20renew_security&user_token={$spbc->user_token}&cp_mode=security' target='_blank'>" . __( 'Renew Security', 'security-malware-firewall' ) . '</a></span>'
        : '<a>' . __( 'Security', 'security-malware-firewall' ) . '</a>';
    
    $title .= $spbc->show_notice ? '<i class="spbc-icon-attention-alt ctlk---red"></i>' : '';
    
    $wp_admin_bar->add_node( array(
        'parent' => 'cleantalk_admin_bar__parent_node',
        'id'     => 'spbc__parent_node',
        'title'  => '<div class="cleantalk-admin_bar__parent">'
                    . $title
                    . '</div>'
    ) );
    
    // Anti-Spam
    // Install link
    if( ! $apbct ){
        $apbct_title = '<a>' . __( 'Anti-Spam', 'cleantalk-spam-protect'  ) . '</a>';
    }elseif( $apbct->admin_bar_enabled ){
        $apbct_title = $apbct->notice_trial == 1
            ? "<span><a class='ctlk---red' href='https://cleantalk.org/my/bill/recharge?utm_source=wp-backend&utm_medium=cpc&utm_campaign=WP%20backend%20trial&user_token={$apbct->user_token}&cp_mode=antispam' target='_blank'>" . __('Renew Anti-Spam', 'cleantalk-spam-protect') . '</a></span>'
            : '<a>' . __( 'Anti-Spam', 'cleantalk-spam-protect'  ) . '</a>';
    }
    
    if( isset( $apbct_title ) ){
        $wp_admin_bar->add_node( array(
            'parent' => 'cleantalk_admin_bar__parent_node',
            'id'     => 'apbct__parent_node',
            'title'  => '<div class="cleantalk-admin_bar__parent">'
                        . $apbct_title
                        . '</div>'
        ) );
    }
}

/**
 * Prepares properties for counters in $apbct
 * Handles counter reset
 *
 * @return void
 */
function spbc_admin__admin_bar__prepare_counters(){
    
    global $spbc;
    
    $spbc->counter__sum = 0;
    
    if( $spbc->settings['admin_bar__users_online_counter'] ){
        $spbc->online_users = spbc_get_authorized_users( true );
        $spbc->counter__users_online = count( $spbc->online_users );
        $spbc->counter__sum += $spbc->counter__users_online;
    }
    if( $spbc->settings['admin_bar__firewall_counter'] ){
        $spbc->counter__firewall_pass = \CleantalkSP\SpbctWP\Counters\FirewallCounter::get( 'pass' );
        $spbc->counter__firewall_deny = \CleantalkSP\SpbctWP\Counters\FirewallCounter::get( 'deny' );
        $spbc->counter__sum += $spbc->counter__firewall_pass + $spbc->counter__firewall_deny;
    }
    if( $spbc->settings['admin_bar__brute_force_counter'] ){
        $spbc->counter__logins_failed = \CleantalkSP\SpbctWP\Counters\SecurityCounter::get( 'auth_failed' );
        $spbc->counter__logins_passed = \CleantalkSP\SpbctWP\Counters\SecurityCounter::get( 'login' );
        $spbc->counter__sum += $spbc->counter__logins_failed + $spbc->counter__logins_passed;
    }
}

function spbc_admin__admin_bar__add_parent_icon( $icon ){
    
    return $icon
           . '<img class="cleantalk_admin_bar__spbc_icon" src="' . SPBC_PATH . '/images/logo_small_gray.png" alt="">&nbsp;';
}

function spbc_admin__admin_bar__add_counter( $after ){
    
    global $spbc;

	$admins_online = $spbc->settings['admin_bar__users_online_counter']
		? ' / <span title="' . __( 'Admins online', 'security-malware-firewall' ) . '">' . $spbc->counter__users_online . '</span>'
		: '';
    
    $counter__sum__layout = ( $after ? ' / ' : '<div class="cleantalk_admin_bar__sum_counter">' )
        . '<span title="' . __('All security events', 'security-malware-firewall') . '">' . ( $spbc->counter__sum - $spbc->counter__users_online ) . '</span>'
        . $admins_online
    . '</div>';
    
    return ( $after ? substr( $after, 0, -6 ) : $after )
           . $counter__sum__layout;
}

function spbc_admin__admin_bar__add_child_nodes( $wp_admin_bar ){
    
    global $spbc;
    
    $attention_mark = $spbc->show_notice ? '<i class="spbc-icon-attention-alt ctlk---red"></i>' : '';
    
    // Counter header
    if( $spbc->counter__sum ){
        $wp_admin_bar->add_node( array(
            'parent' => 'spbc__parent_node',
            'id'     => 'spbc_admin_bar__counter_header',
            'title'  => __( 'Counters:', 'security-malware-firewall' ),
        ) );
    }
    
    // Failed / success login attempts counter
    if( $spbc->settings['admin_bar__brute_force_counter'] ){
        $wp_admin_bar->add_node( array(
            'parent' => 'spbc__parent_node',
            'id'     => 'spbc_admin_bar__counter__logins',
            'meta' => array( 'class' => 'cleantalk_admin_bar__counter'),
            'title'  => '<a>'
                . '<span>' . __('Logins:', 'security-malware-firewall') . '</span>&nbsp;'
                . '<span style="color: white;">'
                    . '<b style="color: green;">' . $spbc->counter__logins_passed . '</b> / '
                    . '<b style="color: red;">' . $spbc->counter__logins_failed . '</b>'
                . '</span>'
                . '<i class="spbc-icon-help-circled" title="' . __('Blocked login attempts in the local database for the past 24 hours.', 'security-malware-firewall') . '"></i>'
            . '</a>',
        ) );
    }
    
    // Firewall blocked / allowed counter
    if( $spbc->settings['admin_bar__firewall_counter'] ){
        $wp_admin_bar->add_node( array(
            'parent' => 'spbc__parent_node',
            'id'     => 'spbc_admin_bar__counter__firewall',
            'meta' => array( 'class' => 'cleantalk_admin_bar__counter'),
            'title'  => '<a>'
                .'<b>' .__( 'Security Firewall: ', 'security-malware-firewall' ) .'</b>&nbsp;'
                . '<b style="color: white;">'
                    . '<b style="color: green;">' . $spbc->counter__firewall_pass . '</b> / '
                    . '<b style="color: red;">' . $spbc->counter__firewall_deny . '</b>'
                . '</b>'
                . '<i class="spbc-icon-help-circled" title="'.__('Passed / Blocked requests by Security Firewall for the past 24 hours.', 'security-malware-firewall').'"></i>'
            . '</a>',
        ) );
    }
    
    // Users online counter
    if( $spbc->settings['admin_bar__users_online_counter'] ){
        $wp_admin_bar->add_node( array(
            'parent' => 'spbc__parent_node',
            'id'     => 'spbc_admin_bar__counter__online',
            'meta' => array( 'class' => 'cleantalk_admin_bar__elem cleantalk_admin_bar__counter'),
            'title'  => '<a>'
                . '<span>' . __( 'Admins online:', 'security-malware-firewall' ) . '</span>'
                . '&nbsp;<b class="spbc-admin_bar--user_counter">' . $spbc->counter__users_online . '</b>'
                . '<i class="spbc-icon-help-circled" title="' . __( 'Shows amount of currently logged in administrators. Updates every 10 seconds.', 'security-malware-firewall' ) .'"></i>'
            . '</a>',
        ) );
        
        if( $spbc->counter__users_online <=3 ){
            $wp_admin_bar->add_node( array(
                'parent' => 'spbc__parent_node',
                'id'     => 'spbc_admin_bar__online_users',
                'meta' => array( 'class' => 'spbc---gray'),
                'title'  => '<a href="options-general.php?page=spbc&spbc_tab=security_log">'
                    . '<b style="margin-left: 5px;" class="spbc-admin_bar--online_users">'
                        . implode( ', ', $spbc->online_users )
                    . '</b>'
                . '</a>',
            ) );
        }
    }
    
    // Counter separator
    if( $spbc->counter__sum ){
        $wp_admin_bar->add_node( array(
            'parent' => 'spbc__parent_node',
            'id'     => 'spbc_admin_bar__separator',
            'title'  =>'<hr style="margin-top: 7px;" />',
            'meta' => array( 'class' => 'cleantalk_admin_bar__separator')
        ) );
    }
    
    // Settings
    $wp_admin_bar->add_node( array(
        'parent' => 'spbc__parent_node',
        'id'     => 'spbc_admin_bar__settings_link',
        'title'  => '<a href="' . $spbc->settings_link . '&spbc_tab=settings_general">' . __( 'Settings', 'security-malware-firewall' ) . '</a>' . $attention_mark,
    ) );
    
    // Scanner
    $wp_admin_bar->add_node( array(
        'parent' => 'spbc__parent_node',
        'id'     => 'spbc_admin_bar__scanner_link',
        'title'  => '<a style="display:inline" href="' . $spbc->settings_link . '&spbc_tab=scanner">' . __( 'Scanner', 'cleantalk-spam-protect' ) . '</a>'
                    . '/'
                    . '<a style="display:inline" href="' . $spbc->settings_link . '&spbc_tab=scanner&spbc_target=spbc_perform_scan&spbc_action=click">' . __( 'Start scan', 'security-malware-firewall' ) . '</a>'
    ) );
    
    // Support link
    $wp_admin_bar->add_node( array(
        'parent' => 'spbc__parent_node',
        'title'  => '<hr style="margin-top: 7px;" /><a target="_blank" href="https://wordpress.org/support/plugin/security-malware-firewall">' . __( 'Support', 'security-malware-firewall' ) . '</a>',
        'id'     => 'spbc_admin_bar__support_link',
    ) );
}

function spbc_apbct_admin__admin_bar__add_child_nodes( $wp_admin_bar ) {
    
    // Installation link
    $wp_admin_bar->add_node( array(
        'parent' => 'apbct__parent_node',
        'id'	 => 'apbct_admin_bar__install',
        'title'  => '<a target="_blank" href="plugin-install.php?s=Spam%20protection%2C%20AntiSpam%20by%20CleanTalk%20&tab=search">' . __( 'Install Anti-Spam by CleanTalk', 'security-malware-firewall' ) . '</a>',
    ) );
    
    $wp_admin_bar->add_node( array(
        'parent' => 'apbct__parent_node',
        'id'     => 'install_separator',
        'title'  =>'<hr style="margin-top: 7px;" />',
        'meta' => array( 'class' => 'cleantalk_admin_bar__separator' )
    ) );
    
    // Counter header
    $wp_admin_bar->add_node( array(
        'parent' => 'apbct__parent_node',
        'id'     => 'apbct_admin_bar__counter_header',
        'title'  => '<a>' . __( 'Counters:', 'security-malware-firewall' ) . '</a>',
        'meta' => array( 'class' => 'cleantalk_admin_bar__blocked' ),
    ) );
    
    // User's counter
    $wp_admin_bar->add_node( array(
        'parent' => 'apbct__parent_node',
        'id'	 => 'apbct_admin_bar__counter__user',
        'title'  => '<a>' . __('Since', 'security-malware-firewall') . '&nbsp;' . date('M d') . ': '
            . '<span style="color: green;">' . 0 . '</span> / '
            . '<span style="color: red;">' . 0 . '</span>'
            . '<i class="spbc-icon-help-circled" title="'
                . __( 'Shows amount of allowed and blocked requests since the date.', 'security-malware-firewall' ) . '"></i>'
        . '</a>',
        'meta' => array( 'class' => 'cleantalk_admin_bar__blocked' ),
    ) );
    
    // All-time counter
    $wp_admin_bar->add_node( array(
        'parent' => 'apbct__parent_node',
        'id'     => 'apbct_admin_bar__counter__all_time',
        'title'  =>'<a>'
            . '<span>'
                . __('Since activation', 'security-malware-firewall') .  ': '
                . '<span style="color: white;">' . 0 . '</span> / '
                . '<span style="color: green;">' . 0 . '</span> / '
                . '<span style="color: red;">' . 0 . '</span>'
            . '</span>'
            . '<i class="spbc-icon-help-circled" title="'
                . __('All / Allowed / Blocked submissions. The number of submissions is being counted since CleanTalk plugin installation.', 'security-malware-firewall').'"></i>'
        . '</a>',
        'meta' => array( 'class' => 'cleantalk_admin_bar__blocked' ),
    ) );
    
    // Daily counter
    $wp_admin_bar->add_node( array(
        'parent' => 'apbct__parent_node',
        'id'	 => 'apbct_admin_bar__counter__daily',
        'title'  =>'<a>'
            . '<span>'
                . __('Daily', 'security-malware-firewall') . ': '
                . '<span style="color: green;">' . 0 . '</span> / '
                . '<span style="color: red;">' . 0 . '</span>'
            . '</span>'
            . '<i class="spbc-icon-help-circled" title="'
                . __('Allowed / Blocked submissions. The number of submissions for the past 24 hours. ', 'security-malware-firewall').'"></i>'
        . '</a>',
        'meta' => array( 'class' => 'cleantalk_admin_bar__blocked' ),
    ) );
    
    // SFW counter
    $wp_admin_bar->add_node( array(
        'parent' => 'apbct__parent_node',
        'id'	 => 'apbct_admin_bar__counter__sfw',
        'title'  =>'<a>'
            . '<span>'
                . __('SpamFireWall', 'security-malware-firewall' ) . ': '
                . '<span style="color: white;">'. 0 . '</span> / '
                . '<span style="color: red;">' . 0 . '</span>'
            . '</span>'
            . '<i class="spbc-icon-help-circled" title="'
                . __('All / Blocked events. Access attempts triggered by SpamFireWall counted since the last plugin activation.', 'security-malware-firewall').'"></i>'
            . '</a>',
        'meta' => array( 'class' => 'cleantalk_admin_bar__blocked' ),
    ) );
    
    // User counter reset.
    $wp_admin_bar->add_node( array(
        'parent' => 'apbct__parent_node',
        'id'	 => 'ct_reset_counter',
        'title'  => '<hr style="margin-top: 7px;"><a>'.__('Reset first counter', 'security-malware-firewall').'</a>',
        'meta' => array( 'class' => 'cleantalk_admin_bar__blocked' ),
    ) );
    
    // Reset ALL counter
    $wp_admin_bar->add_node( array(
        'parent' => 'apbct__parent_node',
        'id'	 => 'ct_reset_counters_all',
        'title'  => '<a>'.__('Reset all counters', 'security-malware-firewall').'</a>',
        'meta' => array( 'class' => 'cleantalk_admin_bar__blocked' ),
    ) );
    
    // Counter separator
    $wp_admin_bar->add_node( array(
        'parent' => 'apbct__parent_node',
        'id'     => 'apbct_admin_bar__separator',
        'title'  =>'<hr style="margin-top: 7px;" />',
        'meta' => array( 'class' => 'cleantalk_admin_bar__separator')
    ) );
    
    $wp_admin_bar->add_node( array(
        'parent' => 'apbct__parent_node',
        'id'	 => 'ct_settings_link',
        'title'  => '<a>'.__('Settings').'</a>',
        'meta' => array( 'class' => 'cleantalk_admin_bar__blocked' ),
    ));
    
    // Add a child item to our parent item. Bulk checks.
    $wp_admin_bar->add_node( array(
        'parent' => 'apbct__parent_node',
        'id'	 => 'ct_settings_bulk_comments',
        'title'  => '<hr style="margin-top: 7px;" /><a>'.__('Bulk spam comments removal tool.', 'security-malware-firewall') . ' ' . __('Check comments for spam', 'security-malware-firewall').'</a>',
        'meta' => array( 'class' => 'cleantalk_admin_bar__blocked' ),
    ) );
    
    // Add a child item to our parent item. Bulk checks.
    $wp_admin_bar->add_node( array(
        'parent' => 'apbct__parent_node',
        'id'	 => 'ct_settings_bulk_users',
        'title'  => '<a>'.__('Check users for spam', 'security-malware-firewall').'</a>',
        'meta' => array( 'class' => 'cleantalk_admin_bar__blocked' ),
    ) );
    
    // Support link
    $wp_admin_bar->add_node( array(
        'parent' => 'apbct__parent_node',
        'id'	 => 'ct_admin_bar_support_link',
        'title'  => '<hr style="margin-top: 7px;" /><a>'.__('Support', 'security-malware-firewall').'</a>',
        'meta' => array( 'class' => 'cleantalk_admin_bar__blocked' ),
    ));
}
