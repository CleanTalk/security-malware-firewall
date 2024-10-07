<?php

use CleantalkSP\SpbctWP\Counters\SecurityCounter;
use CleantalkSP\SpbctWP\G2FA\GoogleAuthenticator;
use CleantalkSP\SpbctWP\Variables\Cookie;
use CleantalkSP\SpbctWP\Helpers\IP;
use CleantalkSP\Variables\Get;
use CleantalkSP\Variables\Server;
use CleantalkSP\SpbctWP\LinkConstructor;

add_filter('authenticate', 'spbc_authenticate', 20, 3); // Hooks for authentificate
add_action('login_errors', 'spbc_fix_error_messages', 99999); // Filters error message
add_action('wp_logout', 'spbc_wp_logout', 1);     // Hooks for authentificate
add_action('login_footer', 'spbc_login_form_notification', 1);

add_filter('manage_users_columns', 'spbc_user_last_login_column');
add_filter('manage_users-network_columns', 'spbc_user_last_login_column');
add_filter('manage_users_custom_column', 'spbc_user_last_login_column_content', 10, 3);

if ( isset($spbc) && ($spbc instanceof \CleantalkSP\SpbctWP\State ) && $spbc->settings['2fa__enable'] ) {
    if (Server::inUri('wp-login.php') && !empty($_POST)) {
        add_action('init', 'spbc_2fa_rate_limit', 10, 1);
    }
    add_action('login_form_login', 'spbc_2fa__authenticate', 1);     // Authenticate with Code
    add_action('login_form', 'spbc_2fa__show_field', 10);
    add_action('after_password_reset', 'spbc_2fa__Google2fa_replace_meta', 10, 1);
    // Profile page hook
    add_action('show_user_profile', 'spbc_2fa__SelfUserProfileEdit', 1);
    add_action('edit_user_profile', 'spbc_2fa__SelfUserProfileEdit', 1);
    // G2FA actions
    add_action('wp_ajax_spbc_get_google_qr_code', 'spbc_2fa__GetGoogleQrCode');
    add_action('wp_ajax_spbc_check_google_code', 'spbc_2fa__CheckGoogleCode');
    add_action('wp_ajax_spbc_disable_google_2fa', 'spbc_2fa__DisableGoogle2fa');
}

/**
 * Disable G2FA after password resetting
 *
 * @param \WP_User $user
 *
 * return void
 */
function spbc_2fa__Google2fa_replace_meta(\WP_User $user)
{
    return delete_user_meta($user->ID, 'spbc_2fa_type') && delete_user_meta($user->ID, 'spbc_g2fa_token');
}

/**
 * Adding notification to registration form
 *
 * @return null
 */
function spbc_login_form_notification()
{
    global $spbc;

    //Return if it's not a registration page.
    $login_url = rtrim(wp_login_url(), '/');
    $server_url = rtrim(Server::getURL(), '/');
    if ( empty(Server::get('REQUEST_SCHEME')) ) {
        $login_url = preg_replace('/https?/', '', $login_url);
        $server_url = preg_replace('/https?/', '', $server_url);
    }
    if ( strpos($server_url, $login_url) === 0 && Get::get('action') !== 'register' ) {
        $show_notification = ( ! empty($spbc->settings['misc__show_link_in_login_form']) ? true : false );
        if ( $show_notification ) {
            $link = $spbc->settings['spbc_trusted_and_affiliate__footer']
                ? spbc_generate_affiliate_link()
                : "<a rel='nofollow' href='https://wordpress.org/plugins/security-malware-firewall/' target='_blank'>" . $spbc->data["wl_brandname"] . "</a>";

            // @ToDo this section need to be refactored
            $link = ! $spbc->data["wl_mode_enabled"] ? $link : $spbc->data["wl_brandname"];
            $logo_img = $spbc->data["wl_mode_enabled"] ? "" : "<img style='vertical-align: bottom; width: 12px; height: 15px;' src='" . SPBC_PATH . "/images/logo_small.png'>";
            echo "<div style='position: relative; right: 20px;'>"
                 . "<p style='text-align: right;'>"
                 . __('Brute Force Protection by', 'security-malware-firewall')
                 . "&nbsp;"
                 . $logo_img
                 . $link
                 . ".</p>"
                 . "<p style='text-align: right;'>" . __('All attempts are logged.', 'security-malware-firewall') . "</p>
			</div>";
        }
    }

    return null;
}

/**
 * Authentificate handler
 *
 * @param WP_User|WP_Error $user
 * @param string           $username
 *
 * @return WP_Error|WP_User
 */
function spbc_authenticate($user, $username)
{
    global $spbc;

    if ( is_wp_error($user) ) {
        spbc_authenticate__check_brute_force();

        $spbc->login_error = true;

        $err_codes = $user->get_error_codes();

        // Passwords brute force
        if ( in_array('incorrect_password', $err_codes, true) ) {
            do_action('spbc_log_wrong_auth');

            spbc_auth_log(
                array(
                'username' => $username,
                'event'    => 'invalid_password',
                )
            );
        }

        // Usernames brute force.
        if ( in_array('invalid_username', $err_codes, true) ) {
            do_action('spbc_log_wrong_auth');

            spbc_auth_log(
                array(
                'username' => $username,
                'event'    => 'invalid_username',
                )
            );
        }

        // Emails brute force.
        if ( in_array('invalid_email', $err_codes, true) ) {
            do_action('spbc_log_wrong_auth');

            spbc_auth_log(
                array(
                'username' => $username,
                'event'    => 'invalid_email',
                )
            );
        }
    }

    // The user is logged in.
    if ( $user instanceof WP_User && $user->ID > 0 ) {
        // Skip for ZAPIER
        if (
            spbc_is_plugin_active('zapier/zapier.php') &&
            Server::get('REQUEST_URI') === '/wp-json/zapier/v1/token'
        ) {
            spbc_authenticate__write_log_login($user);
            return $user;
        }

        // Redirect if 2fa is enabled
        if ( (
                $spbc->settings['2fa__enable'] == 1 &&
                spbc_is_user_role_in($spbc->settings['2fa__roles'], $user)
             ) ||
            (
                $spbc->settings['2fa__enable'] == - 1 &&
                spbc_is_user_role_in($spbc->settings['2fa__roles'], $user) &&
                spbc_authenticate__is_new_device($user)
        ) ) {
            $type2fa = get_user_meta($user->ID, 'spbc_2fa_type', true);
            if ( $type2fa !== 'google_authenticator' ) {
                spbc_2fa__send_mail($user);
            }
            wp_redirect(
                wp_login_url()
                . ( strpos(wp_login_url(), '?') === false ? '?' : '&' )
                . 'spbc_2fa_user=' . rawurlencode($user->user_login)
            );
            die();
        }

        spbc_authenticate__write_log_login($user);

        // Sends logs to get notify about superuser login.
        $result = spbc_send_logs();
        if ( empty($result['error']) ) {
            $spbc->error_delete('send_logs');
            $spbc->data['logs_last_sent']         = current_time('timestamp');
            $spbc->data['last_sent_events_count'] = $result;
            $spbc->save('data');
        } else {
            $spbc->error_add('send_logs', $result);
        }
        if (spbc_authenticate__is_new_device($user)) {
            spbc_authenticate__browser_sign__set($user);
        }
        spbc_authenticate__user_agent__set($user);
    }

    return $user;
}

/**
 * Detecting new device
 *
 * @param WP_User|WP_Error $user
 *
 * @return bool
 */
function spbc_authenticate__is_new_device($user)
{
    $browser_sign__collection = spbc_authenticate__browser_sign__get($user);
    $browser_sign = spbc_authenticate__browser_sign__create();

    return !in_array($browser_sign, $browser_sign__collection);
}

/**
 * Writes log about login
 *
 * @param WP_User $user
 *
 * @return void
 */
function spbc_authenticate__write_log_login($user)
{
    $role = null;
    if ( ! empty($user->roles) && is_array($user->roles) ) {
        $roles = $user->roles;
        $role = reset($roles);
    }

    update_user_meta($user->ID, '_spbc_last_login', time());

    spbc_auth_log(
        array(
            'username'     => $user->user_login,
            'event'        => spbc_authenticate__is_new_device($user) ? 'login_new_device' : 'login',
            'roles'        => $role,
            'user_agent'   => filter_input(INPUT_SERVER, 'HTTP_USER_AGENT'),
            'browser_sign' => spbc_authenticate__browser_sign__get_hash($user),
        )
    );
}

/**
 * Returns browser sign
 *
 * @return string
 */
function spbc_authenticate__browser_sign__create()
{
    $sign = filter_input(INPUT_SERVER, 'HTTP_USER_AGENT');
    $regexp = '#(Firefox|Chrome|Safari|Edge|Edg|Version)\/(\d+\.?)+#';
    $sign = preg_replace_callback(
        $regexp,
        function ($matches) {
            $replaces = preg_replace('#\/(\d+\.?)+#', '', $matches[0]);
            return !is_string($replaces) ? '' : $replaces;
        },
        $sign
    );

    return md5($sign);
}

/**
 * Set browser sign of user
 *
 * @param WP_User $user
 */
function spbc_authenticate__browser_sign__set($user)
{
    $browser_sign = spbc_authenticate__browser_sign__create();

    $old_sign = spbc_authenticate__browser_sign__get($user);
    if ( is_array($old_sign) ) {
        if ( count($old_sign) >= 3 ) {
            array_shift($old_sign);
        }
        $old_sign[] = $browser_sign;
        $browser_sign = $old_sign;
    } else {
        $browser_sign = array($browser_sign);
    }
    update_user_meta($user->ID, 'spbc_browser_sign', $browser_sign);
    update_user_meta($user->ID, 'spbc_browser_sign__updated', time());
}

/**
 * Gets browser sign of user
 *
 * @param $user
 *
 * @return bool|array Browser sign
 */
function spbc_authenticate__browser_sign__get($user)
{
    $sign = get_user_meta($user->ID, 'spbc_browser_sign', true);
    return is_array($sign) ? $sign : array($sign);
}

/**
 * Gets browser collection hash
 *
 * @param $user
 *
 * @return string Browser sign
 */
function spbc_authenticate__browser_sign__get_hash($user)
{
    $sign_collection = get_user_meta($user->ID, 'spbc_browser_sign', true);

    if (is_scalar($sign_collection)) {
        return (string)$sign_collection;
    }

    if (is_array($sign_collection)) {
        $sign = implode('', $sign_collection);
        return md5($sign);
    }

    return '';
}


/**
 * Set browser sign of user
 *
 * @param WP_User $user
 * @param string  $browser_sign Browser sign
 */
function spbc_authenticate__user_agent__set($user)
{
    update_user_meta($user->ID, 'spbc_user_agent', filter_input(INPUT_SERVER, 'HTTP_USER_AGENT'));
}

/**
 * Gets last user agent
 *
 * @param $user
 *
 * @return bool|string Browser sign and update time
 */
function spbc_authenticate__user_agent__get($user)
{
    return get_user_meta($user->ID, 'spbc_user_agent', true);
}

/**
 * Sends email with code
 */
function spbc_2fa__send_mail($user)
{
    global $spbc;

    spbc_2fa__key_remove_old();

    if ( isset($spbc->data['2fa_keys'][ $user->user_login ]) && $spbc->data['2fa_keys'][ $user->user_login ]['generated'] > time() - SPBC_2FA_KEY_TTL ) {
        // Set existing code if exists.
        $key = $spbc->data['2fa_keys'][ $user->user_login ]['val'];
    } else {
        // Set new code if no code spotted
        $key = spbc_2fa__key_generate_and_store($user);
    }

    $brand_name = $spbc->data['wl_brandname'];
    $support_link = $spbc->data['wl_support_url'];
    $code_lifetime = round(SPBC_2FA_KEY_TTL / 60, 0, PHP_ROUND_HALF_DOWN);

    wp_mail(
        $user->user_email,
        // Subject
        sprintf(
            __(esc_html__($brand_name) . ' confirmation code "%s"', 'security-malware-firewall'),
            parse_url(get_option('home'), PHP_URL_HOST)
        ),
        // Message
        sprintf(
            __('Two factor authentication code for user "%s" on "%s" website is %d' . PHP_EOL . 'Lifetime of the code is %d minutes.' . PHP_EOL . PHP_EOL . esc_html__($brand_name) . ' ' . esc_url($support_link), 'security-malware-firewall'),
            $user->user_login,
            parse_url(get_option('home'), PHP_URL_HOST),
            $key,
            $code_lifetime
        )
    );

    return $user;
}

/**
 * Show form for 2fa
 */
function spbc_2fa__show_field()
{
    global $spbc;

    spbc_2fa__key_remove_old();

    if ( $spbc->settings['2fa__enable'] ) {
        if ( isset($_GET['spbc_2fa_user']) ) {
            $user_name = rawurldecode($_GET['spbc_2fa_user']);
            $user      = spbc_get_user_by('login', $user_name);

            if ( ! $user ) {
                return;
            }

            // Recombining form to show only code input
            $label       = $spbc->data["wl_brandname"] . __(' authorization code');
            $description = __('Please, check your email to get code. If you have not received the e-mail, please, check "spam" folder.', 'security-malware-firewall');
            $err_text    = __('Please, check your e-mail to gain pass code', 'security-malware-firewall');

            $type2fa = get_user_meta($user->ID, 'spbc_2fa_type', true);

            if ( $type2fa === 'google_authenticator' ) {
                $label       = __('Google Authenticator authorization code');
                $description = __('Please, check your Google Authenticator to get code.', 'security-malware-firewall');
                $err_text    = __('Please, check your Google Authenticator to gain pass code', 'security-malware-firewall');
            }

            // Error displaying
            if ( isset($_GET['spbc_2fa_error']) ) {
                echo '<script>'
                     . 'var spbc_err = document.createElement("div");'
                     . 'spbc_err.innerHTML = \'<div id="login_error">'
                     . '<strong>' . __('WRONG CODE: ', 'security-malware-firewall') . '</strong>'
                     . $err_text . '\';'
                     . 'document.getElementById("login").insertBefore(spbc_err, document.getElementById("login").children[1]);'
                     . '</script>';
            }

            // Recombining form to show only code input
            if ( spbc_is_user_role_in($spbc->settings['2fa__roles'], $user_name)
                && ( isset($spbc->data['2fa_keys'][ $user_name ]) || $type2fa === 'google_authenticator' )
            ) {
                $tech_support_url = $spbc->default_settings['edit_tech_support_url__link_default'];
                if (
                    $spbc->storage['settings']['edit_tech_support_url__enabled'] &&
                    $spbc->storage['settings']['edit_tech_support_url__link']
                ) {
                    $tech_support_url =
                        LinkConstructor::buildSimpleLink(
                            get_home_url(),
                            $spbc->storage['settings']['edit_tech_support_url__link']
                        );
                }

                if (
                    $spbc->storage['settings']['edit_tech_support_url__enabled'] &&
                    $spbc->storage['settings']['edit_tech_support_url__remove']
                ) {
                    $tech_support_url = '';
                }

                if ( $tech_support_url ) {
                    $tech_support_url = '<a href="' . esc_url($tech_support_url) . '" target="_blank">tech support</a>';
                } else {
                    $tech_support_url = 'tech support';
                }
                $replacement =
                    '<h3 style="text-align: center;margin: 0 0 10px 0;">' . $spbc->data["wl_brandname"] . '</h3>'
                    . '<p id="spbc_2fa_wrapper" style="display: inline !important;">'
                    . '<label for="spbc_2fa">' . $label . '</label>'
                    . '<input type="text"   name="spbc_2fa" id="spbc_2fa" class="input" value="" size="20" />'
                    . '<input type="hidden" name="log" class="input" value="' . $user_name . '" />'
                    . $description . '<br><br>Contact ' . $tech_support_url . ' if you have questions.<br><br>'
                    . '</p>'
                    . '<p class="submit" style="display: inline !important;">'
                    . '<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In">'
                    . '<input type="hidden" name="redirect_to" value="' . admin_url() . '">'
                    . '<input type="hidden" name="testcookie" value="1">'
                    . '</p>';
                // Deleting all form and then put out content in it.
                echo '<script>'
                     . 'var spbc_form = document.getElementById("loginform");'
                     . "spbc_form.innerHTML = '';"
                     . 'setTimeout(function(){'
                     . "spbc_form.innerHTML = '" . $replacement . "';"
                     . "document.getElementById('spbc_2fa').focus();"
                     . '}, 500);'
                     . '</script>';
            }
        }
    }
}

function spbc_2fa__key_generate_and_store($user)
{
    global $spbc;

    // Generate key
    $left_part_for_pad = hexdec(substr(hash('sha256', $spbc->data['salt'] . rand(0, getrandmax())), 0, 6)) % 1000;
    $right_part_for_pad = hexdec(substr(hash('sha256', $spbc->data['salt'] . rand(0, getrandmax())), 0, 6)) % 1000;
    $left_part  = str_pad(
        (string) $left_part_for_pad,
        3,
        '1',
        STR_PAD_LEFT
    );
    $right_part = str_pad(
        (string) $right_part_for_pad,
        3,
        '0',
        STR_PAD_LEFT
    );
    $key        = $left_part . $right_part;

    $spbc->data['2fa_keys'][ $user->user_login ] = array(
        'generated' => time(),
        'val'       => $key,
    );
    $spbc->save('data');

    return (int) $key;
}

function spbc_2fa__key_remove_old()
{
    global $spbc;

    // Check for old keys
    $keys = $spbc->data['2fa_keys'];
    foreach ( $keys as $index => $key ) {
        if ( $key['generated'] < time() - SPBC_2FA_KEY_TTL ) {
            unset($spbc->data['2fa_keys'][ $index ]);
        }
    }

    $spbc->save('data');
}

/**
 * Handle for check if rate limit is passed
 *
 * @return bool
 */
function spbc_2fa_is_rate_limit_pass()
{
    $time = time();

    $rateLimit = get_option('spbc_rate_limit_2fa', [
        'limit' => 10,
        'expires_in' => $time + 60,
        'attempts' => 0,
    ]);

    if ($rateLimit['expires_in'] <= $time) {
        $rateLimit['expires_in'] = $time + 60;
        $rateLimit['attempts'] = 0;
    }

    if ($rateLimit['expires_in'] > $time) {
        $rateLimit['attempts']++;
    }

    if ($rateLimit['attempts'] >= $rateLimit['limit']) {
        return false;
    }

    update_option('spbc_rate_limit_2fa', $rateLimit);

    return true;
}

/**
 * Check if rate limit is passed
 */
function spbc_2fa_rate_limit()
{
    if ( isset($_POST['spbc_2fa'], $_POST['log']) ) {
        $rateLimit = spbc_2fa_is_rate_limit_pass();
        if (!$rateLimit) {
            wp_die(
                __('Rate limit exceeded. Protected - Security by CleanTalk.', 'security-malware-firewall'),
                'Forbidden',
                array('response' => 403)
            );
        }
    }
}

/**
 * Authenticate with 2fa code
 */
function spbc_2fa__authenticate()
{
    global $spbc;

    if ( $spbc->settings['2fa__enable'] ) {
        if ( isset($_POST['spbc_2fa'], $_POST['log']) ) {
            $user = get_user_by('login', $_POST['log']);

            if (!$user) {
                $user = get_user_by('email', $_POST['log']);
            }

            if ( $user instanceof WP_User ) {
                spbc_2fa__key_remove_old();

                $type2fa    = get_user_meta($user->ID, 'spbc_2fa_type', true);
                $g2fa_token = get_user_meta($user->ID, 'spbc_g2fa_token', true);
                $ga         = new GoogleAuthenticator();

                // 2fa passed
                if ( isset($spbc->data['2fa_keys'][ $user->user_login ]) && $spbc->data['2fa_keys'][ $user->user_login ]['val'] == $_POST['spbc_2fa'] ) {
                    // Delete it so no one could login via this code
                    unset($spbc->data['2fa_keys'][ $user->user_login ]);
                    $spbc->save('data');

                    spbc_authenticate__write_log_login($user);
                    spbc_2fa__success($user);
                } elseif ( $type2fa === 'google_authenticator' && $g2fa_token && $_POST['spbc_2fa'] == $ga->getCode($g2fa_token) ) {
                    spbc_authenticate__write_log_login($user);
                    spbc_2fa__success($user);
                } else {
                    spbc_2fa__failed($user);
                }
            }
        }
    }
}

function spbc_2fa__success(\WP_User $user)
{
    global $spbc;

    $type2fa = get_user_meta($user->ID, 'spbc_2fa_type', true);
    $event   = $type2fa === 'google_authenticator' ? 'login_g2fa' : 'login_2fa';

    // Add event to security log
    spbc_auth_log(
        array(
        'username'     => $user->user_login,
        'event'        => $event,
        'roles'        => reset($user->roles),
        'user_agent'   => filter_input(INPUT_SERVER, 'HTTP_USER_AGENT'),
        'browser_sign' => spbc_authenticate__browser_sign__get_hash($user),
        )
    );

    // Sends logs to get notify about superuser login.
    $result = spbc_send_logs();
    if ( empty($result['error']) ) {
        $spbc->error_delete('send_logs');
        $spbc->data['logs_last_sent']         = current_time('timestamp');
        $spbc->data['last_sent_events_count'] = $result;
        $spbc->save('data');
    } else {
        $spbc->error_add('send_logs', $result);
    }

    // Athorize user and redirect to wp-admin
    wp_set_auth_cookie($user->ID);
    if (spbc_authenticate__is_new_device($user)) {
        spbc_authenticate__browser_sign__set($user);
    }
    spbc_authenticate__user_agent__set($user);
    Cookie::set('spbc_2fa_passed', hash('sha256', $spbc->data['salt'] . $user->ID), time() + 60 * 60 * 24 * 30, '/', parse_url(get_option('home'), PHP_URL_HOST), false, true);
    if ( isset($_REQUEST['redirect_to']) ) {
        $redirect_to = $_REQUEST['redirect_to'];
    } else {
        $redirect_to = admin_url();
    }
    wp_redirect($redirect_to);
    die();
}

function spbc_2fa__failed(\WP_User $user)
{
    $type2fa = get_user_meta($user->ID, 'spbc_2fa_type', true);
    $event   = $type2fa === 'google_authenticator' ? 'auth_failed_g2fa' : 'auth_failed_2fa';

    spbc_auth_log(
        array(
        'username'     => $user->user_login,
        'event'        => $event,
        'roles'        => 'administrator',
        'user_agent'   => filter_input(INPUT_SERVER, 'HTTP_USER_AGENT'),
        'browser_sign' => spbc_authenticate__browser_sign__get_hash($user),
        )
    );
    wp_redirect(
        wp_login_url()
        . ( strpos(wp_login_url(), '?') === false ? '?' : '&' )
        . 'spbc_2fa_error=1&spbc_2fa_user=' . $user->user_login
    );
    die();
}

/**
 * Logs a logout event
 *
 * @param $id
 *
 * @return null
 */
function spbc_wp_logout($id)
{
    $user = get_user_by('id', $id);

    // The user is logged out.
    if ( isset($user->ID) && $user->ID > 0 ) {
        $roles = null;
        if ( is_array($user->roles) ) {
            $roles = $user->roles[0]; // Takes only first role.
        }
        spbc_auth_log(
            array(
            'username'     => $user->get('user_login'),
            'event'        => 'logout',
            'roles'        => $roles,
            'user_agent'   => spbc_authenticate__user_agent__get($user),
            'browser_sign' => spbc_authenticate__browser_sign__get_hash($user),
            )
        );
    }

    Cookie::set('spbc_is_logged_in', '0', time() - 30, '/');

    return null;
}

function spbc_fix_error_messages($error_msg)
{
    global $spbc;

    //Fixed for custom filters
    if ( ! is_string($error_msg) ) {
        return $error_msg;
    }

    // 2fa wrong code
    if ( isset($_GET['spbc_2fa_error']) ) {
        $error_msg = explode('<br />', $error_msg);

        return $error_msg[0] . '<br />' . __('Wrong temporary code. Check your email to gain the code.', 'security-malware-firewall');
    }

    // Custom block message
    if ( $spbc->login_error ) {
        return '<strong>' . __('Error') . '</strong>: '
               . __('Entered credentials are wrong, please, try again.', 'security-malware-firewall')
               . ' <a href="' . esc_url(wp_lostpassword_url()) . '">' . __('Lost your password?') . '</a>';
    }

    return $error_msg;
}

function spbc_is_user_logged_in()
{
    return (bool) preg_grep("/wordpress_logged_in/", array_keys($_COOKIE));
}

/**
 * The function logs any attempt to log in the WordPress backend.
 *
 * @param array $params
 *
 * @return int Inserted log ID
 */
function spbc_auth_log($params)
{
    global $wpdb, $spbc;

    if ( ! $spbc->feature_restrictions->getState($spbc, 'security_log')->is_active ) {
        return 0;
    }

    SecurityCounter::increment($params['event']);

    $params_default = array(
        'username'     => null,
        'event'        => null,
        'page'         => null,
        'page_time'    => null,
        'roles'        => null,
        'blog_id'      => ( SPBC_WPMS ? get_current_blog_id() : null ),
        'user_agent'   => null,
        'browser_sign' => null,
    );
    $params         = array_merge($params_default, $params);

    // Cutting to 1024 symbols
    $params['user_agent'] = is_string($params['user_agent'])
        ? substr($params['user_agent'], 0, 1024)
        : $params['user_agent'];

    $auth_ip = IP::get();

    // To fix issue with NULL values for not NULL field.
    $blog_id = isset($params['blog_id']) && $params['blog_id'] !== null ? $params['blog_id'] : 1;

    // @todo Learn the prepare method to insert NULL value
    $wpdb->query(
        $wpdb->prepare(
            'INSERT INTO ' . SPBC_TBL_SECURITY_LOG
            . '(`datetime`, `timestamp_gmt`, `user_login`, `event`, `auth_ip`, `page`, `page_time`, `blog_id`, `role`, `user_agent`, `browser_sign` )'
            . ' VALUES( %s, %d, %s, %s, %s, %s, %d, %d, %s, %s, %s )',
            array(
            date('Y-m-d H:i:s'),
            time(),
            $params['username'],
            $params['event'],
            $auth_ip,
            $params['page'],
            $params['page_time'],
            $blog_id,
            $params['roles'],
            $params['user_agent'],
            $params['browser_sign'],
            )
        )
    );

    return $wpdb->insert_id;
}

/**
 * Add option to the profile page.
 *
 * @param WP_User $wp_user
 */
function spbc_2fa__SelfUserProfileEdit($wp_user)
{
    global $spbc;

    if (spbc_is_user_role_in($spbc->settings['2fa__roles'], $wp_user)) {
        $type2fa = get_user_meta($wp_user->ID, 'spbc_2fa_type', true);
        $button  = '';

        if ($type2fa === 'google_authenticator') {
            $type2fa_label = esc_html__('Google authenticator', 'security-malware-firewall');
            // Disable G2FA can only admin and self-edited user.
            if (current_filter() === 'show_user_profile' || current_user_can('manage_options')) {
                $button = '<button class="button" id="spbc-g2fa-disable" data-user-id="' . sanitize_key((string) $wp_user->ID) . '">' . esc_html__('Disable Google Authenticator', 'security-malware-firewall') . '</button>';
                $button .= '<br><em>' . esc_html__('To disable the Google authentication click the button above or reset the password to the account. The two-factor authentication will be switched to Email. Or you can disable it directly on the page of the WordPress site profile.', 'security-malware-firewall') . '</em>';
            }
        } else {
            $type2fa_label = esc_html__('Email', 'security-malware-firewall');
            // Enable G2FA can only self-edited user.
            if (current_filter() === 'show_user_profile') {
                $button = '<button class="button" id="spbc-g2fa-enable">' . esc_html__('Enable Google Authenticator', 'security-malware-firewall') . '</button>';
            }
        }

        echo '<h2>' . $spbc->data["wl_brandname"] . esc_html__(' 2FA', 'security-malware-firewall') . '</h2>';
        ?>
        <table class="form-table">
            <tr id="spbc-2fa-type">
                <th>
                    <label for="spbc-2fa-type"><?php esc_html_e('2FA type', 'security-malware-firewall'); ?></label>
                </th>
                <td>
                    <p><?php echo esc_html__('Two-factor authentication (2FA) type:', 'security-malware-firewall') . ' '; ?>
                        <strong><?php echo $type2fa_label; ?></strong></p>
                    <p><?php echo $button; ?></p>
                </td>
            </tr>
        </table>
        <div id="spbct-google-qr-code" class="spbc_hide" style="padding: 0 15px;text-align:center;">
            <p><?php esc_html_e('Please scan this with the Google Authenticator App.', 'security-malware-firewall'); ?></p>
            <div id="spbct-google-qr-code-img"></div>
            <p><?php esc_html_e('Enter Google Authenticator code.', 'security-malware-firewall'); ?></p>
            <input name="spbct-google-qr-code" type="text"/>
        </div>
        <?php
    }
}

/**
 * Getting Google QR
 * AJAX action.
 */
function spbc_2fa__GetGoogleQrCode()
{
    spbc_check_ajax_referer('spbc_secret_nonce', 'security');
    $user_obj = wp_get_current_user();

    if (property_exists($user_obj, 'ID')) {
        $user_token = get_user_meta($user_obj->ID, 'spbc_g2fa_token', true);
        $ga = new GoogleAuthenticator();

        if (!$user_token) {
            $user_token = $ga->generateSecret();
            update_user_meta($user_obj->ID, 'spbc_g2fa_token', $user_token);
        }

        $urlencoded = urlencode('otpauth://totp/' . get_site_url() . '?secret=' . $user_token . '');
        $encoder = "https://api.qrserver.com/v1/create-qr-code/?data=";
        $qrImageURL = $encoder . $urlencoded . "&size=200x200&ecc=M";
        $qr         = '<img style="border:0;padding:10px;width:200px;height:auto;" src="' . $qrImageURL . '" alt="Google authenticator QR code"/>';

        wp_send_json_success(array('img' => $qr, 'code' => $user_token));
    }

    wp_send_json_error(esc_html__('Error: Current user is undefined.', 'security-malware-firewall'));
}

/**
 * Checking 6 digit Google 2fa code.
 * AJAX action.
 */
function spbc_2fa__CheckGoogleCode()
{
    spbc_check_ajax_referer('spbc_secret_nonce', 'security');

    if (isset($_POST['code']) && preg_match('/^\d{6}$/', trim($_POST['code']))) {
        $user_obj = wp_get_current_user();

        if (property_exists($user_obj, 'ID')) {
            $user_token = get_user_meta($user_obj->ID, 'spbc_g2fa_token', true);

            if ($user_token) {
                $ga   = new GoogleAuthenticator();
                $code = $ga->getCode($user_token);

                if (trim($_POST['code']) === $code) {
                    if (update_user_meta($user_obj->ID, 'spbc_2fa_type', 'google_authenticator')) {
                        wp_send_json_success();
                    }
                    wp_send_json_error(esc_html__('Error: 2FA type not updated.', 'security-malware-firewall'));
                }

                wp_send_json_error(esc_html__('Error: The code not match.', 'security-malware-firewall'));
            }

            wp_send_json_error(esc_html__('Error: User token error.', 'security-malware-firewall'));
        }

        wp_send_json_error(esc_html__('Error: Current user is undefined.', 'security-malware-firewall'));
    }

    wp_send_json_error(esc_html__('Error: The code is incorrect.', 'security-malware-firewall'));
}

/**
 * Disable Google 2fa.
 * AJAX action.
 */
function spbc_2fa__DisableGoogle2fa()
{
    spbc_check_ajax_referer('spbc_secret_nonce', 'security');

    if (isset($_POST['user_id'])) {
        $user_obj = spbc_get_user_by('id', sanitize_key($_POST['user_id']));

        if (is_object($user_obj) && property_exists($user_obj, 'ID')) {
            if (spbc_2fa__Google2fa_replace_meta($user_obj)) {
                wp_send_json_success();
            }

            wp_send_json_error(esc_html__('Error: 2FA type not updated.', 'security-malware-firewall'));
        }
    }

    wp_send_json_error(esc_html__('Error: Current user is undefined.', 'security-malware-firewall'));
}

function spbc_user_last_login_column($columns)
{
    $columns['spbc_user_last_login'] = esc_html__('Last login', 'security-malware-firewall');
    return $columns;
}

function spbc_user_last_login_column_content($value, $column_name, $user_id)
{
    if ( $column_name === 'spbc_user_last_login' ) {
        $last_login = get_user_meta($user_id, '_spbc_last_login', true);
        if ($last_login) {
            $value = date('M d, Y, H:i:s', $last_login);
        } else {
            $value =  esc_html__('-', 'security-malware-firewall');
        }
    }

    return $value;
}
