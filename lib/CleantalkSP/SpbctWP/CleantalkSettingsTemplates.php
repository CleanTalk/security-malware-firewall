<?php

namespace CleantalkSP\SpbctWP;

class CleantalkSettingsTemplates
{
    private $api_key;

    private static $templates;

    /**
     * CleantalkDefaultSettings constructor.
     *
     * @param $api_key
     */
    public function __construct($api_key)
    {
        $this->api_key = $api_key;
        add_filter('spct_key_additional_links', array($this, 'add_action_button'), 10, 1);
        add_action('wp_ajax_spbc_get_options_template', array($this, 'get_options_template_ajax'));
        add_action('wp_ajax_spbc_settings_templates_export', array($this, 'settings_templates_export_ajax'));
        add_action('wp_ajax_spbc_settings_templates_import', array($this, 'settings_templates_import_ajax'));
        add_action('wp_ajax_spbc_settings_templates_reset', array($this, 'settings_templates_reset_ajax'));
    }

    public function add_action_button($links) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $link    = '<a href="#" class="ct_support_link" onclick="spbcModal.open().load(\'spbc_get_options_template\')" style="color:#666;">'
                   . __('Import/Export Settings', 'security-malware-firewall')
                   . '</a>';
        $links[] = $link;

        return $links;
    }

    public function get_options_template_ajax() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        check_ajax_referer('spbc_secret_nonce', 'security');
        echo $this->getHtmlContent();
        die();
    }

    public function settings_templates_export_ajax() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        check_ajax_referer('spbc_secret_nonce', 'security');
        $error_text = 'Export handler error.';
        if ( isset($_POST['data']) && is_array($_POST['data']) ) {
            $template_info = $_POST['data'];
            if ( isset($template_info['template_id']) ) {
                $template_id = sanitize_text_field($template_info['template_id']);
                $res         = API::method__services_templates_update(
                    $this->api_key,
                    (int) $template_id,
                    $this->getOptions(),
                    'security'
                );
                if ( is_array($res) && array_key_exists('operation_status', $res) ) {
                    if ( $res['operation_status'] === 'SUCCESS' ) {
                        wp_send_json_success(esc_html__('Success. Reloading...', 'security-malware-firewall'));
                    }
                    if ( $res['operation_status'] === 'FAILED' ) {
                        wp_send_json_error('Error: ' . $res['operation_message']);
                    }
                }
                $error_text = 'Template updating response is wrong.';
            }
            if ( isset($template_info['template_name']) ) {
                $template_name = sanitize_text_field($template_info['template_name']);
                $res           = API::method__services_templates_add(
                    $this->api_key,
                    $template_name,
                    $this->getOptions(),
                    'security'
                );
                if ( is_array($res) && array_key_exists('operation_status', $res) ) {
                    if ( $res['operation_status'] === 'SUCCESS' ) {
                        wp_send_json_success(esc_html__('Success. Reloading...', 'security-malware-firewall'));
                    }
                    if ( $res['operation_status'] === 'FAILED' ) {
                        wp_send_json_error('Error: ' . $res['operation_message']);
                    }
                }
                $error_text = 'Template adding response is wrong.';
            }
        }
        wp_send_json_error('Error: ' . $error_text);
    }

    public function settings_templates_import_ajax() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        check_ajax_referer('spbc_secret_nonce', 'security');
        if ( isset($_POST['data']) && is_array($_POST['data']) ) {
            $template_info = $_POST['data'];
            if ( isset($template_info['template_id'], $template_info['template_name'], $template_info['settings']) ) {
                $res = $this->setOptions(
                    $template_info['template_id'],
                    $template_info['template_name'],
                    $template_info['settings']
                );
                if ( $res ) {
                    wp_send_json_success(esc_html__('Success. Reloading...', 'security-malware-firewall'));
                } else {
                    wp_send_json_error(esc_html__('Error. Can not save settings.', 'security-malware-firewall'));
                }
            }
        }
        wp_send_json_error('Import handler error.');
    }

    public function settings_templates_reset_ajax() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        check_ajax_referer('spbc_secret_nonce', 'security');
        $res = $this->resetOptions();
        if ( $res ) {
            wp_send_json_success(esc_html__('Success. Reloading...', 'security-malware-firewall'));
        } else {
            wp_send_json_error(esc_html__('Error. Can not reset settings.', 'security-malware-firewall'));
        }
    }

    public static function get_options_template($api_key) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        if ( ! self::$templates ) {
            $res = API::method__services_templates_get($api_key, 'security');
            if ( is_array($res) ) {
                if ( array_key_exists('error', $res) ) {
                    $templates = array();
                } else {
                    $templates = $res;
                }
            } else {
                $templates = array();
            }

            self::$templates = $templates;
        }

        return self::$templates;
    }

    public function getHtmlContent($import_only = false)
    {
        $templates = self::get_options_template($this->api_key);
        $title     = $this->getTitle();
        $out       = $this->getHtmlContentImport($templates);
        if ( ! $import_only ) {
            $out .= $this->getHtmlContentExport($templates);
            $out .= $this->getHtmlContentReset();
        }

        return $title . $out;
    }

    private function getHtmlContentImport($templates)
    {
        $templatesSet = '<h3>' . esc_html__('Import settings', 'security-malware-firewall') . '</h3>';

        //Check available option_site parameter
        if ( count($templates) > 0 ) {
            foreach ( $templates as $key => $template ) {
                if ( empty($template['options_site']) ) {
                    unset($templates[$key]);
                }
            }
        }

        if ( count($templates) === 0 ) {
            $templatesSet .= esc_html__('There are no settings templates', 'security-malware-firewall');

            return $templatesSet . '<br><hr>';
        }

        $templatesSet .= '<p><select id="spbc_settings_templates_import" >';
        foreach ( $templates as $template ) {
            $templatesSet .= "<option 
								data-id='" . $template['template_id'] . "'
								data-name='" . htmlspecialchars($template['name']) . "''
								data-settings='" . $template['options_site'] . "'>"
                             . htmlspecialchars($template['name'])
                             . "</option>";
        }
        $templatesSet .= '</select></p>';
        $button       = $this->getImportButton();

        return $templatesSet . '<br>' . $button . '<br><hr>';
    }

    public function getHtmlContentExport($templates)
    {
        $templatesSet = '<h3>' . esc_html__('Export settings', 'security-malware-firewall') . '</h3>';
        $templatesSet .= '<p><select id="spbc_settings_templates_export" >';
        $templatesSet .= '<option data-id="new_template" checked="true">New template</option>';
        foreach ( $templates as $template ) {
            $templatesSet .= '<option data-id="'
                             . $template['template_id']
                             . '">'
                             . htmlspecialchars($template['name'])
                             . '</option>';
        }
        $templatesSet .= '</select></p>';
        $templatesSet .= '<p><input type="text" id="spbc_settings_templates_export_name" name="spbc_settings_template_name" placeholder="'
                         . esc_html__('Enter a template name', 'security-malware-firewall')
                         . '" required /></p>';
        $button       = $this->getExportButton();

        return $templatesSet . '<br>' . $button . '<br>';
    }

    public function getHtmlContentReset()
    {
        return '<hr><br>' . $this->getResetButton() . '<br>';
    }

    private function getTitle()
    {
        global $spbc;
        if ( isset($spbc->data['current_settings_template_name']) && $spbc->data['current_settings_template_name'] ) {
            $current_template_name = $spbc->data['current_settings_template_name'];
        } else {
            $current_template_name = 'default';
        }
        $content = '<h2>' . esc_html__('CleanTalk settings templates', 'security-malware-firewall') . '</h2>';
        $content .= '<p style="top: -15px; position: relative;">'
                    . esc_html__(
                        'You can manage settings by using a template here if you need.',
                        'security-malware-firewall'
                    )
                    . '<br>'
                    . esc_html__(
                        'Two-factor authentication settings won\'t be exported. Because they can be operated only direct from the plugin.',
                        'security-malware-firewall'
                    )
                    . '</p>';
        $content .= '<p>'
                    . esc_html__('You are currently using:', 'security-malware-firewall')
                    . ' '
                    . $current_template_name
                    . '</p>';

        return $content;
    }

    private function getExportButton()
    {
        return '<button id="spbc_settings_templates_export_button" class="spbc_manual_link">'
               . esc_html__('Export settings to selected template', 'security-malware-firewall')
               . '<img alt="Preloader ico" style="margin-left: 10px;" class="spbc_preloader_button" src="' . SPBC_PATH . '/images/preloader.gif" />'
               . '<img alt="Success ico" style="margin-left: 10px;" class="spbc_success --hide" src="' . SPBC_PATH . '/images/yes.png" />'
               . '</button>';
    }

    private function getImportButton()
    {
        return '<button id="spbc_settings_templates_import_button" class="spbc_manual_link">'
               . esc_html__('Import settings from selected template', 'security-malware-firewall')
               . '<img alt="Preloader ico" style="margin-left: 10px;" class="spbc_preloader_button" src="' . SPBC_PATH . '/images/preloader.gif" />'
               . '<img alt="Success ico" style="margin-left: 10px;" class="spbc_success --hide" src="' . SPBC_PATH . '/images/yes.png" />'
               . '</button>';
    }

    private function getResetButton()
    {
        return '<button id="spbc_settings_templates_reset_button" class="ct_support_link">'
               . esc_html__('Reset settings to defaults', 'security-malware-firewall')
               . '<img alt="Preloader ico" style="margin-left: 10px;" class="spbc_preloader_button" src="' . SPBC_PATH . '/images/preloader.gif" />'
               . '<img alt="Success ico" style="margin-left: 10px;" class="spbc_success --hide" src="' . SPBC_PATH . '/images/yes.png" />'
               . '</button>';
    }


    /**
     * Collect options to JSON
     *
     * @return false|string
     */
    private function getOptions()
    {
        global $spbc;
        $settings = (array)$spbc->settings;
        // Remove apikey from export
        if ( isset($settings['spbc_key']) ) {
            unset($settings['spbc_key']);
        }
        // Remove misc__custom_key from export
        if ( isset($settings['misc__custom_key']) ) {
            unset($settings['misc__custom_key']);
        }
        // Remove 2FA settings from export to prevent the website access blocking.
        if ( isset($settings['2fa__enable']) ) {
            unset($settings['2fa__enable']);
        }
        if ( isset($settings['2fa__roles']) ) {
            unset($settings['2fa__roles']);
        }
        // Remove all WPMS from export
        $settings = array_filter($settings, static function ($key) {
            return strpos($key, 'multisite__') === false;
        }, ARRAY_FILTER_USE_KEY);

        return json_encode($settings, JSON_FORCE_OBJECT);
    }

    /**
     * Set options to the system
     *
     * @param $template_id
     * @param $template_name
     * @param $settings
     *
     * @return bool
     */
    private function setOptions($template_id, $template_name, $settings)
    {
        global $spbc;
        $settings                                     = array_replace((array)$spbc->settings, $settings);
        $settings                                     = spbc_sanitize_settings($settings);
        $spbc->settings                               = $settings;
        $spbc->data['current_settings_template_id']   = $template_id;
        $spbc->data['current_settings_template_name'] = $template_name;
        $spbc->data['key_changed']                    = true;

        return $spbc->save('settings') && $spbc->save('data');
    }

    /**
     * Reset options to the default values
     *
     * @return bool
     */
    private function resetOptions()
    {
        global $spbc;
        $def_settings = $spbc->default_settings;
        if ( isset($def_settings['spbc_key']) ) {
            unset($def_settings['spbc_key']);
        }
        $settings       = array_replace((array)$spbc->settings, $def_settings);
        $settings       = spbc_sanitize_settings($settings);
        $spbc->settings = $settings;
        $spbc->data['current_settings_template_id']   = null;
        $spbc->data['current_settings_template_name'] = null;
        $spbc->save('data');

        return $spbc->save('settings');
    }

    public static function settingsTemplatesValidateApiResponse($template_id, $template_get_result)
    {
        $services_templates_get_error = '';
        $options_site = null;
        $template_name = '';

        if ( empty($template_get_result) || !is_array($template_get_result) ) {
            throw new \InvalidArgumentException('Parse services_templates_get API error: wrong services_templates_get response');
        }

        if ( array_key_exists('error', $template_get_result) ) {
            throw new \InvalidArgumentException('Parse services_templates_get API error: ' . $template_get_result['error']);
        }

        foreach ( $template_get_result as $_key => $template ) {
            if ( empty($template['template_id']) ) {
                $services_templates_get_error = 'Parse services_templates_get API error: template_id is empty';
                break;
            }
            if ( $template['template_id'] === (int)$template_id ) {
                if ( empty($template['options_site']) ) {
                    $services_templates_get_error = 'Parse services_templates_get API error: options_site is empty';
                    break;
                }
                if ( !is_string($template['options_site']) ) {
                    $services_templates_get_error = 'Parse services_templates_get API error: options_site is not a string';
                    break;
                }
                $options_site = json_decode($template['options_site'], true);
                $template_name = !empty($template['name']) ? htmlspecialchars($template['name']) : 'N\A';
                if ( $options_site === false || !is_array($options_site)) {
                    $services_templates_get_error = 'Parse services_templates_get API error: options_site JSON decode error';
                    break;
                }
            }
        }

        if ( !empty($services_templates_get_error) ) {
            throw new \InvalidArgumentException($services_templates_get_error);
        }

        if ( empty($options_site) ) {
            throw new \InvalidArgumentException('Parse services_templates_get API error: no such template_id found in APi response ' . $template_id);
        }

        return array(
            'template_name' => $template_name,
            'options_site' => $options_site
        );
    }

    public static function settingsTemplatesSetOptions($template_id, array $options_template_data, $api_key)
    {
        $templates_object = new CleantalkSettingsTemplates($api_key);
        $settings_set_result = $templates_object->setOptions(
            $template_id,
            $options_template_data['template_name'],
            $options_template_data['options_site']
        );

        $result = $settings_set_result
            ? json_encode(array('OK' => 'Settings updated'))
            : json_encode(array('ERROR' => 'Internal settings updating error'));

        return $result !== false ? $result : '{"ERROR":"Internal JSON encoding error"}';
    }
}
