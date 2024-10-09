<?php

namespace CleantalkSP\SpbctWP;

class Escape extends \CleantalkSP\Common\Escape
{
    /**
     * Simple method: escape attribute
     *
     * @param $text
     *
     * @return string
     */
    public static function escAttr($text)
    {
        return esc_attr($text);
    }

    /**
     * Simple method: escape html
     *
     * @param $text
     *
     * @return string
     */
    public static function escHtml($text)
    {
        return esc_html($text);
    }

    /**
     * Simple method: escape js
     *
     * @param $text
     *
     * @return string
     */
    public static function escJs($text)
    {
        return esc_js($text);
    }

    /**
     * Simple method: escape textarea
     *
     * @param $text
     *
     * @return string
     */
    public static function escTextarea($text)
    {
        return esc_textarea($text);
    }

    /**
     * Simple method: escape url
     *
     * @param $text
     *
     * @return string
     */
    public static function escUrl($text)
    {
        return esc_url($text);
    }

    /**
     * Simple method: escape url raw
     *
     * @param $text
     *
     * @return string
     */
    public static function escUrlRaw($text)
    {
        return esc_url_raw($text);
    }

    /**
     * Simple method: escape kses
     *
     * @param $string
     * @param $allowed_html
     * @param array $allowed_protocols
     *
     * @return string
     */
    public static function escKses($string, $allowed_html, $allowed_protocols = array())
    {
        return wp_kses($string, $allowed_html, $allowed_protocols = array());
    }

    public static function escKsesPreset($string, $preset = null, $_allowed_protocols = array(), $allowed_style_props = array())
    {

        $kses_presets = array(
            'spbc_settings__display__notifications' => array(
                'a' => array(
                    'target' => true,
                    'href' => true,
                ),
            ),
            'spbc_settings__feature_restrictions' => array(
                'a' => array(
                    'target' => true,
                    'href' => true,
                ),
                'li' => [
                    'class' => 1,
                ],
                'ul' => [
                    'style' => 1,
                ],
                'div' => [
                    'style' => 1,
                ],
                'h3' => [
                    'style' => 1,
                ],
                'input' => [
                    'type' => 1,
                    'class' => 1,
                    'value' => 1,
                ],
            ),
            'spbc_cdn_checker_table' => array(
                'a' => array(
                    'style' => true,
                    'href' => true,
                    'onclick' => true,
                ),
                'p' => array(),
                'b' => array(),
                'table' => array(
                    'id' => true,
                    'style' => true,
                ),
                'tr' => array(
                    'class' => true,
                    'style' => true,
                ),
                'th' => array(
                    'style' => true,
                    'class' => true,
                ),
                'td' => array(
                    'colspan' => true,
                    'style' => true,
                    'class' => true,
                ),
                'tbody' => true,
                'div' => array()
            ),
            'spbc_settings__notice_autosend' => array(
                'div' => array(
                    'class' => true,
                ),
                'p' => array(),
                'img' => array(
                    'src' => true,
                    'alt' => true,
                    'style' => true,
                ),
            ),
            'spbc_settings__sending_for_analysis_rules' => array(
                'div' => array(),
                'p' => array(),
                'li' => array(),
                'ul' => array(
                    'style' => true,
                ),
            )
        );

        add_filter('safe_style_css', function ($styles) use ($allowed_style_props) {
            foreach ( $allowed_style_props as $prop ) {
                $styles[] = $prop;
            }
            return $styles;
        });

        if ( !empty($kses_presets[$preset]) ) {
            $allowed_html = $kses_presets[$preset];
            return self::escKses($string, $allowed_html, $allowed_protocols = array());
        }

        return self::escKses($string, $allowed_html = array(), $allowed_protocols = array());
    }

    /**
     * Simple method: escape kses post
     *
     * @param $data
     *
     * @return string
     */
    public static function escKsesPost($data)
    {
        return wp_kses_post($data);
    }
}
