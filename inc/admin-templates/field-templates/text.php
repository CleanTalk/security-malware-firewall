<?php if ($data['title_first']) { ?>
    <label for="spbc_setting_<?php echo $data['name']; ?>" class="spbc_settings-field_title spbc_settings-field_title--<?php echo $data['type']; ?>"><?php echo $data['title']; ?></label>&nbsp;
<?php } ?>

<?php
$affiliate_short_code = $data['name'] === 'spbc_trusted_and_affiliate__shortcode_tag'
    ? '[cleantalk_security_affiliate_link]'
    : '';
$readonly = !empty($affiliate_short_code) ? 'readonly' : '';
echo '<input type="text" id="spbc_setting_' . $data['name'] . '" name="spbc_settings[' . $data['name'] . ']" '
     //.(!$spbc->data['moderate'] ? ' disabled="disabled"' : '')
     . ($data['class'] ? ' class="' . $data['class'] . '"' : '')
     . ($data['required'] ? ' required="required"' : '')
     . 'value="' . ($data['value'] ?: $affiliate_short_code) . '" '
     . $readonly
     . ($data['disabled'] || ($data['parent'] && ! $data['parent_value']) ? ' disabled="disabled"' : '')
     . (! $data['children'] ? '' : ' children="' . implode(",", $data['children']) . '"')
     . (! $data['children'] ? '' : ' onchange="spbcSettingsDependencies(\'' . implode(",", $data['children']) . '\')"')
     . ' />';
?>

<?php if (! $data['title_first']) { ?>
    &nbsp;<label for="spbc_setting_<?php echo $data['name']; ?>" class="spbc_setting-field_title--<?php echo $data['type']; ?>"><?php echo $data['title']; ?></label>
<?php } ?>

<?php if (isset($data['long_description'])) { ?>
    <i setting="<?php echo $data['name']; ?>" class="spbc_long_description__show spbc-icon-help-circled"></i>
<?php } ?>

<?php if (isset($data['description'])) { ?>
    <div class="spbc_settings_description"><?php echo $data['description']; ?></div>
<?php } ?>
