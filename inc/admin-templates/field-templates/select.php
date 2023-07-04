<?php if (isset($data['title'])) { ?>
    <label for="spbc_setting_<?php echo $data['name']; ?>" class="spbc_settings-field_title spbc_settings-field_title--<?php echo $data['type']; ?>"><?php echo $data['title']; ?></label>&nbsp;
<?php } ?>

<?php

echo '<select'
     . ' class="spbc_setting_' . $data['type'] . '"'
     . ' id="spbc_setting_' . $data['name'] . '"'
     . ' name="spbc_settings[' . $data['name'] . ']"'
     . ($data['disabled'] || ($data['parent'] && ! $data['parent_value']) ? ' disabled="disabled"' : '')
     . (! $data['children'] ? '' : ' children="' . implode(",", $data['children']) . '"')
     // .' onchange="console.log( jQuery(this).find(\'option:selected\') ); console.log( jQuery(this).find(\'option:selected\').attr(\'children_enable\') );"'
     . ($data['children']
        ? ' onchange="spbcSettingsDependencies(\'' . implode(",", $data['children']) . '\', jQuery(this).find(\'option:selected\').attr(\'children_enable\'))"'
        : ''
     )
     . '>';

foreach ($data['options'] as $option) {
    echo '<option'
         . ' value="' . $option['val'] . '"'
         . ($data['value'] == $option['val'] ? 'selected' : '')
         . (isset($option['children_enable']) ? ' children_enable=' . $option['children_enable'] : '')
         . '>'
         . $option['label']
         . '</option>';
}
echo '</select>';
?>

<?php if (isset($data['long_description'])) { ?>
    <i setting="<?php echo $data['name']; ?>" class="spbc_long_description__show spbc-icon-help-circled"></i>
<?php } ?>

<?php if (isset($data['description'])) { ?>
    <div style="margin-bottom: 10px" class="spbc_settings_description"><?php echo $data['description']; ?></div>
<?php } ?>
