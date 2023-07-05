<?php if (isset($data['title'])) { ?>
    <span class="spbc_settings-field_title spbc_settings-field_title--<?php echo $data['type']; ?>"><?php echo $data['title']; ?></span>
<?php } ?>

<?php if (isset($data['long_description'])) { ?>
    <i setting="<?php echo $data['name']; ?>" class="spbc_long_description__show spbc-icon-help-circled"></i>
<?php } ?>

<?php if (isset($data['description']) && function_exists($data['description'])) {
    call_user_func($data['description']);
} elseif (isset($data['description']) && ! function_exists($data['description'])) { ?>
    <div style="margin-bottom: 10px" class="spbc_settings_description"><?php echo $data['description']; ?></div>
<?php } ?>

<?php

foreach ($data['options'] as $option) {
    echo '<input'
         . ' type="radio"'
         . ' class="spbc_setting_' . $data['type'] . '"'
         . ' id="spbc_setting__' . (strtolower(str_replace(' ', '_', $option['label']))) . '"'
         . ' name="spbc_settings[' . $data['name'] . ']"'
         . ' value="' . $option['val'] . '"'
         . ($data['parent'] ? ' disabled="disabled"' : '')
         . (! $data['children'] ? '' : ' children="' . implode(",", $data['children']) . '"')
         . (! $data['children'] ? '' : ' onchange="spbcSettingsDependencies(\'' . implode(",", $data['children']) . '\')"')
         . (! $data['children_by_ids'] ? '' : ' onchange="spbcSettingsDependenciesbyId([\'' . implode("','", $data['children_by_ids']) . '\'])"')
         . ($data['value'] == $option['val'] ? ' checked' : '') . ' />'
         . '<label for="spbc_setting__' . $option['label'] . '"> ' . $option['label'] . '</label>';
    echo '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;';
}

?>
