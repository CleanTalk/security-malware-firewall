<?php global $spbc; ?>

<input type="checkbox"
       id="spbc_setting_<?php echo $data['name']; ?>"
       name="spbc_settings[<?php echo $data['name']; ?>]"
       value="1"
       <?php echo $data['disabled'] ? ' disabled="disabled"' : ''; ?>
       <?php echo $data['required'] ? ' required="required"' : ''; ?>
       <?php echo (string)$data['value'] === '1' ? ' checked' : ''; ?>
       <?php echo $data['parent'] && ! $spbc->settings[ $data['parent'] ] ? ' disabled="disabled"' : ''; ?>
       <?php echo ! $data['children'] ? '' : ' children="' . implode(",", $data['children']) . '"'; ?>
       <?php echo ! $data['children'] ? '' : ' onchange="spbcSettingsDependencies(\'' . implode(",", $data['children']) . '\')"' ?>
       <?php echo ! $data['children_by_ids'] ? '' : ' onchange="spbcSettingsDependenciesbyId([\'' . implode("','", $data['children_by_ids']) . '\'])"' ?>
/>

<?php if (isset($data['title'])) { ?>
    <label for="spbc_setting_<?php echo $data['name']; ?>" class="spbc_setting-field_title--<?php echo $data['type']; ?>"><?php echo $data['title']; ?></label>
<?php } ?>

<?php if (isset($data['long_description'])) { ?>
    <i setting="<?php echo $data['name']; ?>" class="spbc_long_description__show spbc-icon-help-circled"></i>
<?php } ?>

<?php if (isset($data['description'])) { ?>
    <div class="spbc_settings_description"><?php echo $data['description']; ?></div>
<?php } ?>
