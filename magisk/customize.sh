ui_print "- Setting android-sec-mcp permissions"
set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/uninstall.sh" 0 0 0755
set_perm "$MODPATH/system/bin/android-sec-mcp" 0 0 0755
set_perm "$MODPATH/system/bin/frida-server" 0 0 0755
