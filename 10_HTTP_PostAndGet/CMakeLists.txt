
if(CONFIG_APPIMG_LOAD_FLASH)
add_appimg(${target} ${flash_ldscript} user_main.c)
else(CONFIG_APPIMG_LOAD_FLASH)
add_appimg(${target} ${file_ldscript} user_main.c)
endif()

