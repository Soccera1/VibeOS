/* This is a generated file, don't edit */

#define NUM_APPLETS 12
#define KNOWN_APPNAME_OFFSETS 0

const char applet_names[] ALIGN1 = ""
"cat" "\0"
"cp" "\0"
"echo" "\0"
"false" "\0"
"ls" "\0"
"mkdir" "\0"
"mv" "\0"
"pwd" "\0"
"rm" "\0"
"sh" "\0"
"sleep" "\0"
"true" "\0"
;

#define APPLET_NO_cat 0
#define APPLET_NO_cp 1
#define APPLET_NO_echo 2
#define APPLET_NO_false 3
#define APPLET_NO_ls 4
#define APPLET_NO_mkdir 5
#define APPLET_NO_mv 6
#define APPLET_NO_pwd 7
#define APPLET_NO_rm 8
#define APPLET_NO_sh 9
#define APPLET_NO_sleep 10
#define APPLET_NO_true 11

#ifndef SKIP_applet_main
int (*const applet_main[])(int argc, char **argv) = {
cat_main,
cp_main,
echo_main,
false_main,
ls_main,
mkdir_main,
mv_main,
pwd_main,
rm_main,
ash_main,
sleep_main,
true_main,
};
#endif

