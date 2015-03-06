cat vusbf_log_* | egrep 'Fatal trap|panic:|#1 |#2 |#3 |#4 |#5 |#6 |#7 |#8 ' | grep -v " savecore: reboot after panic:" | sort -u;
echo "";
printf 'TEST:\t' ;
cat vusbf_log_* | grep -i 'TEST #' | wc -l ;
printf 'Fatal trap:\t' ;
cat vusbf_log_* | grep 'Fatal trap' | wc -l;
printf 'Kernel Panics:\t' ;
cat vusbf_log_* | grep -i 'panic' | wc -l
