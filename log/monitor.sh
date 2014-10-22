cat vusbf_log_* | egrep 'BUG|segfault|panic|recursive|Segmentation' | cut -c 16-  | sort -u;
echo "";
printf 'TEST:\t' ;
cat vusbf_log_* | grep -i 'TEST #' | wc -l ;
printf 'Bugs:\t' ;
cat vusbf_log_* | grep 'BUG' | wc -l; 
printf 'Kernel Panics:\t' ;
cat vusbf_log_* | grep -i 'panic' | wc -l 
printf 'Reboot needed:\t' ;
cat vusbf_log_* | grep -i 'recursive' | wc -l
printf 'Segfault:\t'
cat vusbf_log_* | grep -i 'segfault' | wc -l

