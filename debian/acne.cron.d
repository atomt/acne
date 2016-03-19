MAILTO=root

31 20 * * * root if [ -x /usr/sbin/acne ]; then /usr/sbin/acne renew-auto --cron; fi
