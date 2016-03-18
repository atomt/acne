MAILTO=root

31 20 * * * root if [ -x /usr/bin/acne ]; then /usr/bin/acne renew-auto --cron; fi
