#!/bin/sh

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <number of zones>"
    exit 1
fi

. ../system/conf.sh

cat << EOF
options {
        directory "`pwd`";
        listen-on { localhost; };
        listen-on-v6 { localhost; };
	port 5300;
        allow-query { any; };
        allow-transfer { localhost; };
        allow-recursion { none; };
        recursion no;
};

key rndc_key {
        secret "1234abcd8765";
        algorithm hmac-md5;
};

controls {
        inet 127.0.0.1 port 9953 allow { any; } keys { rndc_key; };
};

logging {
        channel basic {
                file "`pwd`/named.log" versions 3 size 100m;
                severity info;
                print-time yes;
                print-severity no;
                print-category no;
        };
        category default {
                basic;
        };
};

EOF

$PERL makenames.pl $1 | while read zonename; do
        echo "zone $zonename { type master; file \"smallzone.db\"; };"
done
