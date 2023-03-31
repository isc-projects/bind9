set -e
AFL=/path/to/afl
git clone https://github.com/jingtianer/bind9_namedfuzz.git bind9
SUBJECT=$PWD/bind9

export AFL_PERSISTENT=1
export LD_LIBRARY_PATH=$SUBJECT/lib/isc/.libs:$SUBJECT/lib/dns/.libs:$SUBJECT/lib/isccc/.libs:$SUBJECT/lib/isccfg/.libs

export CC=$AFLFAST/afl-clang-fast
export CXX=$AFLFAST/afl-clang-fast++

export CFLAGS="-D ENABLE_AFL"
export CXXFLAGS="-D ENABLE_AFL"

pushd $SUBJECT
	autoreconf -fi
	./configure  --enable-fuzzing=afl
	sudo make -j
	sudo make install
popd

if [ ! -d workdir ]; then
    mkdir workdir
fi
tee named.conf <<-'EOF'
options {
    directory    "$PWD/workdir";
    allow-query     { any; };
    listen-on port 1053 { any; };
};
EOF
pattern="s/\$PWD/$(echo `pwd` | sed "s/\//\\\\\//g")/g"
sed -i $pattern named.conf 
cat named.conf

$AFLFAST/afl-fuzz -t 50000 -m none -i in -o out -- $SUBJECT/bin/named/.libs/named -A client:127.0.0.1:1053 -g -c named.conf
