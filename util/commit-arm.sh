ps=`git log -1 --date=raw --pretty=format:%ad -- doc/arm/Bv9ARM.pdf | awk '{print $1;}'`
for f in doc/arm/*.html
do
	ts=`git log -1 --date=raw --pretty=format:%ad -- $f | awk '{print $1;}'`
	if test ${ts:-0} -gt ${ps:-0}
	then
		echo commit needed.
	fi
done
