case `hostname -s` in
ches)
	IF=bge0
	IN=fd43:4845:5300::/48
	OF=dc0
	ON=2620:0000:0f0e::/48
	;;
dev)
	IF=em0
	IN=fd72:6574:6e65:7400::/63
	OF=em0
	ON=2001:470:e17f:8000::/49
	;;
*)
	echo "go: aw not configured for this machine, aborting" >&2
	exit 1
esac

make && sudo ./aw $IF $IN $OF $ON || echo exit code $?
