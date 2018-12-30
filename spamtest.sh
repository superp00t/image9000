# courtesy of @ayyghost
#!/bin/bash
while true
do
	mx=320;my=256;head -c "$((3*mx*my))" /dev/urandom | convert -depth 8 -size "${mx}x${my}" RGB:- random.png
	curl -i -X POST -F "file=@random.png" https://i.pavona.tech/upload
done

