#
# ssh-keygen -t ed25519 -f ./test_ed25519_key -N ""
#

ed25519_private_key = '''
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAPKVT3pV5RMD/kAdJB97yzFJVBHOZqCd/Z7WJnIfrN4AAAAKDJDxEOyQ8R
DgAAAAtzc2gtZWQyNTUxOQAAACAPKVT3pV5RMD/kAdJB97yzFJVBHOZqCd/Z7WJnIfrN4A
AAAEC24s0CKUenp53tN6tP5dZni96nYrYKhgSYSJniRV8TDA8pVPelXlEwP+QB0kH3vLMU
lUEc5moJ39ntYmch+s3gAAAAHHdvbGZAV29sZnMtTWFjQm9vay1Qcm8ubG9jYWwB
-----END OPENSSH PRIVATE KEY-----
'''

ed25519_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA8pVPelXlEwP+QB0kH3vLMUlUEc5moJ39ntYmch+s3g wolf@Wolfs-MacBook-Pro.local"

#
# ssh-keygen -Y sign -f ./test_ed25519_key -n file ./ExampleMessage.txt
# Signing file ./ExampleMessage.txt
# Write signature to ./ExampleMessage.txt.sig
#

example_message_ed25519_signature = '''
-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgDylU96VeUTA/5AHSQfe8sxSVQR
zmagnf2e1iZyH6zeAAAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx
OQAAAEBVIG39Xn6DEvM8xSyKDMHCvkb6DCcQ8nznhOWbW8egQSojGCn9YjVBnNQE2WhW+G
BDU/Nu+IHNO+MkjmttCtAB
-----END SSH SIGNATURE-----
'''

#
# ssh-keygen -t rsa -b 2048 -f ./test_rsa_key -N ""
#

rsa_private_key = '''
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAmRz7uPW15sVvtbD3fkxBauPb0lASvLPFyJGPY4FBSEQg0T1B41Ho
ClA+K6wzZQyZmBaiKo73AokkqjaRZ3lWIW+PsqNBtbK8Q3mYLz6aHaMEYvMaeamsLBZF/n
JU5RtOEnWxXeiNAVVanqORCq6kbBKQOP+dKdGRARUdw+n4E9h/zyaTh9Ygl12ECrkpKmXZ
X288LwjINIq5EXEV2gsD9B/TndlsDCHrX8eTYGGCnyRs/34BiaAQEv0XTiQdY0b0isCxP9
Sq8vuMRJbpWxcKy9xAE0UNXNen3DrGjJrbEHmeD+SjtGiwS+WNhH9XAk/MUqlcf9i15S/G
cW7RSOlSzwAAA9hMv/Y5TL/2OQAAAAdzc2gtcnNhAAABAQCZHPu49bXmxW+1sPd+TEFq49
vSUBK8s8XIkY9jgUFIRCDRPUHjUegKUD4rrDNlDJmYFqIqjvcCiSSqNpFneVYhb4+yo0G1
srxDeZgvPpodowRi8xp5qawsFkX+clTlG04SdbFd6I0BVVqeo5EKrqRsEpA4/50p0ZEBFR
3D6fgT2H/PJpOH1iCXXYQKuSkqZdlfbzwvCMg0irkRcRXaCwP0H9Od2WwMIetfx5NgYYKf
JGz/fgGJoBAS/RdOJB1jRvSKwLE/1Kry+4xElulbFwrL3EATRQ1c16fcOsaMmtsQeZ4P5K
O0aLBL5Y2Ef1cCT8xSqVx/2LXlL8ZxbtFI6VLPAAAAAwEAAQAAAQAhs3BwiJyuG7z31+jR
wsUPWvHye690G3moKOnPtA6DcoNqqroK5+dUBc95W2DAmCJiiHDPP0J9K2SHlpUwmlNr7p
tJbYe0D5BCpcvqcjQH2+7GPM4SA1ejKI/lbpLjDryDcaZFjj8jEP9uNYBiQohsRTW7Zf/Y
yYjKHTS8/42cCE8HIqFR/p0eCq4X6fJs+/NH+SJhU/nIt3MEY1hLWuFcADWwkgJjVsZZ0e
Aebr1lWGkqUHo8zNhzyv1EnNRG7AUVtvBbZ6qP+zFsiY7fXK6tM1OiEAYicnhJR+Ls0y8a
oLR16ewEH51T9G0DJV5hEGmkMte0LALtRyDRTE5dPwIpAAAAgQDHrSr6GdBkidn6ekdbrp
jtc5BIYw/gU7rSOM+fayYsRqPw9Ik277nj69gaebyHOOi3pR0F5/v2ASJHQRVyV6UaPnfp
/UXFF2uNUNUDBdDkoLdNjEh5fsXxCcnRKUQEI3aI0vAmYc1nHSUDGaE8nAE3kyswh0gIly
LX88nAwQGCXgAAAIEAyQuB56tCLjH9CP1aScWTYdv4iUqcI9h91S3ohwmNB2Fo6P5YxHK3
uQE62JuJa3Zb/0W6j61W21OmOWOJ0YWVK/IOCpmQtBe2gN42M11aaPkbb3NOnogvraQHCM
RBFL0n1EkylcQT6O1mb2/8yevYYZUmMovcXqSec+iTu01jhBUAAACBAML3XS2v9pUfwlXF
5yC4vammavY3UGwf+QSwJkfil0f23kjmGvceBGxkMHJI62b3RbaQZtBE+U4B/TVGKFhUKv
7IXaRIdGDrLOI7Uu6WcIzZMf2EjLXzwYCWFJwIc2cQJo4VBhr22dHdf4tEXeTyAAnQMPq6
Zt/GRbf3/DCg74BTAAAAHHdvbGZAV29sZnMtTWFjQm9vay1Qcm8ubG9jYWwBAgMEBQY=
-----END OPENSSH PRIVATE KEY-----
'''

rsa_public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCZHPu49bXmxW+1sPd+TEFq49vSUBK8s8XIkY9jgUFIRCDRPUHjUegKUD4rrDNlDJmYFqIqjvcCiSSqNpFneVYhb4+yo0G1srxDeZgvPpodowRi8xp5qawsFkX+clTlG04SdbFd6I0BVVqeo5EKrqRsEpA4/50p0ZEBFR3D6fgT2H/PJpOH1iCXXYQKuSkqZdlfbzwvCMg0irkRcRXaCwP0H9Od2WwMIetfx5NgYYKfJGz/fgGJoBAS/RdOJB1jRvSKwLE/1Kry+4xElulbFwrL3EATRQ1c16fcOsaMmtsQeZ4P5KO0aLBL5Y2Ef1cCT8xSqVx/2LXlL8ZxbtFI6VLP wolf@Wolfs-MacBook-Pro.local"

#
# ssh-keygen -t dsa -b 1024 -f ./test_dsa_key -N ""
#

dsa_private_key = '''
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABsQAAAAdzc2gtZH
NzAAAAgQDxjvKWbbjAz9ESY8y+pKGTwOKZEQNy5YChj1fnP4wTd/Q/GUX75EoRmN7H1HwL
OS5U5/ALpEByhLF7A+7jdDQywZUYocgDzgrMGJPmL4fEE+tPVkM8dep9xMY1n8fe6IogFL
F+BMsCxAyUw17df1THTIeO6MlRdouNqvqOmHhc2wAAABUArandk7VxnfM/3sClmLFSdwQB
ImsAAACAfLAW6uY9tlNXLCk7XjuvWMWmj58XSZ9hU73hKtn20eiUs+R9iW3Jy89aWzRwGS
lR/J8bZaUlRF90mMZwc6STrQGMDgB3wLUXDty0ZMcS1A1xYewSwC7cPyZyteSeb5T8v6dR
6ua988f53pcV2k9yQsBbvVjaFmtCdMv6OL5hRsAAAACAI1qPHWioOoUluRJp2COy5FV+83
VsrQ8roWvEqa15xLduCE+pKwn01br0QoNHSbGsxWJ464i4b+fRKgmziZGILgIvKRzDJbjS
w+S6xgWaCSrpQFIhv5SmTYlzAyN8qA/U/mNr/7F7xESgX7CM3Hpqnw4mjQbERngieg8sxJ
1OqdgAAAH4jCMBtYwjAbUAAAAHc3NoLWRzcwAAAIEA8Y7ylm24wM/REmPMvqShk8DimRED
cuWAoY9X5z+ME3f0PxlF++RKEZjex9R8CzkuVOfwC6RAcoSxewPu43Q0MsGVGKHIA84KzB
iT5i+HxBPrT1ZDPHXqfcTGNZ/H3uiKIBSxfgTLAsQMlMNe3X9Ux0yHjujJUXaLjar6jph4
XNsAAAAVAK2p3ZO1cZ3zP97ApZixUncEASJrAAAAgHywFurmPbZTVywpO147r1jFpo+fF0
mfYVO94SrZ9tHolLPkfYltycvPWls0cBkpUfyfG2WlJURfdJjGcHOkk60BjA4Ad8C1Fw7c
tGTHEtQNcWHsEsAu3D8mcrXknm+U/L+nUermvfPH+d6XFdpPckLAW71Y2hZrQnTL+ji+YU
bAAAAAgCNajx1oqDqFJbkSadgjsuRVfvN1bK0PK6FrxKmtecS3bghPqSsJ9NW69EKDR0mx
rMVieOuIuG/n0SoJs4mRiC4CLykcwyW40sPkusYFmgkq6UBSIb+Upk2JcwMjfKgP1P5ja/
+xe8REoF+wjNx6ap8OJo0GxEZ4InoPLMSdTqnYAAAAFQCGdqZk1QG6mALBA5Z+xrA+CSAj
IAAAABx3b2xmQFdvbGZzLU1hY0Jvb2stUHJvLmxvY2FsAQIDBAUG
-----END OPENSSH PRIVATE KEY-----
'''

dsa_public_key = "ssh-dss AAAAB3NzaC1kc3MAAACBAPGO8pZtuMDP0RJjzL6koZPA4pkRA3LlgKGPV+c/jBN39D8ZRfvkShGY3sfUfAs5LlTn8AukQHKEsXsD7uN0NDLBlRihyAPOCswYk+Yvh8QT609WQzx16n3ExjWfx97oiiAUsX4EywLEDJTDXt1/VMdMh47oyVF2i42q+o6YeFzbAAAAFQCtqd2TtXGd8z/ewKWYsVJ3BAEiawAAAIB8sBbq5j22U1csKTteO69YxaaPnxdJn2FTveEq2fbR6JSz5H2JbcnLz1pbNHAZKVH8nxtlpSVEX3SYxnBzpJOtAYwOAHfAtRcO3LRkxxLUDXFh7BLALtw/JnK15J5vlPy/p1Hq5r3zx/nelxXaT3JCwFu9WNoWa0J0y/o4vmFGwAAAAIAjWo8daKg6hSW5EmnYI7LkVX7zdWytDyuha8SprXnEt24IT6krCfTVuvRCg0dJsazFYnjriLhv59EqCbOJkYguAi8pHMMluNLD5LrGBZoJKulAUiG/lKZNiXMDI3yoD9T+Y2v/sXvERKBfsIzcemqfDiaNBsRGeCJ6DyzEnU6p2A== wolf@Wolfs-MacBook-Pro.local"

#
# ssh-keygen -t ecdsa -b 256 -f ./test_ecdsa_key -N ""
#

ecdsa_private_key = '''
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQSNkyCnrLIZur2Wsv/QbNrcqZZH/zmx
x7pYxAtUk3aXZ9Wf1Ve5LzsQvk9ReavB2IgtGqN2k+pcW/kaWC0L49ogAAAAuE8ZP2ZPGT
9mAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBI2TIKesshm6vZay
/9Bs2typlkf/ObHHuljEC1STdpdn1Z/VV7kvOxC+T1F5q8HYiC0ao3aT6lxb+RpYLQvj2i
AAAAAhAORh/5SZLdB6d9pRvkcyqE9a5LY5H7c18fGATB/GaGzuAAAAHHdvbGZAV29sZnMt
TWFjQm9vay1Qcm8ubG9jYWwBAgM=
-----END OPENSSH PRIVATE KEY-----
'''

ecdsa_public_key = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBI2TIKesshm6vZay/9Bs2typlkf/ObHHuljEC1STdpdn1Z/VV7kvOxC+T1F5q8HYiC0ao3aT6lxb+RpYLQvj2iA= wolf@Wolfs-MacBook-Pro.local"
