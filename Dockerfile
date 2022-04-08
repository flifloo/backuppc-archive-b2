FROM adferrand/backuppc
RUN apk add py3-pip gnupg
RUN pip3 install b2sdk python-gnupg progress
