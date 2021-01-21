FROM sconecuratedimages/apps:python-3.7.3-alpine3.10-scone4.2.1
COPY encrypted-files /fspf/encrypted-files
COPY fspf-file/fs.fspf /fspf/fs.fspf
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
