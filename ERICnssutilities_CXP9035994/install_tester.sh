#!/bin/bash
FOLDERNAME="torutils_whls"
FILENAME="torutils.tar.gz"
curl -L "https://arm1s11-eiffel004.eiffel.gic.ericsson.se:8443/nexus/service/local/artifact/maven/redirect?r=releases&g=com.ericsson.dms.torutility&a=ERICtorutilitiesinternal_CXP9030579&v=RELEASE&e=tar.gz" > $FILENAME
mkdir -p $FOLDERNAME
tar xvzf torutils.tar.gz --strip-components=1 -C $FOLDERNAME
pip install --no-index --find-links=$FOLDERNAME $FOLDERNAME/EnmUtilsInt-0.0.0-py2-none-any.whl
pip install --no-index --find-links=$FOLDERNAME $FOLDERNAME/EnmUtilsTestware-0.0.0-py2-none-any.whl
rm -Rf $FOLDERNAME $FILENAME
