#!/bin/bash
if test `uname` = 'Darwin'; then
  sed -i '' -e "s;github.build.ge.com/adoption;github.com/PredixDev;" scripts/variables.sh
else
  sed -i -e "s;github.build.ge.com/adoption;github.com/PredixDev;" scripts/variables.sh
fi
