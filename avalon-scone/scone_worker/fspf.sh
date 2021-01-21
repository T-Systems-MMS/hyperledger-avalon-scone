#!/bin/bash
# Copyright 2020 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cp -rf /custom-libzmq /project/custom-libzmq
cp -rf /custom-libffi /project/custom-libffi
cp -rf /custom-libressl /project/custom-libressl
cp -rf /custom-python /project/custom-python
cp -rf /muslusr /project/muslusr

# create a file system protection file (first unencrypted)
scone fspf create /project/fs.fspf

# root region (i.e., "/") is not protected 
scone fspf addr /project/fs.fspf / --not-protected --kernel /

# add authenticated regions 
scone fspf addr /project/fs.fspf /project/custom-libzmq --kernel /project/custom-libzmq --authenticated 
scone fspf addf /project/fs.fspf /project/custom-libzmq /project/custom-libzmq /project/custom-libzmq
scone fspf addr /project/fs.fspf /project/custom-libffi --kernel /project/custom-libffi --authenticated 
scone fspf addf /project/fs.fspf /project/custom-libffi /project/custom-libffi /project/custom-libffi
scone fspf addr /project/fs.fspf /project/custom-libressl --kernel /project/custom-libressl --authenticated 
scone fspf addf /project/fs.fspf /project/custom-libressl /project/custom-libressl /project/custom-libressl
scone fspf addr /project/fs.fspf /project/custom-python/ --kernel /project/custom-python/ --authenticated 
scone fspf addf /project/fs.fspf /project/custom-python/ /project/custom-python/ /project/custom-python/
scone fspf addr /project/fs.fspf /project/muslusr --kernel /project/muslusr --authenticated 
scone fspf addf /project/fs.fspf /project/muslusr /project/muslusr /project/muslusr
scone fspf addr /project/fs.fspf /lib --kernel /lib --authenticated 
scone fspf addf /project/fs.fspf /lib /lib /lib

# add encrypted region /project/avalon
scone fspf addr /project/fs.fspf /project/avalon/ --encrypted --kernel /project/avalon/
scone fspf addf /project/fs.fspf /project/avalon/ /native-files/ /project/avalon/ 

# finally, encrypt the file system protection file and store the keys in directory (we assume in this demo that we run on a trusted host)
scone fspf encrypt /project/fs.fspf > /native-files/keytag
