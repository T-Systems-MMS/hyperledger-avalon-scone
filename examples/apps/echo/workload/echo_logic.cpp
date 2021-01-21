/* Copyright 2019 Intel Corporation
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include <string>
#include "echo_logic.h"
#include "io_helper.h"

std::string Process(std::string str_in) {
    return std::to_string(fib(std::stoll(str_in)));
}

unsigned long long fib(unsigned long long n)
{
    std::string file_path = "enclave_file.txt";
    IoHelper io_helper(file_path);
    std::string ret_str;
    io_helper.DeleteFile();
    // Generate symmetric hex key
    ret_str = io_helper.GenerateKey();
    io_helper.SetKey(ret_str);
    io_helper.WriteFile(std::to_string(n));

    io_helper.SetKey(ret_str);
    unsigned long long count=0;
    if (io_helper.ReadFile(ret_str) == 0) {
        count = std::stoll(ret_str);
        //count++;
        //ret_str = std::to_string(count);
        //io_helper.WriteFile(ret_str);
    }

    unsigned long long *array = new unsigned long long int[count];

    if (count <= 1)
    {
        delete [] array;
        return count;
    }
    array[0] = fib(count - 1) + fib(count - 2);
    unsigned long long  res=array[0];
    delete [] array;
    return res;
}
