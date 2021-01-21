#!/usr/bin/python3

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
import sys
import logging
from avalon_worker.workload.workload import WorkLoad
import array
from ctypes import cdll, c_char_p, c_char, c_float, c_int,c_wchar_p,addressof, create_string_buffer,POINTER

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler(sys.stdout))

# -------------------------------------------------------------------------


class FibonacciCPPWorkLoad(WorkLoad):
    """
    Fibonacci workload class. This is an example workload.
    """

# -------------------------------------------------------------------------

    def execute(self, in_data_array):
        """
        Executes Fibonacci workload.
        Parameters :
            in_data_array: Input data array containing data in plain bytes
        Returns :
            status as boolean and output result in bytes.
        """
        logger.info("Execute Fibonacci CPP workload")
        data_plain_bytes = in_data_array[0]["data"]
        try:
            data_str = data_plain_bytes.decode("UTF-8")
            fib_num = self._fibonacci(data_str)
            out_msg = "Fibonacci number at position {} = {}".format(data_str, fib_num)
            out_msg_bytes = out_msg.encode("utf-8")
            result = True
        except Exception as e:
            out_msg = "Error processing Fibonacci number: " + str(e)
            out_msg_bytes = out_msg.encode("utf-8")
            logger.error(out_msg)
            result = False
        return result, out_msg_bytes

# -------------------------------------------------------------------------

    def _fibonacci(self, n):
        """
        Function to calculate nth Fibonacci number
        Parameters :
            n: nth Fibonacci number to calculate
        Returns :
            nth Fibonacci number
        """
        # connect to .so
        lib = cdll.LoadLibrary('/home/pythonworker/fib_exponential.so')

        # set data types of arguments of cpp function
        lib.c_fib_linear.argtypes = [c_char_p]

        # set result data type
        lib.c_fib_linear.restype = c_int

        # string I want to pass to the function
        s = n.encode("UTF-8")

        # create buffer that will pass my string to cpp function
        buff = create_string_buffer(s)

        # passing buff to function
        result = lib.c_fib_linear(buff)
        return result
            
# -------------------------------------------------------------------------
