## Problem

### Introduction

The goal of this exercise is to create a script that bruteforces md5-hashed
passwords. In order to achieve that goal, you are allowed to use Python as a
programming language and any Python library you might find suitable for the
task, including numerical and cryptographical libraries.

The submitted solution for this exercise must include:

* The script itself (source code)
* Execution times from both your script and John the ripper (see below).
* Answer to the question

### Requirements

The input of the script will be a table like the following:

    +-------+------+
    | user  | pass |
    +-------+------+
    | john  | qwer |
    | eva   | asdf |
    | allan | zxcv |
    +-------+------+

You can either hardcode it in the script or read it from a CSV file
which path would be provided via command line argument.

From that input you should:

1. Create a third attribute called `md5` with a md5sum of the password.
2. Delete the `pass` attribute.
3. Get the original passwords from md5sum using bruteforce.
   We assume passwords of 4 ASCII characters.
   NOTE: Do it in multiprocess mode.
4. Append two new attributes to the table: `pass` (again)
   and `time` (time to get every original password by bruteforce).
5. Execute your script printing the final table and total elapsed time.
6. Compare your time results with John the ripper (`john` package in Debian).

### Questions

* Do you think that efficiency can be improved. In that case, how?


## Solution

* To see the execution times, run the following:

    `python md5_to_password.py data.csv`

* Cracking the digests with `John` took a little *over 25 seconds*:


        $ time ./john --format=raw-md5 digests.txt    
        Loaded 3 password hashes with no different salts (Raw-MD5 [MD5 128/128 AVX 12x])    
        Warning: poor OpenMP scalability for this hash type, consider --fork=8     
        Will run 8 OpenMP threads    
        Press 'q' or Ctrl-C to abort, almost any other key for status   
        asdf             (eva)    
        qwer             (john)    
        zxcv             (allan)     
        3g 0:00:00:25 DONE 3/3 (2014-05-23 01:38) 0.1159g/s 13678Kp/s 13678Kc/s 13686KC/s fsgar1x..z0kS
        Use the "--show" option to display all of the cracked passwords reliably     
        Session completed    

        real    0m26.006s    
        user    1m47.499s    
        sys     0m0.452s    


* For an answer to the efficiency question see *Idea for improvement* in the docstring of the `get_password_from_md5_digest` function.
