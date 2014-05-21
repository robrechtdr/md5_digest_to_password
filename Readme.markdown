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


* For an answer to the efficiency question see *Idea for improvement* in the docstring of the `get_password_from_md5_digest` function.
