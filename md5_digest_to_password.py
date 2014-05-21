#!/usr/bin/env python

import csv
import functools
import hashlib
import itertools
import string
import sys
import time
import types


class Table(list):
    def load_table_from_csv(self, path):
        with open(path) as f:
            f_csv = csv.DictReader(f)
            for row in f_csv:
                self.append(row)

    def create_column(self, name, value):
        # See: http://stackoverflow.com/questions/624926/how-to-detect-whether-
        # a-python-variable-is-a-function/624948#624948
        if isinstance(value, (types.FunctionType,
                              types.BuiltinFunctionType,
                              functools.partial)):
            row_manipulator = value
        else:
            row_manipulator = None

        for n, row in enumerate(self):
            if name not in row:  # row.has_key(name):
                if row_manipulator:
                    row[name] = row_manipulator(row)
                else:
                    row[name] = value

    def delete_column(self, name):
        for row in self:
            del row[name]

    def __repr__(self):
        return "Table({0})".format(super(Table, self).__repr__())


# Assumes that passw exists out of 4 printable ASCII characters.
# Optimised for finding lowercase-only passwords.
def get_password_from_md5_digest(md5_digest):
    """Brute force guess a password from an md5 digest.

    Args:
        md5_digest (str): An md5 digest to get the corresponding password of.

    Returns:
        str.


    Performance:

    The worst case performance is for a guess of a password containing one
    or more non-lowercase characters. This is the case of 26**4 + 95**4
    guesses.

    The worst case performance of a guess of a password containing only
    lowercase characters is for the password "zzzz" with 26**4 guesses
    because this is the last guessed password according to the
    itertools.product algorithm.

    On my laptop (Lenovo E531), this guess executes consistently
    under 0.49 seconds.

    Worst case performance of a guess of a password containing one or more
    non-lowercase characters should thus be about 179.24
    ((26**4 + 95**4)/float(26**4)) times worse than the worst case guess
    of a lowercase-only password.

    That means that the worst case password should not take over
    about 87.83 seconds on my laptop.


    Idea for improvement:

    A more efficient algorithm would ...

    1. ... check each md5_digest against a digest_guess generated from a list of
    the most frequently occuring 4 character permutations as passwords.
    Even better would be if the check would occur against precomputed
    digest_guesses and then grab the password that is paired with it from a
    table.
    2. ... if still not found, then check only against permutations not
    guessed before.

    """
    digits = string.printable[0:10]
    lowercases = string.printable[10:36]
    uppercases = string.printable[36:62]
    # Last 5 printables not used (e.g. tab and newline)
    remaining = string.printable[62:-5]
    # There are 95 printable chars, so 95**4 permutations possible: oom of 7.
    printables = lowercases + uppercases + digits + remaining

    # Runs through 26**4 permutations.
    for lowercase_perm in itertools.product(lowercases, repeat=4):
        guess = "".join(lowercase_perm)
        digest_guess = hashlib.md5(guess).hexdigest()
        if digest_guess == md5_digest:
            return guess

    # This algorithm runs when at least 1 non-lowercase character was used in
    # in the original password.
    # It does 26**4 useless checks in the worst case scenario.
    # However, this is only about 0.56% (26**4/float(95**4)*100) slower
    # than if it didn't.
    for perm in itertools.product(printables, repeat=4):
        guess = "".join(perm)
        digest_guess = hashlib.md5(guess).hexdigest()
        if digest_guess == md5_digest:
            return guess


def get_password_and_time(md5_digest):
    init_time = time.time()
    passw = get_password_from_md5_digest(md5_digest)
    end_time = time.time()
    exec_time = end_time - init_time
    return passw, exec_time


def main(table):
    # Step 1. in the problem description.
    table.create_column("md5", lambda row: hashlib.md5(row["pass"]).hexdigest())

    # Step 2. in the problem description.
    table.delete_column("pass")

    # Step 3. and 4. in the problem description.
    table.create_column("pass", "")
    table.create_column("time", "")
    for row in table:
        passw, time = get_password_and_time(row["md5"])
        row["pass"] = passw
        row["time"] = time

    # First part of step 5. in the problem description.
    for row in table:
        print row


if __name__ == "__main__":
    init_time = time.time()
    table = Table([])
    try:
        script, csv_file = sys.argv
    except ValueError:
        script = sys.argv[0]
        print ("Please provide a csv file as argument, e.g.: \n"
               "python {0} data.csv\n".format(script))
        sys.exit()

    table.load_table_from_csv(csv_file)
    main(table)
    end_time = time.time()
    total_time = end_time - init_time
    # Second part of step 5. in the problem description.
    print "Total execution time is {0} seconds.".format(total_time)
