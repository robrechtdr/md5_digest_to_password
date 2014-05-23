#!/usr/bin/env python

import csv
import functools
import hashlib
import itertools
import multiprocessing
import string
import sys
import time
import types


class CSVTable(list):
    def __init__(self, csv_file_path):
        super(CSVTable, self).__init__()
        with open(csv_file_path) as f:
            f_csv = csv.DictReader(f)
            # So we can still get the original column order if we need to.
            self.columns = f_csv.fieldnames
            for row in f_csv:
                self.append(row)

    def create_column(self, name, value):
        self.columns.append(name)
        # See: http://stackoverflow.com/questions/624926/how-to-detect-whether-
        # a-python-variable-is-a-function/624948#624948
        if isinstance(value, (types.FunctionType,
                              types.BuiltinFunctionType,
                              functools.partial)):
            row_manipulator = value
        else:
            row_manipulator = None

        for n, row in enumerate(self):
            if name not in row:
                if row_manipulator:
                    row[name] = row_manipulator(row)
                else:
                    row[name] = value

    def delete_column(self, name):
        self.columns.remove(name)
        for row in self:
            del row[name]

    def show(self, min_column_len=9):
        trailing_space = "  "
        trailing_space_len = len(trailing_space)
        assert min_column_len >= trailing_space_len

        just_len = min_column_len - trailing_space_len
        for n, row in enumerate(self):
            if n == 0:
                for column_name in self.columns:
                    diff = len(str(row[column_name])) - len(column_name)
                    if diff >= 0:
                        column_name = column_name + diff * " "
                    print "{0}{1}".format(column_name, trailing_space).ljust(just_len),
                print "\n"

            for column in self.columns:
                print "{0}{1}".format(row[column], trailing_space).ljust(just_len),
            print ""

    def __repr__(self):
        return "CSVTable({0})".format(super(CSVTable, self).__repr__())


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

    That means that the worst case 4 character password should not take over
    about 87.83 (179.24*0.49) seconds to crack on my laptop.


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


def get_optimized_amount_of_processes(iterable):
    """Get the optimized amount of processes to process the items in
    the iterable via multiprocessing.

    Args:
        iterable (iterable): The iterable of which the items need to be
            processed via multiprocessing.

    Returns:
        int.

    """
    assert hasattr(iterable, "__len__")
    iterations = len(iterable)
    virtual_cores = multiprocessing.cpu_count()
    # Afaik it would not make sense to spawn more processes than the number
    # of items to process.
    if iterations < virtual_cores:
        return iterations
    # There seems to be an overhead per process spawned.
    # Afaiu the following SO thread takes the number of virtual cores as a
    # sensible limit to the amount of processes to spawn:
    # http://stackoverflow.com/questions/9355472/are-there-any-guidelines-
    # to-follow-when-choosing-number-of-processes-with-multip
    else:
        return virtual_cores


def main(table):
    # Step 1. in the problem description.
    table.create_column("md5", lambda row: hashlib.md5(row["pass"]).hexdigest())

    # Step 2. in the problem description.
    table.delete_column("pass")

    # Step 3. and 4. in the problem description.
    table.create_column("pass", None)
    table.create_column("time", None)

    md5s = (row["md5"] for row in table)
    processes = get_optimized_amount_of_processes(table)
    pool = multiprocessing.Pool(processes=processes)
    result = pool.map(get_password_and_time, md5s)
    for row, row_result in zip(table, result):
        row["pass"], row["time"] = row_result

    # First part of step 5. in the problem description.
    table.show()


if __name__ == "__main__":
    init_time = time.time()
    try:
        script, csv_file = sys.argv
    except ValueError:
        script = sys.argv[0]
        print ("Please provide a csv file as argument, e.g.: \n"
               "python {0} data.csv\n".format(script))
        sys.exit()

    table = CSVTable(csv_file)
    main(table)
    end_time = time.time()
    total_time = end_time - init_time
    # Second part of step 5. in the problem description.
    print "\nTotal execution time is {0} seconds.".format(total_time)
