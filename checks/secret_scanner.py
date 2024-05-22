import glob
import os
import re
import sys
import argparse

parser = argparse.ArgumentParser(
    prog='Secret Scanner',
    usage='This tool is used for scanning project directory for secrets that should not be shared.'
          'Run .exe or .py file in your terminal. Use -h/--help flag to get more information.',
    description='The program scans the files of the current or specified (with -p/--path) directory for secrets '
                '(password, secret key etc.) that have not been hidden (e.g. added to .env). '
                'By default files added to .gitignore are NOT scanned. You can change it by using the -a/--all flag. '
                'After scanning a summary of the results is given in "secret_scanner_results.txt" file '
                'and in case secrets are found the detailed report is given in the same file'
                '(generated in the scanned dir and added to .gitignore) '
                'and in the terminal.',
    epilog='The author is Elena Kolomeets (GitHub elena-kolomeets).',
)
parser.add_argument(
    '-p', '--path',
    type=str,
    default='.',
    required=False,
    help='Provide the absolute or relative path to the directory that needs to be scanned for secrets. '
         'By default the current directory is used.',
    metavar='[path]',
)
parser.add_argument(
    '-a', '--all',
    required=False,
    action='store_true',
    help='Use this flag to scan all files, including the files added to .gitignore (not scanned by default)',
)

args = parser.parse_args()


def ignore(user_path):
    """
    Checking if dir contains .gitignore
    and returns a list of all ignored files from all subdirs.
    :param user_path: the path given by the user with -p/--path parameter
    :return: a list of files to ignore while scanning
    """
    gitignore, ignore_list = [], []
    if os.path.exists(user_path + '/.gitignore'):
        with open(user_path + '/.gitignore') as g:
            for line in g:
                if line != '' and line != '\n':
                    if '\n' in line:
                        line = line[:-1]
                    if line[-1] == '/':
                        line = line + '*'
                    if line[:2] == '**':
                        line = line[2:]
                    gitignore.append(line)
        for i in gitignore:
            i = user_path + '/**/' + i + '*'
            for j in glob.iglob(i, recursive=True):
                ignore_list.append(os.path.relpath(j, start=user_path))
    return ignore_list


def generate_words():
    """
    Generating a list of words to search for while scanning for secrets.
    :return: the list of secret words and expressions
    """
    words_case, secret_words = [], []
    for word in ['password', 'pass', 'key', 'token', 'credential', 'database_url', 'database-url', 'db_url', 'db-url', 'client_secret', 'api_key']:
        words_case.extend((word, word.upper(), word.capitalize()))
    for word in words_case:
        secret_words.extend((word+':', word+' :', word+'=', word+' =', '_'+word, word+'s', word+' is'))
    return secret_words


def scan(userpath, scan_ignore, secret_words):
    """
    Scanning files in the folder and subfolders for secrets
    and adding file names and their lines with secrets to list of dictionaries
    :param userpath:
    :param scan_ignore: flag
    :param secret_words: list of secret words to scan for
    :return: file_list: list of dictionaries with the results
    """
    file_list = []
    for name in glob.iglob(userpath, recursive=True):
        if os.path.isdir(name) or os.path.relpath(name, start=userpath)[6:] in scan_ignore \
                or os.path.basename(name) == 'secret_scanner_results.txt':
            continue
        try:
            for secret_word in secret_words:
                if secret_word in os.path.basename(name):
                    file_list.append({'file_name': os.path.relpath(name, start=userpath)[6:]})
            with open(name, mode='r', encoding='utf-8') as f:
                for file_line in f:
                    for secret_word in secret_words:
                        if secret_word in file_line and \
                        re.search(r'([a-zA-Z]+[0-9]+|[0-9]+[a-zA-Z]+)[+?@^!§$%&]*\S{8,}', file_line):
                            file_list.append({'file_name': os.path.relpath(name, start=userpath)[6:],
                                              'file_line': file_line.strip()})
                            break
        except Exception:
            continue
    return file_list


def write_output(file_list, output):
    """
    Writing the scan output to the terminal instead of a file.
    :param file_list:
    :param output:
    """
    print(output, file=sys.stdout)
    if file_list:
        for results in file_list:
            print()
            for key, value in results.items():
                print(f"{key}: {value}")


def main(user_path_raw, all_files):
    """
    The program scans all files in all subdirectories of given directory
    for exposed secrets locally using the algorithm developed by the author.
    Files added to .gitignore can be scanned too (with -a/-all flag).
    The results are written in the terminal and in "secret_scanner_results.txt".
    :param user_path_raw:
    :param all_files:
    :return: executing all functions
    """
    os.path.normpath(user_path_raw)
    user_path = user_path_raw.replace(os.sep, '/')
    if os.path.isdir(user_path):
        file_list = []
        if len(glob.glob(user_path+'/**/*', recursive=True)) <= 3000:
            secret_words = generate_words()
            if not all_files:
                scan_ignore = ignore(user_path)
            else:
                scan_ignore = []

            dot_file_list = scan(user_path+'/**/.*', scan_ignore, secret_words)
            file_list = scan(user_path + '/**/*', scan_ignore, secret_words)
            file_list.extend(dot_file_list)

            if not file_list:
                output = "No secrets found, good job! Keep an eye on them anyway as no tool is perfect."
            else:
                output = f"The scanner found {len(file_list)} possible secret exposure(s).\n\n"
        else:
            output = "The given directory is too large."
        write_output(file_list, output)
    else:
        print("The given path is not found. Shall we try another one?", file=sys.stdout)


if __name__ == '__main__':
    main(args.path, args.all)
