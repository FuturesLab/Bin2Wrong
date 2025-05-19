import sys

def append_binary_files(file1, file2, output_file):
    with open(file1, 'rb') as f1, open(file2, 'rb') as f2, open(output_file, 'wb') as output:
        output.write(f1.read())
        output.write(f2.read())

first_file_name = sys.argv[1]
second_file_name = sys.argv[2]
final_file_name = sys.argv[3]

append_binary_files(first_file_name, second_file_name, final_file_name)
print(first_file_name + " and " + second_file_name + " have been combined into " + final_file_name)