import subprocess

binary_name = "./allstar/testprog.bin.strip"
rc = subprocess.call('./generate_training_data.sh ASTGenerator.java ' + binary_name, shell=True)
