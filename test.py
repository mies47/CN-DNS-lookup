import csv

f = open('./test.csv')
reader = csv.reader(f, delimiter=',')

for row in reader:
    print(row)