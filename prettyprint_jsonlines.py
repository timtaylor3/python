import csv, jsonlines

input = "file.jsonl"

output = "file.csv"

csv_data = open(output, 'w')
csvwriter = csv.writer(csv_data, dialect='excel')

count = 0
with jsonlines.open(input) as reader:
    for row in reader.iter(type=dict):
        if count == 0:
            header = row.keys()
            csvwriter.writerow(header)
            count += 1
        else:
            csvwriter.writerow(row.values())

csv_data.close()
