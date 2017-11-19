import csv

if __name__ == '__main__':
    dt = {}
    with open('QQmail.csv', encoding='gbk') as f:
        csv_reader = csv.reader(f)
        for row in csv_reader:
            if row[2] == '电子邮件':
                continue
            dt[row[2][:-7]] = row[0]
    print(dt)
