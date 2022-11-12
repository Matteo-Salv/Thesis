file = "StraceOutput.txt"
count_occurrences = {}
f = open("../" + file, "r")
out = open("AnalyzerOutput.txt", "w")
file_raws = f.readlines()
for row in file_raws:
    syscall = []
    if "pid" not in row:
        syscall = row.split("]: ")
        print(syscall)
        if syscall[2] not in count_occurrences.keys():
            count_occurrences[syscall[2]] = 1
        elif syscall[2] in count_occurrences.keys():
            count_occurrences[syscall[2]] = count_occurrences[syscall[2]] + 1

backslash = '\\'
for val in count_occurrences:
    out.write(f"{val[:-1]}: {count_occurrences[val]}\n")
    out.flush()
out.write(f"total number of syscalls: {sum(count_occurrences.values())}")
print(count_occurrences)
