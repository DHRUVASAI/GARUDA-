"""Remove orphaned HTML lines from garuda.html"""
with open('garuda.html', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Lines to remove (1-indexed): 741-770 (orphaned topology), 788-869 (orphaned port/traffic/dashboard/devices/settings)
remove_ranges = [(741, 770), (788, 869)]
keep = []
for i, line in enumerate(lines):
    ln = i + 1
    skip = any(start <= ln <= end for start, end in remove_ranges)
    if not skip:
        keep.append(line)

with open('garuda.html', 'w', encoding='utf-8') as f:
    f.writelines(keep)

print(f"Done. Removed {len(lines) - len(keep)} lines. {len(keep)} lines remain.")
