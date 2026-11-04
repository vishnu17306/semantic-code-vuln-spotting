from datasets import load_dataset

ds = load_dataset("DetectVul/CVEFixes")
train = ds["train"]

vulnerable_examples = [ex for ex in train if 1 in ex["label"]]
print(f"Train examples with a vulnerable line: {len(vulnerable_examples)}")

categories = {"sqli": 0, "cmdi": 0, "path_traversal": 0, "other": 0}

for ex in vulnerable_examples:
    for line, label in zip(ex["raw_lines"], ex["label"]):
        if label == 1:
            l = line.lower()
            if ".execute(" in l or "cursor" in l:
                categories["sqli"] += 1
            elif "os.system(" in l or "subprocess." in l or "os.popen(" in l:
                categories["cmdi"] += 1
            elif "os.path.join(" in l or "os.path.realpath(" in l:
                categories["path_traversal"] += 1
            else:
                categories["other"] += 1

print(categories)