import json
import re

dll_name_regex = re.compile(r"(?:32|64)_(?:[0-9\.]+?)_(.*?)_(?:0x[0-9]+)")

with open('apiscout/db_builder/10.0_filtered.json') as original_db:
    data = json.load(original_db)
    api_db = {}
    for dll in data["dlls"]:
        dll_name = dll_name_regex.match(dll).group(1)
        for exported_function in data["dlls"][dll]["exports"]:
            exported_name = exported_function["name"]
            if not exported_name:
                continue
            if exported_name not in api_db:
                api_db[exported_name] = [dll_name]
            elif dll_name not in api_db[exported_name]:
                print("Found a duplicate API in DLL '{}' and previously in {}".format(dll_name, api_db[exported_function["name"]]))
                api_db[exported_name].append(dll_name)

    with open("apidb.json", "w") as new_db:
        json.dump(api_db, new_db, sort_keys=True, indent=4)
