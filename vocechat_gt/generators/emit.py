import json, yaml, os
SCRATCH = os.path.dirname(os.path.abspath(__file__)) + "/"
GT = "C:/Users/User/Documents/pengent_web_gt_schema_student_v1/vocechat_gt/"

class S(str): pass
def _s(dumper, data): return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|" if "\n" in data else None)
yaml.add_representer(S, _s)
yaml.representer.SafeRepresenter.add_representer(type(None), lambda d, _: d.represent_scalar("tag:yaml.org,2002:null", "null"))

def dump(obj, path):
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(obj, f, sort_keys=False, allow_unicode=True, width=120, default_flow_style=False)

l1 = json.load(open(SCRATCH + "l1_build.json", encoding="utf-8"))["l1"]
l2 = json.load(open(SCRATCH + "l2_build.json", encoding="utf-8"))
dump(l1, GT + "l1_gt.yaml")
dump(l2, GT + "l2_gt.yaml")
print("wrote l1_gt.yaml, l2_gt.yaml")
